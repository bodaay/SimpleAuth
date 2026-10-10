// Package ldaptest is a minimal LDAP server for tests of the connection/TLS layer.
// It speaks just enough of the protocol to answer a StartTLS extended request; it
// records the tag of every operation the client sends before TLS is established, so
// tests can assert that no bind or search ever crosses the wire in cleartext.
package ldaptest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"
)

// LDAP protocol-op tags (RFC 4511, [APPLICATION n]).
const (
	TagBindRequest     = 0x60
	TagSearchRequest   = 0x63
	TagExtendedRequest = 0x77
)

// Server is a fake directory listening on 127.0.0.1.
type Server struct {
	Addr string

	mu          sync.Mutex
	cleartext   []byte
	tlsUpgraded bool
}

// CleartextOps returns the tags of the operations received before TLS was set up.
func (s *Server) CleartextOps() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.cleartext...)
}

// TLSUpgraded reports whether a StartTLS handshake completed.
func (s *Server) TLSUpgraded() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tlsUpgraded
}

// StartTLSServer starts a plain ldap:// server. With cert set it accepts StartTLS and
// completes the TLS handshake; with cert nil it refuses StartTLS (protocolError).
// Any other first operation closes the connection.
func StartTLSServer(t *testing.T, cert *tls.Certificate) *Server {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	s := &Server{Addr: ln.Addr().String()}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c, cert)
		}
	}()
	return s
}

func (s *Server) serve(c net.Conn, cert *tls.Certificate) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	id, tag, err := readMessage(c)
	if err != nil {
		return
	}
	s.mu.Lock()
	s.cleartext = append(s.cleartext, tag)
	s.mu.Unlock()
	if tag != TagExtendedRequest {
		return
	}
	if cert == nil {
		c.Write(extendedResponse(id, 2)) // protocolError: StartTLS not supported
		return
	}
	c.Write(extendedResponse(id, 0))
	tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{*cert}})
	if err := tc.Handshake(); err != nil {
		return
	}
	s.mu.Lock()
	s.tlsUpgraded = true
	s.mu.Unlock()
	io.Copy(io.Discard, tc)
}

// StartLDAPSServer starts an ldaps:// server (TLS from the first byte) that only
// completes the handshake.
func StartLDAPSServer(t *testing.T, cert tls.Certificate) *Server {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	s := &Server{Addr: ln.Addr().String()}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				if err := c.(*tls.Conn).Handshake(); err == nil {
					s.mu.Lock()
					s.tlsUpgraded = true
					s.mu.Unlock()
				}
				io.Copy(io.Discard, c)
			}()
		}
	}()
	return s
}

// readMessage reads one LDAPMessage and returns its message ID bytes and protocol-op tag.
func readMessage(r io.Reader) (id []byte, tag byte, err error) {
	hdr := make([]byte, 2)
	if _, err = io.ReadFull(r, hdr); err != nil {
		return nil, 0, err
	}
	n := int(hdr[1])
	if n&0x80 != 0 {
		lenBytes := make([]byte, n&0x7f)
		if _, err = io.ReadFull(r, lenBytes); err != nil {
			return nil, 0, err
		}
		n = 0
		for _, b := range lenBytes {
			n = n<<8 | int(b)
		}
	}
	body := make([]byte, n)
	if _, err = io.ReadFull(r, body); err != nil {
		return nil, 0, err
	}
	// body: INTEGER messageID (02 len value...), then the protocol op.
	idLen := int(body[1])
	return body[2 : 2+idLen], body[2+idLen], nil
}

// extendedResponse encodes an ExtendedResponse with the given result code.
func extendedResponse(id []byte, resultCode byte) []byte {
	body := append([]byte{0x02, byte(len(id))}, id...)
	body = append(body, 0x78, 0x07, 0x0a, 0x01, resultCode, 0x04, 0x00, 0x04, 0x00)
	return append([]byte{0x30, byte(len(body))}, body...)
}

// CA is a throwaway certificate authority.
type CA struct {
	Pool *x509.CertPool
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// NewCA creates a self-signed CA.
func NewCA(t *testing.T) *CA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ldaptest CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &CA{Pool: pool, cert: cert, key: key}
}

// Issue returns a server certificate for the given DNS names and IP addresses.
func (ca *CA) Issue(t *testing.T, dnsNames []string, ips []net.IP) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "ldaptest server"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
