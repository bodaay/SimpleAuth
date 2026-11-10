// Package ldaptest is a minimal LDAP server for tests of the connection/TLS layer.
// It speaks just enough of the protocol to answer a StartTLS extended request and,
// once the connection is secured, a bind (any credentials succeed) and a RootDSE
// search; it records the tag of every operation the client sends before TLS is
// established, so tests can assert that no bind or search ever crosses the wire in
// cleartext.
package ldaptest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
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

	tagBindResponse     = 0x61
	tagUnbindRequest    = 0x42
	tagSearchResEntry   = 0x64
	tagSearchResDone    = 0x65
	tagExtendedResponse = 0x78
)

// NamingContext is the defaultNamingContext the RootDSE reports.
const NamingContext = "DC=corp,DC=test"

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
	id, tag, _, err := readMessage(c)
	if err != nil {
		return
	}
	s.recordCleartext(tag)
	if tag != TagExtendedRequest {
		return
	}
	if cert == nil {
		c.Write(message(id, ldapResult(tagExtendedResponse, 2))) // protocolError: StartTLS not supported
		return
	}
	c.Write(message(id, ldapResult(tagExtendedResponse, 0)))
	tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{*cert}})
	if err := tc.Handshake(); err != nil {
		return
	}
	s.mu.Lock()
	s.tlsUpgraded = true
	s.mu.Unlock()
	s.serveDirectory(tc, false)
}

// StartPlainServer starts a cleartext ldap:// server without a certificate: it
// refuses StartTLS (protocolError) and answers binds and searches in cleartext,
// recording every operation. It stands for a directory used with allow_insecure.
func StartPlainServer(t *testing.T) *Server {
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
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				s.serveDirectory(c, true)
			}()
		}
	}()
	return s
}

func (s *Server) recordCleartext(tag byte) {
	s.mu.Lock()
	s.cleartext = append(s.cleartext, tag)
	s.mu.Unlock()
}

// serveDirectory answers operations until the client unbinds or sends something
// it does not know: any bind succeeds, a search of the RootDSE (empty base)
// returns defaultNamingContext, any other search returns no entries, and
// StartTLS is refused. With cleartext set every operation is recorded.
func (s *Server) serveDirectory(c net.Conn, cleartext bool) {
	for {
		id, tag, op, err := readMessage(c)
		if err != nil {
			return
		}
		if cleartext {
			s.recordCleartext(tag)
		}
		switch tag {
		case TagBindRequest:
			c.Write(message(id, ldapResult(tagBindResponse, 0)))
		case TagSearchRequest:
			if baseTag, base, _ := splitTLV(op); baseTag == 0x04 && len(base) == 0 {
				c.Write(message(id, rootDSE()))
			}
			c.Write(message(id, ldapResult(tagSearchResDone, 0)))
		case TagExtendedRequest:
			c.Write(message(id, ldapResult(tagExtendedResponse, 2)))
		default: // unbind, abandon, anything else
			return
		}
	}
}

// StartLDAPSServer starts an ldaps:// server (TLS from the first byte) that
// completes the handshake and then answers like the directory behind StartTLS.
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
				if err := c.(*tls.Conn).Handshake(); err != nil {
					return
				}
				s.mu.Lock()
				s.tlsUpgraded = true
				s.mu.Unlock()
				s.serveDirectory(c, false)
			}()
		}
	}()
	return s
}

// readMessage reads one LDAPMessage and returns its message ID bytes, its
// protocol-op tag and the protocol-op content.
func readMessage(r io.Reader) (id []byte, tag byte, op []byte, err error) {
	hdr := make([]byte, 2)
	if _, err = io.ReadFull(r, hdr); err != nil {
		return nil, 0, nil, err
	}
	n := int(hdr[1])
	if n&0x80 != 0 {
		lenBytes := make([]byte, n&0x7f)
		if _, err = io.ReadFull(r, lenBytes); err != nil {
			return nil, 0, nil, err
		}
		n = 0
		for _, b := range lenBytes {
			n = n<<8 | int(b)
		}
	}
	body := make([]byte, n)
	if _, err = io.ReadFull(r, body); err != nil {
		return nil, 0, nil, err
	}
	// body: INTEGER messageID (02 len value...), then the protocol op.
	_, id, rest := splitTLV(body)
	tag, op, _ = splitTLV(rest)
	return id, tag, op, nil
}

// splitTLV splits the first BER element off b: its tag, its content and the
// bytes after it. Malformed input yields a zero tag.
func splitTLV(b []byte) (tag byte, content, rest []byte) {
	if len(b) < 2 {
		return 0, nil, nil
	}
	n, off := int(b[1]), 2
	if n&0x80 != 0 {
		k := n & 0x7f
		if 2+k > len(b) {
			return 0, nil, nil
		}
		n = 0
		for _, x := range b[2 : 2+k] {
			n = n<<8 | int(x)
		}
		off += k
	}
	if off+n > len(b) {
		return 0, nil, nil
	}
	return b[0], b[off : off+n], b[off+n:]
}

// tlv encodes one BER element whose content is the concatenation of parts.
func tlv(tag byte, parts ...[]byte) []byte {
	var body []byte
	for _, p := range parts {
		body = append(body, p...)
	}
	switch n := len(body); {
	case n < 0x80:
		return append([]byte{tag, byte(n)}, body...)
	case n < 0x100:
		return append([]byte{tag, 0x81, byte(n)}, body...)
	default:
		return append([]byte{tag, 0x82, byte(n >> 8), byte(n)}, body...)
	}
}

// message wraps a protocol op in an LDAPMessage with the given message ID.
func message(id, op []byte) []byte {
	return tlv(0x30, tlv(0x02, id), op)
}

// ldapResult encodes an LDAPResult-shaped response (BindResponse,
// SearchResultDone, ExtendedResponse) with an empty matchedDN and message.
func ldapResult(tag, resultCode byte) []byte {
	return tlv(tag, tlv(0x0a, []byte{resultCode}), tlv(0x04), tlv(0x04))
}

// rootDSE encodes a SearchResultEntry for the RootDSE.
func rootDSE() []byte {
	attr := tlv(0x30, tlv(0x04, []byte("defaultNamingContext")), tlv(0x31, tlv(0x04, []byte(NamingContext))))
	return tlv(tagSearchResEntry, tlv(0x04), tlv(0x30, attr))
}

// CA is a throwaway certificate authority.
type CA struct {
	Pool *x509.CertPool
	// PEM is the CA certificate as an operator would paste it into ca_cert.
	PEM  string
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
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return &CA{Pool: pool, PEM: string(certPEM), cert: cert, key: key}
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
