// SimpleAuth JavaScript/TypeScript SDK
// Zero-dependency, works in Node.js (18+) and browsers

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface SimpleAuthOptions {
  /** SimpleAuth server URL (e.g. https://auth.corp.local:9090) */
  url: string;
  /** Admin API key for admin operations */
  adminKey?: string;
  /** @deprecated Use `adminKey` instead. Falls back to clientSecret if adminKey is not set. */
  clientId?: string;
  /** @deprecated Use `adminKey` instead. Falls back to clientSecret if adminKey is not set. */
  clientSecret?: string;
  /** @deprecated No longer used. Realm-based URLs have been removed. */
  realm?: string;
}

export interface TokenResponse {
  access_token: string;
  refresh_token?: string;
  id_token?: string;
  token_type: string;
  expires_in: number;
  scope?: string;
  force_password_change?: boolean;
}

export interface UserInfo {
  sub: string;
  name?: string;
  email?: string;
  preferred_username?: string;
  department?: string;
  company?: string;
  job_title?: string;
  roles?: string[];
  groups?: string[];
  realm_access?: { roles: string[] };
  resource_access?: Record<string, { roles: string[] }>;
}

export interface User {
  guid: string;
  display_name?: string;
  email?: string;
  department?: string;
  company?: string;
  job_title?: string;
  disabled?: boolean;
  created_at?: string;
  updated_at?: string;
}

export interface SimpleAuthUser {
  /** User GUID */
  sub: string;
  name?: string;
  email?: string;
  preferred_username?: string;
  roles: string[];
  permissions: string[];
  groups: string[];
  department?: string;
  company?: string;
  job_title?: string;

  /** Check if user has a specific role */
  hasRole(role: string): boolean;
  /** Check if user has a specific permission */
  hasPermission(permission: string): boolean;
  /** Check if user has any of the given roles */
  hasAnyRole(...roles: string[]): boolean;
}

interface JWK {
  kty: string;
  use: string;
  kid: string;
  alg: string;
  n: string;
  e: string;
}

interface JWKSResponse {
  keys: JWK[];
}

interface JWTHeader {
  alg: string;
  typ?: string;
  kid?: string;
}

interface JWTPayload {
  sub?: string;
  iss?: string;
  aud?: string | string[];
  exp?: number;
  iat?: number;
  jti?: string;
  name?: string;
  email?: string;
  preferred_username?: string;
  department?: string;
  company?: string;
  job_title?: string;
  roles?: string[];
  permissions?: string[];
  groups?: string[];
  realm_access?: { roles: string[] };
  resource_access?: Record<string, { roles: string[] }>;
  scope?: string;
  typ?: string;
  azp?: string;
  nonce?: string;
  at_hash?: string;
  family_id?: string;
}

// Express-compatible types
interface ExpressRequest {
  headers: Record<string, string | string[] | undefined>;
  user?: SimpleAuthUser;
}

interface ExpressResponse {
  status(code: number): ExpressResponse;
  json(body: unknown): void;
}

type ExpressNextFunction = (err?: unknown) => void;

type ExpressMiddleware = (
  req: ExpressRequest,
  res: ExpressResponse,
  next: ExpressNextFunction,
) => void;

export class SimpleAuthError extends Error {
  public readonly status: number;
  public readonly code?: string;
  public readonly description?: string;

  constructor(message: string, status: number, code?: string, description?: string) {
    super(message);
    this.name = 'SimpleAuthError';
    this.status = status;
    this.code = code;
    this.description = description;
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Base64url decode to Uint8Array */
function base64urlDecode(str: string): Uint8Array {
  // Pad to multiple of 4
  let padded = str.replace(/-/g, '+').replace(/_/g, '/');
  while (padded.length % 4 !== 0) padded += '=';

  // Decode — works in both Node.js and browser
  if (typeof globalThis.atob === 'function') {
    const binary = globalThis.atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }
  // Node.js Buffer fallback (older Node without atob)
  return new Uint8Array(Buffer.from(padded, 'base64'));
}

/** Encode Uint8Array to base64url string */
function base64urlEncode(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  if (typeof globalThis.btoa === 'function') {
    return globalThis.btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  return Buffer.from(bytes).toString('base64url');
}

/** Decode a JWT without verification — returns header and payload */
function decodeJWT(token: string): { header: JWTHeader; payload: JWTPayload; signatureInput: string; signature: Uint8Array } {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new SimpleAuthError('Invalid JWT: expected 3 parts', 400);
  }

  const header: JWTHeader = JSON.parse(new TextDecoder().decode(base64urlDecode(parts[0])));
  const payload: JWTPayload = JSON.parse(new TextDecoder().decode(base64urlDecode(parts[1])));
  const signatureInput = parts[0] + '.' + parts[1];
  const signature = base64urlDecode(parts[2]);

  return { header, payload, signatureInput, signature };
}

/** Create a SimpleAuthUser from JWT payload */
function payloadToUser(payload: JWTPayload): SimpleAuthUser {
  const roles = payload.roles ?? payload.realm_access?.roles ?? [];
  const permissions = payload.permissions ?? [];
  const groups = payload.groups ?? [];

  return {
    sub: payload.sub ?? '',
    name: payload.name,
    email: payload.email,
    preferred_username: payload.preferred_username,
    roles,
    permissions,
    groups,
    department: payload.department,
    company: payload.company,
    job_title: payload.job_title,
    hasRole(role: string): boolean {
      return roles.includes(role);
    },
    hasPermission(permission: string): boolean {
      return permissions.includes(permission);
    },
    hasAnyRole(...checkRoles: string[]): boolean {
      return checkRoles.some((r) => roles.includes(r));
    },
  };
}

// ---------------------------------------------------------------------------
// RSA Verification — platform-agnostic
// ---------------------------------------------------------------------------

/** Convert JWK (n, e) to a CryptoKey (browser) or verify directly (Node.js) */
async function verifyRS256(
  signatureInput: string,
  signature: Uint8Array,
  jwk: JWK,
): Promise<boolean> {
  const encoder = new TextEncoder();
  const data = encoder.encode(signatureInput);

  // Try SubtleCrypto first (browser + Node 15+)
  if (typeof globalThis.crypto?.subtle?.importKey === 'function') {
    const cryptoKey = await globalThis.crypto.subtle.importKey(
      'jwk',
      {
        kty: jwk.kty,
        n: jwk.n,
        e: jwk.e,
        alg: 'RS256',
        ext: true,
      },
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['verify'],
    );
    return globalThis.crypto.subtle.verify('RSASSA-PKCS1-v1_5', cryptoKey, signature, data);
  }

  // Fallback: Node.js crypto module
  try {
    const nodeCrypto = await import('crypto');
    // Build a PEM from the JWK components
    const nBytes = base64urlDecode(jwk.n);
    const eBytes = base64urlDecode(jwk.e);

    // Construct RSA public key in DER (PKCS#1) then wrap in PKIX
    const nLen = nBytes.length;
    const eLen = eBytes.length;

    // Use Node's createPublicKey with JWK input (Node 15.12+)
    const pubKey = nodeCrypto.createPublicKey({
      key: {
        kty: 'RSA',
        n: jwk.n,
        e: jwk.e,
      },
      format: 'jwk',
    });

    const verifier = nodeCrypto.createVerify('RSA-SHA256');
    verifier.update(signatureInput);
    return verifier.verify(pubKey, Buffer.from(signature));
  } catch {
    throw new SimpleAuthError(
      'RS256 verification failed: no suitable crypto API available',
      500,
    );
  }
}

// ---------------------------------------------------------------------------
// JWKS Cache
// ---------------------------------------------------------------------------

class JWKSCache {
  private keys: Map<string, JWK> = new Map();
  private fetchedAt = 0;
  private fetching: Promise<void> | null = null;
  private readonly ttlMs = 60 * 60 * 1000; // 1 hour
  private readonly jwksUrl: string;

  constructor(jwksUrl: string) {
    this.jwksUrl = jwksUrl;
  }

  async getKey(kid: string): Promise<JWK> {
    // Try cache first
    const cached = this.keys.get(kid);
    const now = Date.now();

    if (cached && now - this.fetchedAt < this.ttlMs) {
      return cached;
    }

    // Refresh if stale or kid not found
    await this.refresh();

    const key = this.keys.get(kid);
    if (!key) {
      throw new SimpleAuthError(`JWKS: no key found for kid "${kid}"`, 401);
    }
    return key;
  }

  private async refresh(): Promise<void> {
    // Deduplicate concurrent fetches
    if (this.fetching) {
      await this.fetching;
      return;
    }

    this.fetching = (async () => {
      try {
        const resp = await fetch(this.jwksUrl);
        if (!resp.ok) {
          throw new SimpleAuthError(
            `JWKS fetch failed: ${resp.status} ${resp.statusText}`,
            resp.status,
          );
        }
        const jwks: JWKSResponse = await resp.json();
        this.keys.clear();
        for (const key of jwks.keys) {
          if (key.kid) {
            this.keys.set(key.kid, key);
          }
        }
        this.fetchedAt = Date.now();
      } finally {
        this.fetching = null;
      }
    })();

    await this.fetching;
  }
}

// ---------------------------------------------------------------------------
// SimpleAuth Client
// ---------------------------------------------------------------------------

export class SimpleAuth {
  private readonly url: string;
  private readonly adminKey?: string;
  private readonly jwksCache: JWKSCache;

  constructor(options: SimpleAuthOptions) {
    // Strip trailing slash
    this.url = options.url.replace(/\/+$/, '');
    // adminKey takes precedence, fall back to clientSecret for backward compat
    this.adminKey = options.adminKey ?? options.clientSecret;

    const jwksUrl = `${this.url}/.well-known/jwks.json`;
    this.jwksCache = new JWKSCache(jwksUrl);
  }

  /** Build admin Bearer header (uses adminKey or clientSecret as API key) */
  private adminAuthHeader(): string {
    if (!this.adminKey) {
      throw new SimpleAuthError('adminKey (or clientSecret) is required for admin operations', 401);
    }
    return 'Bearer ' + this.adminKey;
  }

  // -------------------------------------------------------------------------
  // Authentication
  // -------------------------------------------------------------------------

  /**
   * Authenticate with username and password via the direct login API.
   */
  async login(username: string, password: string): Promise<TokenResponse> {
    const resp = await fetch(`${this.url}/api/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ username, password }),
    });

    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      throw new SimpleAuthError(
        err.error_description ?? err.error ?? 'Login failed',
        resp.status,
        err.error,
        err.error_description,
      );
    }

    return resp.json();
  }

  /**
   * Refresh an access token using a refresh token.
   */
  async refresh(refreshToken: string): Promise<TokenResponse> {
    const resp = await fetch(`${this.url}/api/auth/refresh`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ refresh_token: refreshToken }),
    });

    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      throw new SimpleAuthError(
        err.error_description ?? err.error ?? 'Token refresh failed',
        resp.status,
        err.error,
        err.error_description,
      );
    }

    return resp.json();
  }

  /**
   * Logout is not available as a direct API endpoint.
   * This method is a no-op retained for backward compatibility.
   * @deprecated No direct logout endpoint exists. Discard tokens client-side instead.
   */
  async logout(_idToken?: string): Promise<void> {
    // No-op: SimpleAuth direct API does not have a logout endpoint.
    // To "log out", simply discard the access and refresh tokens client-side.
  }

  // -------------------------------------------------------------------------
  // Token Verification (server-side)
  // -------------------------------------------------------------------------

  /**
   * Verify a JWT access token using the server's JWKS.
   * Checks RS256 signature, expiration, and issuer.
   * Returns a SimpleAuthUser with helper methods.
   */
  async verify(token: string): Promise<SimpleAuthUser> {
    const { header, payload, signatureInput, signature } = decodeJWT(token);

    if (header.alg !== 'RS256') {
      throw new SimpleAuthError(`Unsupported algorithm: ${header.alg}`, 401);
    }

    // Get the signing key
    const kid = header.kid;
    if (!kid) {
      throw new SimpleAuthError('JWT missing kid header', 401);
    }

    const jwk = await this.jwksCache.getKey(kid);

    // Verify signature
    const valid = await verifyRS256(signatureInput, signature, jwk);
    if (!valid) {
      throw new SimpleAuthError('Invalid token signature', 401);
    }

    // Check expiration
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp && payload.exp < now) {
      throw new SimpleAuthError('Token has expired', 401);
    }

    // Check issuer — accept the server URL as issuer
    const expectedIssuer = this.url;
    if (payload.iss && payload.iss !== expectedIssuer) {
      throw new SimpleAuthError(
        `Invalid issuer: expected "${expectedIssuer}", got "${payload.iss}"`,
        401,
      );
    }

    return payloadToUser(payload);
  }

  // -------------------------------------------------------------------------
  // User Info
  // -------------------------------------------------------------------------

  /**
   * Fetch user claims from the UserInfo endpoint.
   */
  async userInfo(accessToken: string): Promise<UserInfo> {
    const resp = await fetch(`${this.url}/api/auth/userinfo`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      throw new SimpleAuthError(
        err.error_description ?? 'UserInfo request failed',
        resp.status,
        err.error,
        err.error_description,
      );
    }

    return resp.json();
  }

  // -------------------------------------------------------------------------
  // Admin Operations (require adminKey as Bearer API key)
  // -------------------------------------------------------------------------

  /**
   * Get a user by GUID.
   * Requires adminKey (or clientSecret for backward compat).
   */
  async getUser(guid: string): Promise<User> {
    const resp = await fetch(`${this.url}/api/admin/users/${encodeURIComponent(guid)}`, {
      headers: { Authorization: this.adminAuthHeader() },
    });

    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      throw new SimpleAuthError(err.error ?? 'Failed to get user', resp.status);
    }

    return resp.json();
  }

  /**
   * Get the roles assigned to a user.
   * Requires adminKey (or clientSecret for backward compat).
   */
  async getUserRoles(guid: string): Promise<string[]> {
    const resp = await fetch(
      `${this.url}/api/admin/users/${encodeURIComponent(guid)}/roles`,
      { headers: { Authorization: this.adminAuthHeader() } },
    );

    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      throw new SimpleAuthError(err.error ?? 'Failed to get roles', resp.status);
    }

    return resp.json();
  }

  /**
   * Set the roles for a user.
   * Requires adminKey (or clientSecret for backward compat).
   */
  async setUserRoles(guid: string, roles: string[]): Promise<void> {
    const resp = await fetch(
      `${this.url}/api/admin/users/${encodeURIComponent(guid)}/roles`,
      {
        method: 'PUT',
        headers: {
          Authorization: this.adminAuthHeader(),
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(roles),
      },
    );

    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      throw new SimpleAuthError(err.error ?? 'Failed to set roles', resp.status);
    }
  }

  /**
   * Get the permissions assigned to a user.
   * Requires adminKey (or clientSecret for backward compat).
   */
  async getUserPermissions(guid: string): Promise<string[]> {
    const resp = await fetch(
      `${this.url}/api/admin/users/${encodeURIComponent(guid)}/permissions`,
      { headers: { Authorization: this.adminAuthHeader() } },
    );

    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      throw new SimpleAuthError(err.error ?? 'Failed to get permissions', resp.status);
    }

    return resp.json();
  }

  /**
   * Set the permissions for a user.
   * Requires adminKey (or clientSecret for backward compat).
   */
  async setUserPermissions(guid: string, permissions: string[]): Promise<void> {
    const resp = await fetch(
      `${this.url}/api/admin/users/${encodeURIComponent(guid)}/permissions`,
      {
        method: 'PUT',
        headers: {
          Authorization: this.adminAuthHeader(),
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(permissions),
      },
    );

    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      throw new SimpleAuthError(err.error ?? 'Failed to set permissions', resp.status);
    }
  }

  // -------------------------------------------------------------------------
  // Express Middleware
  // -------------------------------------------------------------------------

  /**
   * Create Express middleware that verifies the Bearer token and sets req.user.
   *
   * @param options.required - If true (default), returns 401 when no token is present.
   *                           If false, continues without setting req.user.
   */
  expressMiddleware(options?: { required?: boolean }): ExpressMiddleware {
    const required = options?.required ?? true;

    return async (req: ExpressRequest, res: ExpressResponse, next: ExpressNextFunction) => {
      const authHeader = req.headers['authorization'] ?? req.headers['Authorization'];
      const headerValue = Array.isArray(authHeader) ? authHeader[0] : authHeader;

      if (!headerValue || !headerValue.startsWith('Bearer ')) {
        if (required) {
          res.status(401).json({ error: 'Missing or invalid Authorization header' });
          return;
        }
        return next();
      }

      const token = headerValue.slice(7);

      try {
        const user = await this.verify(token);
        (req as any).user = user;
        next();
      } catch (err) {
        if (required) {
          const message = err instanceof SimpleAuthError ? err.message : 'Token verification failed';
          res.status(401).json({ error: message });
          return;
        }
        next();
      }
    };
  }
}

// ---------------------------------------------------------------------------
// Convenience factory
// ---------------------------------------------------------------------------

/**
 * Create a new SimpleAuth client.
 *
 * @example
 * ```ts
 * import { createSimpleAuth } from '@simpleauth/js';
 *
 * const auth = createSimpleAuth({
 *   url: 'https://auth.corp.local:9090',
 *   adminKey: 'my-admin-key',      // optional, for admin operations
 * });
 *
 * const tokens = await auth.login('admin', 'password');
 * const user = await auth.verify(tokens.access_token);
 * console.log(user.hasRole('admin'));
 * ```
 */
export function createSimpleAuth(options: SimpleAuthOptions): SimpleAuth {
  return new SimpleAuth(options);
}

// Default export
export default SimpleAuth;
