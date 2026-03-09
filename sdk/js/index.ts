// SimpleAuth JavaScript/TypeScript SDK
// Zero-dependency, works in Node.js (18+) and browsers

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface SimpleAuthOptions {
  /** SimpleAuth server URL (e.g. https://auth.corp.local:9090) */
  url: string;
  /** App ID (client_id) */
  appId: string;
  /** App API key (client_secret) — required for server-side admin operations */
  appSecret?: string;
  /** OIDC realm (default: 'simpleauth') */
  realm?: string;
}

export interface TokenResponse {
  access_token: string;
  refresh_token?: string;
  id_token?: string;
  token_type: string;
  expires_in: number;
  scope?: string;
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
  app_id?: string;

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
  app_id?: string;
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

/** Base64 encode a string (for Basic auth) */
function base64Encode(str: string): string {
  if (typeof globalThis.btoa === 'function') {
    return globalThis.btoa(str);
  }
  return Buffer.from(str).toString('base64');
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
    app_id: payload.app_id,
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
  private readonly appId: string;
  private readonly appSecret?: string;
  private readonly realm: string;
  private readonly jwksCache: JWKSCache;

  constructor(options: SimpleAuthOptions) {
    // Strip trailing slash
    this.url = options.url.replace(/\/+$/, '');
    this.appId = options.appId;
    this.appSecret = options.appSecret;
    this.realm = options.realm ?? 'simpleauth';

    const jwksUrl = `${this.url}/realms/${this.realm}/protocol/openid-connect/certs`;
    this.jwksCache = new JWKSCache(jwksUrl);
  }

  /** OIDC prefix for this realm */
  private get oidcPrefix(): string {
    return `${this.url}/realms/${this.realm}/protocol/openid-connect`;
  }

  /** Build Basic auth header from appId:appSecret */
  private basicAuthHeader(): string {
    const secret = this.appSecret ?? '';
    return 'Basic ' + base64Encode(
      encodeURIComponent(this.appId) + ':' + encodeURIComponent(secret),
    );
  }

  /** Build admin Bearer header (uses appSecret as API key) */
  private adminAuthHeader(): string {
    if (!this.appSecret) {
      throw new SimpleAuthError('appSecret is required for admin operations', 401);
    }
    return 'Bearer ' + this.appSecret;
  }

  // -------------------------------------------------------------------------
  // Authentication
  // -------------------------------------------------------------------------

  /**
   * Authenticate using the Resource Owner Password Credentials grant.
   * Uses the OIDC token endpoint with grant_type=password.
   */
  async login(username: string, password: string): Promise<TokenResponse> {
    const body = new URLSearchParams({
      grant_type: 'password',
      username,
      password,
      scope: 'openid profile email',
    });

    const resp = await fetch(`${this.oidcPrefix}/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Authorization: this.basicAuthHeader(),
      },
      body: body.toString(),
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
    const body = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
    });

    const resp = await fetch(`${this.oidcPrefix}/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Authorization: this.basicAuthHeader(),
      },
      body: body.toString(),
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
   * End the user session via the OIDC logout endpoint.
   * Optionally pass the id_token to revoke all sessions.
   */
  async logout(idToken?: string): Promise<void> {
    const params = new URLSearchParams();
    if (idToken) {
      params.set('id_token_hint', idToken);
    }

    const resp = await fetch(`${this.oidcPrefix}/logout`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params.toString(),
      redirect: 'manual', // logout may redirect
    });

    // 200, 204, or 302 are all acceptable
    if (!resp.ok && resp.status !== 302) {
      throw new SimpleAuthError('Logout failed', resp.status);
    }
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

    // Check issuer
    const expectedIssuer = `${this.url}/realms/${this.realm}`;
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
   * Fetch user claims from the OIDC UserInfo endpoint.
   */
  async userInfo(accessToken: string): Promise<UserInfo> {
    const resp = await fetch(`${this.oidcPrefix}/userinfo`, {
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
  // OIDC Authorization Code Flow
  // -------------------------------------------------------------------------

  /**
   * Build the authorization URL for the OIDC authorization code flow.
   * Redirect the user's browser to this URL.
   */
  getAuthorizationUrl(options: {
    redirectUri: string;
    state?: string;
    scope?: string;
    nonce?: string;
  }): string {
    const params = new URLSearchParams({
      client_id: this.appId,
      response_type: 'code',
      redirect_uri: options.redirectUri,
      scope: options.scope ?? 'openid profile email',
    });

    if (options.state) params.set('state', options.state);
    if (options.nonce) params.set('nonce', options.nonce);

    return `${this.oidcPrefix}/auth?${params.toString()}`;
  }

  /**
   * Exchange an authorization code for tokens.
   */
  async exchangeCode(code: string, redirectUri: string): Promise<TokenResponse> {
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri,
    });

    const resp = await fetch(`${this.oidcPrefix}/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Authorization: this.basicAuthHeader(),
      },
      body: body.toString(),
    });

    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      throw new SimpleAuthError(
        err.error_description ?? err.error ?? 'Code exchange failed',
        resp.status,
        err.error,
        err.error_description,
      );
    }

    return resp.json();
  }

  // -------------------------------------------------------------------------
  // Admin Operations (require appSecret as Bearer API key)
  // -------------------------------------------------------------------------

  /**
   * Get a user by GUID.
   * Requires appSecret (admin API key).
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
   * Get the roles assigned to a user for this app.
   * Requires appSecret (admin API key).
   */
  async getUserRoles(guid: string): Promise<string[]> {
    const resp = await fetch(
      `${this.url}/api/admin/apps/${encodeURIComponent(this.appId)}/users/${encodeURIComponent(guid)}/roles`,
      { headers: { Authorization: this.adminAuthHeader() } },
    );

    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      throw new SimpleAuthError(err.error ?? 'Failed to get roles', resp.status);
    }

    return resp.json();
  }

  /**
   * Set the roles for a user in this app.
   * Requires appSecret (admin API key).
   */
  async setUserRoles(guid: string, roles: string[]): Promise<void> {
    const resp = await fetch(
      `${this.url}/api/admin/apps/${encodeURIComponent(this.appId)}/users/${encodeURIComponent(guid)}/roles`,
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
   * Get the permissions assigned to a user for this app.
   * Requires appSecret (admin API key).
   */
  async getUserPermissions(guid: string): Promise<string[]> {
    const resp = await fetch(
      `${this.url}/api/admin/apps/${encodeURIComponent(this.appId)}/users/${encodeURIComponent(guid)}/permissions`,
      { headers: { Authorization: this.adminAuthHeader() } },
    );

    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      throw new SimpleAuthError(err.error ?? 'Failed to get permissions', resp.status);
    }

    return resp.json();
  }

  /**
   * Set the permissions for a user in this app.
   * Requires appSecret (admin API key).
   */
  async setUserPermissions(guid: string, permissions: string[]): Promise<void> {
    const resp = await fetch(
      `${this.url}/api/admin/apps/${encodeURIComponent(this.appId)}/users/${encodeURIComponent(guid)}/permissions`,
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
 *   appId: 'my-app',
 *   appSecret: 'my-api-key',
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
