// ---------------------------------------------------------------------------
// SimpleAuth Example: Service-to-Service Authentication
// ---------------------------------------------------------------------------
// Demonstrates machine-to-machine (M2M) authentication using the client
// credentials grant. Common patterns:
//
//   1. Obtain a token via client credentials
//   2. Call another internal service with that token
//   3. Automatic token caching and renewal
//   4. Building a reusable authenticated HTTP client
//
// Usage:
//   npx tsx service-to-service.ts
// ---------------------------------------------------------------------------

import { createSimpleAuth, SimpleAuthError, TokenResponse } from "@simpleauth/js";

// ==========================================================================
// 1. Token Manager — caches tokens and refreshes before expiry
// ==========================================================================

class TokenManager {
  private auth;
  private cachedToken: TokenResponse | null = null;
  private tokenExpiresAt = 0; // Unix timestamp in seconds
  private refreshing: Promise<string> | null = null;

  /** How many seconds before expiry to preemptively refresh. */
  private readonly refreshMarginSec: number;

  constructor(options: {
    url: string;
    appId: string;
    appSecret: string;
    refreshMarginSec?: number;
  }) {
    this.auth = createSimpleAuth({
      url: options.url,
      appId: options.appId,
      appSecret: options.appSecret,
    });
    this.refreshMarginSec = options.refreshMarginSec ?? 30;
  }

  /**
   * Returns a valid access token. Automatically fetches a new one via
   * client_credentials if the cached token is missing or about to expire.
   *
   * Safe to call concurrently — concurrent callers share a single in-flight
   * token request.
   */
  async getToken(): Promise<string> {
    const nowSec = Math.floor(Date.now() / 1000);

    // Return cached token if still valid
    if (this.cachedToken && this.tokenExpiresAt - nowSec > this.refreshMarginSec) {
      return this.cachedToken.access_token;
    }

    // Deduplicate concurrent refresh requests
    if (this.refreshing) {
      return this.refreshing;
    }

    this.refreshing = this.fetchNewToken();

    try {
      return await this.refreshing;
    } finally {
      this.refreshing = null;
    }
  }

  private async fetchNewToken(): Promise<string> {
    // The SimpleAuth SDK does not expose a standalone clientCredentials()
    // method on the JS client, so we call the token endpoint directly.
    const tokenUrl = `${this.auth["url"]}/realms/${this.auth["realm"]}/protocol/openid-connect/token`;

    const body = new URLSearchParams({
      grant_type: "client_credentials",
      client_id: this.auth["appId"],
      client_secret: this.auth["appSecret"] ?? "",
    });

    const resp = await fetch(tokenUrl, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });

    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      throw new SimpleAuthError(
        err.error_description ?? "Client credentials grant failed",
        resp.status,
        err.error,
        err.error_description,
      );
    }

    const token: TokenResponse = await resp.json();
    this.cachedToken = token;
    this.tokenExpiresAt = Math.floor(Date.now() / 1000) + token.expires_in;

    console.log(
      "[TokenManager] New token acquired (expires in %d seconds)",
      token.expires_in,
    );

    return token.access_token;
  }

  /** Invalidate the cached token (e.g. after a 401 from a downstream service). */
  invalidate(): void {
    this.cachedToken = null;
    this.tokenExpiresAt = 0;
  }
}

// ==========================================================================
// 2. Authenticated HTTP Client
// ==========================================================================

/**
 * A thin HTTP client that automatically injects a Bearer token into every
 * outgoing request. Retries once on 401 in case the token was just revoked.
 */
class AuthenticatedClient {
  private tokenManager: TokenManager;
  private baseUrl: string;

  constructor(baseUrl: string, tokenManager: TokenManager) {
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.tokenManager = tokenManager;
  }

  async request<T = unknown>(
    method: string,
    path: string,
    options?: {
      body?: unknown;
      headers?: Record<string, string>;
    },
  ): Promise<T> {
    const doRequest = async (retry: boolean): Promise<T> => {
      const token = await this.tokenManager.getToken();

      const headers: Record<string, string> = {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
        ...options?.headers,
      };

      const resp = await fetch(`${this.baseUrl}${path}`, {
        method,
        headers,
        body: options?.body ? JSON.stringify(options.body) : undefined,
      });

      // Retry once on 401 — the token may have been revoked server-side
      if (resp.status === 401 && retry) {
        console.warn("[AuthenticatedClient] Got 401, refreshing token and retrying...");
        this.tokenManager.invalidate();
        return doRequest(false);
      }

      if (!resp.ok) {
        const text = await resp.text();
        throw new Error(`${method} ${path} failed (${resp.status}): ${text}`);
      }

      // Handle 204 No Content
      if (resp.status === 204) {
        return undefined as T;
      }

      return resp.json() as Promise<T>;
    };

    return doRequest(true);
  }

  async get<T = unknown>(path: string): Promise<T> {
    return this.request<T>("GET", path);
  }

  async post<T = unknown>(path: string, body: unknown): Promise<T> {
    return this.request<T>("POST", path, { body });
  }

  async put<T = unknown>(path: string, body: unknown): Promise<T> {
    return this.request<T>("PUT", path, { body });
  }

  async delete<T = unknown>(path: string): Promise<T> {
    return this.request<T>("DELETE", path);
  }
}

// ==========================================================================
// 3. Example: Calling an Internal Order Service
// ==========================================================================

interface Order {
  id: string;
  customer_id: string;
  total: number;
  status: string;
}

interface OrderService {
  listOrders(): Promise<Order[]>;
  getOrder(id: string): Promise<Order>;
  cancelOrder(id: string): Promise<void>;
}

function createOrderServiceClient(client: AuthenticatedClient): OrderService {
  return {
    async listOrders(): Promise<Order[]> {
      return client.get<Order[]>("/api/orders");
    },

    async getOrder(id: string): Promise<Order> {
      return client.get<Order>(`/api/orders/${encodeURIComponent(id)}`);
    },

    async cancelOrder(id: string): Promise<void> {
      await client.post(`/api/orders/${encodeURIComponent(id)}/cancel`, {});
    },
  };
}

// ==========================================================================
// 4. Main — putting it all together
// ==========================================================================

async function main() {
  // Create a token manager for this service's identity
  const tokenManager = new TokenManager({
    url: process.env.SIMPLEAUTH_URL ?? "https://auth.corp.local:9090",
    appId: process.env.SIMPLEAUTH_APP_ID ?? "billing-service",
    appSecret: process.env.SIMPLEAUTH_APP_SECRET ?? "billing-service-secret",
    refreshMarginSec: 60, // Refresh 60 seconds before expiry
  });

  // Create an authenticated client for the order service
  const orderServiceUrl = process.env.ORDER_SERVICE_URL ?? "https://orders.internal:8080";
  const httpClient = new AuthenticatedClient(orderServiceUrl, tokenManager);
  const orderService = createOrderServiceClient(httpClient);

  // -----------------------------------------------------------------------
  // Use the order service — the token is managed automatically
  // -----------------------------------------------------------------------

  console.log("[1] Listing recent orders...");
  try {
    const orders = await orderService.listOrders();
    console.log("  Found %d orders", orders.length);
    for (const order of orders.slice(0, 5)) {
      console.log("  - %s: $%s (%s)", order.id, order.total.toFixed(2), order.status);
    }
  } catch (err) {
    console.error("  Failed to list orders:", (err as Error).message);
  }

  console.log("\n[2] Fetching a specific order...");
  try {
    const order = await orderService.getOrder("order-42");
    console.log("  Order %s: $%s (%s)", order.id, order.total.toFixed(2), order.status);
  } catch (err) {
    console.error("  Failed to get order:", (err as Error).message);
  }

  console.log("\n[3] Cancelling an order...");
  try {
    await orderService.cancelOrder("order-42");
    console.log("  Order cancelled successfully.");
  } catch (err) {
    console.error("  Failed to cancel order:", (err as Error).message);
  }

  // -----------------------------------------------------------------------
  // Demonstrate that repeated calls reuse the cached token
  // -----------------------------------------------------------------------
  console.log("\n[4] Making multiple rapid calls (token should be cached)...");
  const start = Date.now();
  await Promise.all([
    orderService.listOrders().catch(() => {}),
    orderService.listOrders().catch(() => {}),
    orderService.listOrders().catch(() => {}),
  ]);
  console.log("  3 parallel calls completed in %d ms", Date.now() - start);
}

// --- Entry point ----------------------------------------------------------

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
