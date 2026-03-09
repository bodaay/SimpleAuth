// ---------------------------------------------------------------------------
// SimpleAuth Example: Express.js Protected API
// ---------------------------------------------------------------------------
// Demonstrates building a REST API with Express where routes are protected
// by SimpleAuth JWT verification. Shows:
//   - Public routes (no auth required)
//   - Optional auth routes (user info available if logged in)
//   - Protected routes (any authenticated user)
//   - Role-restricted routes (admin only)
//   - Permission-restricted routes (fine-grained access)
//   - Centralized error handling
//
// Usage:
//   npm install express
//   npx tsx express-api.ts
//
// Test with:
//   curl http://localhost:3000/health
//   curl http://localhost:3000/api/profile -H "Authorization: Bearer <token>"
//   curl http://localhost:3000/api/admin/users -H "Authorization: Bearer <token>"
// ---------------------------------------------------------------------------

import express, { Request, Response, NextFunction } from "express";
import { createSimpleAuth, SimpleAuthError, SimpleAuthUser } from "@simpleauth/js";

// Extend the Express Request type so TypeScript knows about req.user
declare global {
  namespace Express {
    interface Request {
      user?: SimpleAuthUser;
    }
  }
}

// --- Configuration --------------------------------------------------------

const auth = createSimpleAuth({
  url: process.env.SIMPLEAUTH_URL ?? "https://auth.corp.local:9090",
  appId: process.env.SIMPLEAUTH_APP_ID ?? "my-api-service",
  appSecret: process.env.SIMPLEAUTH_APP_SECRET ?? "my-api-secret",
});

const app = express();
app.use(express.json());

// --- Middleware factories --------------------------------------------------

/**
 * Require authentication. Returns 401 if no valid Bearer token is present.
 * On success, populates req.user with the verified SimpleAuthUser.
 */
const requireAuth = auth.expressMiddleware({ required: true });

/**
 * Optional authentication. If a Bearer token is present and valid, req.user
 * is populated. If missing or invalid, the request continues without a user.
 */
const optionalAuth = auth.expressMiddleware({ required: false });

/**
 * Require a specific role. Must be used AFTER requireAuth.
 */
function requireRole(...roles: string[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = req.user;
    if (!user) {
      res.status(401).json({ error: "Authentication required" });
      return;
    }
    if (!user.hasAnyRole(...roles)) {
      res.status(403).json({
        error: "Forbidden",
        message: `Required role: ${roles.join(" or ")}`,
      });
      return;
    }
    next();
  };
}

/**
 * Require a specific permission. Must be used AFTER requireAuth.
 */
function requirePermission(permission: string) {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = req.user;
    if (!user) {
      res.status(401).json({ error: "Authentication required" });
      return;
    }
    if (!user.hasPermission(permission)) {
      res.status(403).json({
        error: "Forbidden",
        message: `Required permission: ${permission}`,
      });
      return;
    }
    next();
  };
}

// --- Public routes --------------------------------------------------------

app.get("/health", (_req: Request, res: Response) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

app.get("/api/public/info", (_req: Request, res: Response) => {
  res.json({
    service: "my-api-service",
    version: "1.0.0",
    docs: "https://docs.example.com/api",
  });
});

// --- Optional auth routes -------------------------------------------------

// The greeting is personalized if the user is logged in
app.get("/api/greeting", optionalAuth, (req: Request, res: Response) => {
  if (req.user) {
    res.json({ message: `Hello, ${req.user.name ?? req.user.preferred_username ?? "user"}!` });
  } else {
    res.json({ message: "Hello, anonymous visitor!" });
  }
});

// --- Protected routes (any authenticated user) ----------------------------

app.get("/api/profile", requireAuth, (req: Request, res: Response) => {
  const user = req.user!;
  res.json({
    id: user.sub,
    name: user.name,
    email: user.email,
    department: user.department,
    company: user.company,
    job_title: user.job_title,
    roles: user.roles,
    permissions: user.permissions,
    groups: user.groups,
  });
});

app.get("/api/dashboard", requireAuth, (req: Request, res: Response) => {
  const user = req.user!;
  res.json({
    welcome: `Welcome back, ${user.name ?? user.sub}`,
    notifications: 3,
    recent_activity: [
      { action: "login", timestamp: new Date().toISOString() },
    ],
  });
});

// --- Role-restricted routes (admin only) ----------------------------------

app.get(
  "/api/admin/users",
  requireAuth,
  requireRole("admin"),
  async (_req: Request, res: Response, next: NextFunction) => {
    try {
      // In a real app, you would query your database here.
      // The admin API key on the SimpleAuth client could also be used
      // to fetch user details from SimpleAuth's admin endpoints.
      res.json({
        users: [
          { id: "user-1", name: "Alice", role: "editor" },
          { id: "user-2", name: "Bob", role: "viewer" },
        ],
        total: 2,
      });
    } catch (err) {
      next(err);
    }
  },
);

app.post(
  "/api/admin/users/:userId/roles",
  requireAuth,
  requireRole("admin", "user-manager"),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { userId } = req.params;
      const { roles } = req.body as { roles: string[] };

      // Use the admin SDK to update roles on SimpleAuth
      await auth.setUserRoles(userId, roles);

      res.json({ message: "Roles updated", userId, roles });
    } catch (err) {
      next(err);
    }
  },
);

// --- Permission-restricted routes -----------------------------------------

app.delete(
  "/api/reports/:reportId",
  requireAuth,
  requirePermission("reports:delete"),
  (req: Request, res: Response) => {
    const { reportId } = req.params;
    // In a real app: delete the report from the database
    res.json({ message: "Report deleted", reportId });
  },
);

app.post(
  "/api/reports",
  requireAuth,
  requirePermission("reports:create"),
  (req: Request, res: Response) => {
    const user = req.user!;
    const { title, content } = req.body as { title: string; content: string };
    res.status(201).json({
      id: "report-" + Date.now(),
      title,
      content,
      author: user.sub,
      created_at: new Date().toISOString(),
    });
  },
);

// --- Centralized error handler --------------------------------------------

app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
  if (err instanceof SimpleAuthError) {
    console.error("[SimpleAuth Error]", err.message, {
      status: err.status,
      code: err.code,
    });
    res.status(err.status).json({
      error: err.code ?? "auth_error",
      message: err.message,
    });
    return;
  }

  console.error("[Unhandled Error]", err);
  res.status(500).json({ error: "internal_error", message: "Something went wrong" });
});

// --- Start server ---------------------------------------------------------

const PORT = parseInt(process.env.PORT ?? "3000", 10);

app.listen(PORT, () => {
  console.log(`API server listening on http://localhost:${PORT}`);
  console.log("Routes:");
  console.log("  GET  /health                   — public health check");
  console.log("  GET  /api/public/info           — public service info");
  console.log("  GET  /api/greeting              — optional auth greeting");
  console.log("  GET  /api/profile               — authenticated user profile");
  console.log("  GET  /api/dashboard             — authenticated user dashboard");
  console.log("  GET  /api/admin/users           — admin only: list users");
  console.log("  POST /api/admin/users/:id/roles — admin/user-manager: assign roles");
  console.log("  POST /api/reports               — requires reports:create permission");
  console.log("  DEL  /api/reports/:id           — requires reports:delete permission");
});
