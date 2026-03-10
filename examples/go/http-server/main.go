// ---------------------------------------------------------------------------
// SimpleAuth Example: Protected HTTP API Server (Go)
// ---------------------------------------------------------------------------
// Demonstrates building a protected REST API using the standard library
// HTTP mux (Go 1.22+) with SimpleAuth middleware. Shows:
//
//   - Public endpoints (no auth)
//   - Protected endpoints (any authenticated user)
//   - Role-restricted endpoints (admin only)
//   - Permission-restricted endpoints
//   - Custom middleware composition
//   - JSON response helpers
//
// Usage:
//   go run main.go
//
// Test:
//   curl http://localhost:8080/health
//   curl http://localhost:8080/api/profile -H "Authorization: Bearer <token>"
//   curl http://localhost:8080/api/admin/users -H "Authorization: Bearer <token>"
//
// Environment variables:
//   SIMPLEAUTH_URL, PORT
// ---------------------------------------------------------------------------
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	simpleauth "github.com/bodaay/simpleauth-go"
)

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}

// jsonError writes a JSON error response.
func jsonError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func main() {
	// -----------------------------------------------------------------
	// Initialize SimpleAuth client
	// -----------------------------------------------------------------
	auth := simpleauth.New(simpleauth.Options{
		URL:                envOr("SIMPLEAUTH_URL", "https://auth.corp.local:9090"),
		InsecureSkipVerify: true,
	})

	// -----------------------------------------------------------------
	// Set up routes using Go 1.22 enhanced mux
	// -----------------------------------------------------------------
	mux := http.NewServeMux()

	// --- Public routes ------------------------------------------------

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"status":    "ok",
			"timestamp": time.Now().Format(time.RFC3339),
		})
	})

	mux.HandleFunc("GET /api/public/info", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"service": "my-api-service",
			"version": "1.0.0",
		})
	})

	// --- Protected routes (any authenticated user) --------------------

	// Use auth.Middleware() to protect a group of routes.
	// UserFromContext retrieves the verified user from the request context.

	mux.Handle("GET /api/profile", auth.Middleware(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			user := simpleauth.UserFromContext(r.Context())
			writeJSON(w, http.StatusOK, map[string]any{
				"id":         user.Sub,
				"name":       user.Name,
				"email":      user.Email,
				"department": user.Department,
				"company":    user.Company,
				"job_title":  user.JobTitle,
				"roles":      user.Roles,
				"groups":     user.Groups,
			})
		},
	)))

	mux.Handle("GET /api/dashboard", auth.Middleware(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			user := simpleauth.UserFromContext(r.Context())
			writeJSON(w, http.StatusOK, map[string]any{
				"welcome":       fmt.Sprintf("Welcome back, %s", user.Name),
				"notifications": 5,
			})
		},
	)))

	// --- Role-restricted routes (admin only) --------------------------

	// auth.RequireRole() combines auth.Middleware() + a role check.
	// Returns 401 if unauthenticated, 403 if the role is missing.

	mux.Handle("GET /api/admin/users", auth.RequireRole("admin", http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			// In a real app, query your database here
			writeJSON(w, http.StatusOK, map[string]any{
				"users": []map[string]string{
					{"id": "user-1", "name": "Alice", "role": "editor"},
					{"id": "user-2", "name": "Bob", "role": "viewer"},
				},
				"total": 2,
			})
		},
	)))

	mux.Handle("DELETE /api/admin/users/{userId}", auth.RequireRole("admin", http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			userID := r.PathValue("userId")
			writeJSON(w, http.StatusOK, map[string]string{
				"message": "User deleted",
				"user_id": userID,
			})
		},
	)))

	// --- Permission-restricted routes ---------------------------------

	mux.Handle("POST /api/reports", auth.RequirePermission("reports:create", http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			user := simpleauth.UserFromContext(r.Context())

			var body struct {
				Title   string `json:"title"`
				Content string `json:"content"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				jsonError(w, http.StatusBadRequest, "Invalid request body")
				return
			}

			writeJSON(w, http.StatusCreated, map[string]any{
				"id":         fmt.Sprintf("report-%d", time.Now().UnixMilli()),
				"title":      body.Title,
				"content":    body.Content,
				"author":     user.Sub,
				"created_at": time.Now().Format(time.RFC3339),
			})
		},
	)))

	mux.Handle("DELETE /api/reports/{reportId}", auth.RequirePermission("reports:delete", http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			reportID := r.PathValue("reportId")
			writeJSON(w, http.StatusOK, map[string]string{
				"message":   "Report deleted",
				"report_id": reportID,
			})
		},
	)))

	// --- Custom composite middleware ----------------------------------
	// For more complex authorization, compose your own middleware.

	mux.Handle("POST /api/admin/users/{userId}/roles", auth.Middleware(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			user := simpleauth.UserFromContext(r.Context())

			// Allow admins or user-managers
			if !user.HasAnyRole("admin", "user-manager") {
				jsonError(w, http.StatusForbidden, "Requires admin or user-manager role")
				return
			}

			userID := r.PathValue("userId")

			var body struct {
				Roles []string `json:"roles"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				jsonError(w, http.StatusBadRequest, "Invalid request body")
				return
			}

			writeJSON(w, http.StatusOK, map[string]any{
				"message": "Roles updated",
				"user_id": userID,
				"roles":   body.Roles,
			})
		},
	)))

	// -----------------------------------------------------------------
	// Start server
	// -----------------------------------------------------------------
	port := envOr("PORT", "8080")
	addr := ":" + port

	fmt.Printf("API server listening on http://localhost%s\n", addr)
	fmt.Println("Routes:")
	fmt.Println("  GET    /health                       — public health check")
	fmt.Println("  GET    /api/public/info               — public service info")
	fmt.Println("  GET    /api/profile                   — authenticated user profile")
	fmt.Println("  GET    /api/dashboard                 — authenticated dashboard")
	fmt.Println("  GET    /api/admin/users               — admin: list users")
	fmt.Println("  DELETE /api/admin/users/{userId}      — admin: delete user")
	fmt.Println("  POST   /api/admin/users/{userId}/roles — admin/user-manager: set roles")
	fmt.Println("  POST   /api/reports                   — requires reports:create")
	fmt.Println("  DELETE /api/reports/{reportId}        — requires reports:delete")

	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
