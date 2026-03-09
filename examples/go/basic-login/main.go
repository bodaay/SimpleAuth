// ---------------------------------------------------------------------------
// SimpleAuth Example: Basic Login (Go)
// ---------------------------------------------------------------------------
// Demonstrates the fundamental authentication lifecycle in Go:
//   1. Login with username and password
//   2. Verify the returned access token
//   3. Print user info and check roles/permissions
//   4. Refresh the token
//
// Usage:
//   go run main.go
//
// Environment variables:
//   SIMPLEAUTH_URL        — SimpleAuth server URL (default: https://auth.corp.local:9090)
//   SIMPLEAUTH_APP_ID     — Application ID (default: my-go-app)
//   SIMPLEAUTH_APP_SECRET — Application secret (default: my-app-secret)
//   TEST_USERNAME         — Username for login (default: admin)
//   TEST_PASSWORD         — Password for login (default: admin123)
// ---------------------------------------------------------------------------
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/simpleauth/sdk/go/simpleauth"
)

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	// -----------------------------------------------------------------
	// Initialize the client
	// -----------------------------------------------------------------
	client := simpleauth.New(simpleauth.Options{
		URL:                envOr("SIMPLEAUTH_URL", "https://auth.corp.local:9090"),
		AppID:              envOr("SIMPLEAUTH_APP_ID", "my-go-app"),
		AppSecret:          envOr("SIMPLEAUTH_APP_SECRET", "my-app-secret"),
		InsecureSkipVerify: true, // Only for development with self-signed certs
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	username := envOr("TEST_USERNAME", "admin")
	password := envOr("TEST_PASSWORD", "admin123")

	// -----------------------------------------------------------------
	// Step 1: Login
	// -----------------------------------------------------------------
	fmt.Println("[1] Logging in...")

	tokens, err := client.Login(ctx, username, password)
	if err != nil {
		log.Fatalf("Login failed: %v", err)
	}

	fmt.Printf("  Access token received (expires in %d seconds)\n", tokens.ExpiresIn)
	fmt.Printf("  Token type: %s\n", tokens.TokenType)
	fmt.Printf("  Refresh token present: %v\n", tokens.RefreshToken != "")

	// -----------------------------------------------------------------
	// Step 2: Verify the access token
	// -----------------------------------------------------------------
	fmt.Println("\n[2] Verifying access token...")

	user, err := client.Verify(tokens.AccessToken)
	if err != nil {
		log.Fatalf("Token verification failed: %v", err)
	}

	fmt.Printf("  User ID (sub): %s\n", user.Sub)
	fmt.Printf("  Name: %s\n", orDefault(user.Name, "(not set)"))
	fmt.Printf("  Email: %s\n", orDefault(user.Email, "(not set)"))
	fmt.Printf("  Username: %s\n", orDefault(user.PreferredUsername, "(not set)"))
	fmt.Printf("  Department: %s\n", orDefault(user.Department, "(not set)"))
	fmt.Printf("  Company: %s\n", orDefault(user.Company, "(not set)"))
	fmt.Printf("  Job Title: %s\n", orDefault(user.JobTitle, "(not set)"))
	fmt.Printf("  Roles: %s\n", orDefault(strings.Join(user.Roles, ", "), "(none)"))
	fmt.Printf("  Permissions: %s\n", orDefault(strings.Join(user.Permissions, ", "), "(none)"))
	fmt.Printf("  Groups: %s\n", orDefault(strings.Join(user.Groups, ", "), "(none)"))

	// Use the built-in helper methods
	fmt.Println("\n  Role checks:")
	fmt.Printf("    Is admin? %v\n", user.HasRole("admin"))
	fmt.Printf("    Is editor? %v\n", user.HasRole("editor"))
	fmt.Printf("    Is admin or editor? %v\n", user.HasAnyRole("admin", "editor"))
	fmt.Printf("    Can delete users? %v\n", user.HasPermission("users:delete"))

	// -----------------------------------------------------------------
	// Step 3: Fetch user info from OIDC endpoint
	// -----------------------------------------------------------------
	fmt.Println("\n[3] Fetching user info from OIDC endpoint...")

	info, err := client.UserInfo(ctx, tokens.AccessToken)
	if err != nil {
		log.Fatalf("UserInfo failed: %v", err)
	}

	fmt.Printf("  Subject: %s\n", info.Sub)
	fmt.Printf("  Name: %s\n", orDefault(info.Name, "(not set)"))
	fmt.Printf("  Email: %s\n", orDefault(info.Email, "(not set)"))
	fmt.Printf("  Preferred Username: %s\n", orDefault(info.PreferredUsername, "(not set)"))

	// -----------------------------------------------------------------
	// Step 4: Refresh the token
	// -----------------------------------------------------------------
	fmt.Println("\n[4] Refreshing token...")

	if tokens.RefreshToken == "" {
		fmt.Println("  No refresh token available, skipping.")
	} else {
		refreshed, err := client.Refresh(ctx, tokens.RefreshToken)
		if err != nil {
			log.Fatalf("Token refresh failed: %v", err)
		}

		fmt.Printf("  New access token received (expires in %d seconds)\n", refreshed.ExpiresIn)

		// Verify the new token
		refreshedUser, err := client.Verify(refreshed.AccessToken)
		if err != nil {
			log.Fatalf("Refreshed token verification failed: %v", err)
		}
		fmt.Printf("  Verified refreshed token — user: %s\n", refreshedUser.Sub)
	}

	fmt.Println("\nDone.")
}

func orDefault(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
