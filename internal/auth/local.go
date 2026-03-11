package auth

import (
	"fmt"
	"strings"
	"unicode"

	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func CheckPassword(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// PasswordPolicy holds the password complexity requirements.
type PasswordPolicy struct {
	MinLength        int
	RequireUppercase bool
	RequireLowercase bool
	RequireDigit     bool
	RequireSpecial   bool
}

// ValidatePassword checks a password against the configured policy.
// Returns nil if the password meets all requirements.
func ValidatePassword(password string, policy PasswordPolicy) error {
	if len(password) < policy.MinLength {
		return fmt.Errorf("password must be at least %d characters", policy.MinLength)
	}

	var missing []string

	if policy.RequireUppercase {
		found := false
		for _, r := range password {
			if unicode.IsUpper(r) {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, "uppercase letter")
		}
	}

	if policy.RequireLowercase {
		found := false
		for _, r := range password {
			if unicode.IsLower(r) {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, "lowercase letter")
		}
	}

	if policy.RequireDigit {
		found := false
		for _, r := range password {
			if unicode.IsDigit(r) {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, "digit")
		}
	}

	if policy.RequireSpecial {
		found := false
		for _, r := range password {
			if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, "special character")
		}
	}

	if len(missing) > 0 {
		return fmt.Errorf("password must contain: %s", strings.Join(missing, ", "))
	}

	return nil
}

// CheckPasswordHistory checks if a password matches any of the stored history hashes.
// Returns true if the password was previously used.
func CheckPasswordHistory(password string, history []string) bool {
	for _, h := range history {
		if CheckPassword(h, password) {
			return true
		}
	}
	return false
}

// AddToPasswordHistory adds a hash to the history, keeping only the last N entries.
func AddToPasswordHistory(history []string, hash string, maxCount int) []string {
	if maxCount <= 0 {
		return nil
	}
	history = append(history, hash)
	if len(history) > maxCount {
		history = history[len(history)-maxCount:]
	}
	return history
}
