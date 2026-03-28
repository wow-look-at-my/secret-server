package csrf

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
)

type contextKey struct{}

// TokenFromContext returns the CSRF token stored in the request context.
func TokenFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(contextKey{}).(string); ok {
		return v
	}
	return ""
}

func generateToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("csrf: failed to generate random token: " + err.Error())
	}
	return hex.EncodeToString(b)
}

const cookieName = "csrf_token"

// Protect returns middleware that enforces double-submit cookie CSRF protection.
// GET/HEAD/OPTIONS requests get a token set; POST/PUT/DELETE requests must include
// the token as a form field matching the cookie.
func Protect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost, http.MethodPut, http.MethodDelete:
			cookie, err := r.Cookie(cookieName)
			if err != nil || cookie.Value == "" {
				http.Error(w, "Forbidden - missing CSRF token", http.StatusForbidden)
				return
			}
			if err := r.ParseForm(); err != nil {
				http.Error(w, "Bad Request", http.StatusBadRequest)
				return
			}
			formToken := r.FormValue("csrf_token")
			if formToken == "" || formToken != cookie.Value {
				http.Error(w, "Forbidden - CSRF token mismatch", http.StatusForbidden)
				return
			}
			// Token valid — put it in context and continue
			ctx := context.WithValue(r.Context(), contextKey{}, cookie.Value)
			next.ServeHTTP(w, r.WithContext(ctx))
		default:
			// For safe methods, ensure a token exists
			token := ""
			if cookie, err := r.Cookie(cookieName); err == nil && cookie.Value != "" {
				token = cookie.Value
			} else {
				token = generateToken()
				http.SetCookie(w, &http.Cookie{
					Name:     cookieName,
					Value:    token,
					Path:     "/",
					HttpOnly: false, // JS needs to read it for AJAX if needed
					SameSite: http.SameSiteStrictMode,
					Secure:   r.TLS != nil,
				})
			}
			ctx := context.WithValue(r.Context(), contextKey{}, token)
			next.ServeHTTP(w, r.WithContext(ctx))
		}
	})
}
