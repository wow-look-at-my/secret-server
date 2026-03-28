package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

type CFAccessIdentity struct {
	Subject string
	Email   string
}

type contextKey string

const cfIdentityKey contextKey = "cf-identity"

func CFIdentityFromContext(ctx context.Context) *CFAccessIdentity {
	id, _ := ctx.Value(cfIdentityKey).(*CFAccessIdentity)
	return id
}

type CloudflareAccessValidator struct {
	teamDomain string
	audience   string
	certsURL   string
	mu         sync.RWMutex
	jwks       *jose.JSONWebKeySet
	fetched    time.Time
}

func NewCloudflareAccessValidator(teamDomain, audience string) *CloudflareAccessValidator {
	return &CloudflareAccessValidator{
		teamDomain: teamDomain,
		audience:   audience,
	}
}

func (v *CloudflareAccessValidator) ValidateRequest(r *http.Request) (*CFAccessIdentity, error) {
	token := r.Header.Get("Cf-Access-Jwt-Assertion")
	if token == "" {
		if cookie, err := r.Cookie("CF_Authorization"); err == nil {
			token = cookie.Value
		}
	}
	if token == "" {
		return nil, fmt.Errorf("no CF Access token found")
	}

	keys, err := v.getKeys(r.Context())
	if err != nil {
		return nil, fmt.Errorf("get CF JWKS: %w", err)
	}

	tok, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return nil, fmt.Errorf("parse CF JWT: %w", err)
	}

	var found *jose.JSONWebKey
	for _, header := range tok.Headers {
		if header.KeyID != "" {
			matches := keys.Key(header.KeyID)
			if len(matches) > 0 {
				found = &matches[0]
				break
			}
		}
	}
	if found == nil {
		return nil, fmt.Errorf("no matching key found in CF JWKS")
	}

	stdClaims := jwt.Claims{}
	var customClaims struct {
		Email string `json:"email"`
	}
	if err := tok.Claims(found.Key, &stdClaims, &customClaims); err != nil {
		return nil, fmt.Errorf("verify CF claims: %w", err)
	}

	expected := jwt.Expected{
		Time:        time.Now(),
		AnyAudience: []string{v.audience},
	}
	if err := stdClaims.Validate(expected); err != nil {
		return nil, fmt.Errorf("validate CF claims: %w", err)
	}

	return &CFAccessIdentity{
		Subject: stdClaims.Subject,
		Email:   customClaims.Email,
	}, nil
}

func (v *CloudflareAccessValidator) RequireCFAccess(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, err := v.ValidateRequest(r)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), cfIdentityKey, identity)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (v *CloudflareAccessValidator) getKeys(ctx context.Context) (*jose.JSONWebKeySet, error) {
	v.mu.RLock()
	if v.jwks != nil && time.Since(v.fetched) < jwksCacheTTL {
		defer v.mu.RUnlock()
		return v.jwks, nil
	}
	v.mu.RUnlock()

	v.mu.Lock()
	defer v.mu.Unlock()

	if v.jwks != nil && time.Since(v.fetched) < jwksCacheTTL {
		return v.jwks, nil
	}

	jwksURL := v.certsURL
	if jwksURL == "" {
		jwksURL = fmt.Sprintf("https://%s.cloudflareaccess.com/cdn-cgi/access/certs", v.teamDomain)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create CF JWKS request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch CF JWKS: %w", err)
	}
	defer resp.Body.Close()

	var raw struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode CF JWKS: %w", err)
	}

	var jwks jose.JSONWebKeySet
	for _, keyData := range raw.Keys {
		var jwk jose.JSONWebKey
		if err := jwk.UnmarshalJSON(keyData); err != nil {
			continue
		}
		jwks.Keys = append(jwks.Keys, jwk)
	}

	v.jwks = &jwks
	v.fetched = time.Now()
	return &jwks, nil
}
