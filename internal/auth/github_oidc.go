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

const (
	githubOIDCDiscovery = "https://token.actions.githubusercontent.com/.well-known/openid-configuration"
	jwksCacheTTL        = 1 * time.Hour
)

type GitHubClaims struct {
	Subject         string `json:"-"` // populated from jwt.Claims.Subject
	Repository      string `json:"repository"`
	RepositoryOwner string `json:"repository_owner"`
	Actor           string `json:"actor"`
	Workflow        string `json:"workflow"`
	Ref             string `json:"ref"`
	Environment     string `json:"environment"`
}

type GitHubOIDCValidator struct {
	audience     string
	discoveryURL string
	mu           sync.RWMutex
	jwks         *jose.JSONWebKeySet
	fetched      time.Time
	jwksURL      string
}

func NewGitHubOIDCValidator(audience string) *GitHubOIDCValidator {
	return &GitHubOIDCValidator{
		audience:     audience,
		discoveryURL: githubOIDCDiscovery,
	}
}

func (v *GitHubOIDCValidator) ValidateToken(ctx context.Context, tokenString string) (*GitHubClaims, error) {
	keys, err := v.getKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("get JWKS: %w", err)
	}

	tok, err := jwt.ParseSigned(tokenString, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return nil, fmt.Errorf("parse JWT: %w", err)
	}

	// Find the matching key
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
		return nil, fmt.Errorf("no matching key found in JWKS")
	}

	// Validate standard claims
	stdClaims := jwt.Claims{}
	customClaims := GitHubClaims{}
	if err := tok.Claims(found.Key, &stdClaims, &customClaims); err != nil {
		return nil, fmt.Errorf("verify claims: %w", err)
	}

	expected := jwt.Expected{
		Issuer:   "https://token.actions.githubusercontent.com",
		Time:     time.Now(),
	}
	if v.audience != "" {
		expected.AnyAudience = []string{v.audience}
	}
	if err := stdClaims.Validate(expected); err != nil {
		return nil, fmt.Errorf("validate standard claims: %w", err)
	}

	customClaims.Subject = stdClaims.Subject
	return &customClaims, nil
}

func (v *GitHubOIDCValidator) getKeys(ctx context.Context) (*jose.JSONWebKeySet, error) {
	v.mu.RLock()
	if v.jwks != nil && time.Since(v.fetched) < jwksCacheTTL {
		defer v.mu.RUnlock()
		return v.jwks, nil
	}
	v.mu.RUnlock()

	v.mu.Lock()
	defer v.mu.Unlock()

	// Double-check after acquiring write lock
	if v.jwks != nil && time.Since(v.fetched) < jwksCacheTTL {
		return v.jwks, nil
	}

	jwksURL, err := v.discoverJWKS(ctx)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create JWKS request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	var jwks jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("decode JWKS: %w", err)
	}

	v.jwks = &jwks
	v.fetched = time.Now()
	v.jwksURL = jwksURL
	return &jwks, nil
}

func (v *GitHubOIDCValidator) discoverJWKS(ctx context.Context) (string, error) {
	if v.jwksURL != "" {
		return v.jwksURL, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.discoveryURL, nil)
	if err != nil {
		return "", fmt.Errorf("create discovery request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch discovery doc: %w", err)
	}
	defer resp.Body.Close()

	var doc struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return "", fmt.Errorf("decode discovery doc: %w", err)
	}
	if doc.JWKSURI == "" {
		return "", fmt.Errorf("empty jwks_uri in discovery doc")
	}
	return doc.JWKSURI, nil
}
