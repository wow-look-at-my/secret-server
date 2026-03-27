package auth

import (
	"time"

	"github.com/go-jose/go-jose/v4"
)

// SetJWKSForTesting injects JWKS keys into a validator for testing purposes.
func SetJWKSForTesting(v *GitHubOIDCValidator, jwks *jose.JSONWebKeySet) {
	v.jwks = jwks
	v.fetched = time.Now()
	v.jwksURL = "test"
}
