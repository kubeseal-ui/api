package oidc

import (
	"encoding/json"
	"fmt"
)

// configuredClaims contains normalized identity claims extracted from an ID token.
type configuredClaims struct {
	Subject  string
	Email    string
	Username string
	Groups   []string
}

func extractConfiguredClaims(claims map[string]any, groupsClaim, usernameClaim string) (configuredClaims, error) {
	result := configuredClaims{
		Subject:  stringClaim(claims["sub"]),
		Email:    stringClaim(claims["email"]),
		Username: stringClaim(claims[usernameClaim]),
	}
	if result.Subject == "" || result.Email == "" || result.Username == "" {
		return configuredClaims{}, fmt.Errorf("missing required identity claim")
	}
	if raw, ok := claims[groupsClaim]; ok {
		bytes, err := json.Marshal(raw)
		if err != nil || json.Unmarshal(bytes, &result.Groups) != nil {
			return configuredClaims{}, fmt.Errorf("invalid groups claim")
		}
	}
	return result, nil
}

func stringClaim(value any) string {
	valueString, _ := value.(string)
	return valueString
}
