package utils

import (
	"auth-api/config"
	"errors"

	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	UserID string `json:"user_id"`
	jwt.RegisteredClaims
}

// ParseToken validates a JWT and returns its claims.
//
// The signing method is pinned: without it, a token presenting a different
// algorithm is handed to the HMAC verifier, which is the classic algorithm
// confusion foothold. The token itself is never logged — it is a bearer
// credential, and journald is readable by every operator.
func ParseToken(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(
		tokenStr,
		&Claims{},
		func(token *jwt.Token) (interface{}, error) {
			return config.JWTSecret, nil
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
	)
	if err != nil || !token.Valid {
		return nil, errors.New("invalid token")
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		return nil, errors.New("could not parse claims")
	}
	return claims, nil
}
