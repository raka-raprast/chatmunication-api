package utils

import (
	"auth-api/config"
	"errors"
	"log"

	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	UserID string `json:"user_id"`
	jwt.RegisteredClaims
}

func ParseToken(tokenStr string) (*Claims, error) {
	log.Printf("🔐 Parsing token: %s", tokenStr)
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return config.JWTSecret, nil // ✅ use the actual secret
	})

	if err != nil || !token.Valid {
		log.Printf("❌ Error parsing JWT: %v", err)
		return nil, errors.New("invalid token")
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		return nil, errors.New("could not parse claims")
	}

	return claims, nil
}
