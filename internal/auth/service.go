package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"time"
)

type Service struct {
	repository *Repository
	jwtSecret  string
	webhookURL string
}

func NewService(repository *Repository, jwtSecret string, webhookURL string) *Service {
	return &Service{
		repository: repository,
		jwtSecret:  jwtSecret,
		webhookURL: webhookURL,
	}
}

func (s *Service) GenerateTokens(ctx context.Context, userID, userAgent, ip string) (string, string, error) {
	accessToken, err := s.generateAccessToken(userID)
	if err != nil {
		return "", "", fmt.Errorf("error(GenerateTokens):generate access token: %w", err)
	}

	refreshToken, err := generateRandomBase64(32)
	if err != nil {
		return "", "", fmt.Errorf("error(GenerateTokens):generate refresh token: %w", err)
	}

	hashedToken, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		return "", "", fmt.Errorf("error(GenerateTokens):hash refresh token: %w", err)
	}

	expiresAt := time.Now().Add(7 * 24 * time.Hour)
	if err := s.repository.SaveRefreshToken(ctx, userID, string(hashedToken), userAgent, ip, expiresAt); err != nil {
		return "", "", fmt.Errorf("error(GenerateTokens):save refresh token: %w", err)
	}

	return accessToken, refreshToken, nil
}

func (s *Service) GetUserIDFromToken(tokenStr string) (string, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("error(GetUserIDFromToken): unexpected signing method")
		}
		return []byte(s.jwtSecret), nil
	})
	if err != nil || !token.Valid {
		return "", fmt.Errorf("error(GetUserIDFromToken): invalid token")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("error(GetUserIDFromToken): invalid token claims")
	}
	userID, ok := claims["user_id"].(string)
	if !ok {
		return "", fmt.Errorf("error(GetUserIDFromToken): user_id not found in token")
	}
	return userID, nil
}

func (s *Service) generateAccessToken(userID string) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(10 * time.Minute).Unix(),
		"iat":     time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	return token.SignedString([]byte(s.jwtSecret))
}

func generateRandomBase64(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("error(generateRandomBase64):rand is fail: %w", err)
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func (s *Service) RefreshTokens(ctx context.Context, oldRefreshToken, userID, userAgent, ip string) (string, string, error) {
	tokens, err := s.repository.GetRefreshTokensByUser(ctx, userID)
	if err != nil {
		return "", "", fmt.Errorf("error(RefreshTokens):rand is fail: %w", err)
	}
	fmt.Printf("Tokens in DB for user %s:\n", userID)
	for _, token := range tokens {
		fmt.Printf("- TokenHash: %s, Used: %v, ExpiresAt: %v, UserAgent: %s, IP: %s\n", token.TokenHash, token.Used, token.ExpiresAt, token.UserAgent, token.IPAddress)
	}

	var needToken *RefreshToken
	for _, token := range tokens {
		if bcrypt.CompareHashAndPassword([]byte(token.TokenHash), []byte(oldRefreshToken)) == nil {
			needToken = &token
			break
		}
	}
	if needToken == nil {
		return "", "", fmt.Errorf("error(RefreshTokens): refresh token not found or invalid")
	}

	if needToken.Used || time.Now().After(needToken.ExpiresAt) {
		go sendWebhookAlert(s.webhookURL, needToken.UserID, ip)
		return "", "", fmt.Errorf("error(RefreshTokens): expired or used token")
	}
	if needToken.UserAgent != userAgent {
		_ = s.repository.DeleteTokensByUserID(ctx, needToken.UserID)
		return "", "", fmt.Errorf("error(RefreshTokens): user agent mismatch")
	}
	if needToken.IPAddress != ip {
		go sendWebhookAlert(s.webhookURL, needToken.UserID, ip)
	}
	_ = s.repository.MarkTokenUsed(ctx, needToken.TokenHash)
	return s.GenerateTokens(ctx, needToken.UserID, userAgent, ip)
}

func (s *Service) Deauthorize(ctx context.Context, userID string) error {
	return s.repository.DeleteTokensByUserID(ctx, userID)
}

func sendWebhookAlert(webhookURL, userID, ip string) {
	payload := map[string]string{
		"user_id": userID,
		"ip":      ip,
	}
	jsonData, _ := json.Marshal(payload)
	http.Post(webhookURL, "application/json", bytes.NewBuffer(jsonData))
}
