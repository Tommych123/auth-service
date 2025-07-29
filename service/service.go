package service

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/Tommych123/auth-service/repository"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"time"
)

type Service struct {
	repository *repository.Repository
	jwtSecret  string
	webhookURL string
}

func NewService(repository *repository.Repository, jwtSecret string, webhookURL string) *Service {
	return &Service{
		repository: repository,
		jwtSecret:  jwtSecret,
		webhookURL: webhookURL,
	}
}

// GenerateTokens создает пару access и refresh токенов, сохраняет refresh токен с хэшем и привязывает tokenID (jti)
func (s *Service) GenerateTokens(ctx context.Context, userID, userAgent, ip string) (string, string, error) {
	tokenID := uuid.New().String()

	accessToken, err := s.generateAccessToken(userID, tokenID)
	if err != nil {
		return "", "", fmt.Errorf("error(GenerateTokens): generate access token: %w", err)
	}

	refreshToken, err := generateRandomBase64(32)
	if err != nil {
		return "", "", fmt.Errorf("error(GenerateTokens): generate refresh token: %w", err)
	}

	hashedToken, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		return "", "", fmt.Errorf("error(GenerateTokens): hash refresh token: %w", err)
	}

	expiresAt := time.Now().Add(7 * 24 * time.Hour)
	if err := s.repository.SaveRefreshToken(ctx, userID, string(hashedToken), userAgent, ip, expiresAt, tokenID); err != nil {
		return "", "", fmt.Errorf("error(GenerateTokens): save refresh token: %w", err)
	}

	return accessToken, refreshToken, nil
}

func (s *Service) generateAccessToken(userID, tokenID string) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"jti":     tokenID,
		"exp":     time.Now().Add(10 * time.Minute).Unix(),
		"iat":     time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	return token.SignedString([]byte(s.jwtSecret))
}

func generateRandomBase64(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("error(generateRandomBase64): rand read failed: %w", err)
	}
	return base64.StdEncoding.EncodeToString(b), nil
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

func (s *Service) RefreshTokens(ctx context.Context, oldRefreshToken, userID, userAgent, ip string) (string, string, error) {
	tokens, err := s.repository.GetRefreshTokensByUser(ctx, userID)
	if err != nil {
		return "", "", fmt.Errorf("error(RefreshTokens): get tokens failed: %w", err)
	}
	var matchedToken *repository.RefreshToken
	for _, token := range tokens {
		if bcrypt.CompareHashAndPassword([]byte(token.TokenHash), []byte(oldRefreshToken)) == nil {
			matchedToken = &token
			break
		}
	}
	if matchedToken == nil {
		return "", "", fmt.Errorf("error(RefreshTokens): refresh token not found or invalid")
	}
	if matchedToken.Used || time.Now().After(matchedToken.ExpiresAt) {
		go sendWebhookAlert(s.webhookURL, matchedToken.UserID, ip)
		return "", "", fmt.Errorf("error(RefreshTokens): token expired or already used")
	}
	if matchedToken.UserAgent != userAgent {
		_ = s.repository.DeleteTokensByUserID(ctx, matchedToken.UserID)
		return "", "", fmt.Errorf("error(RefreshTokens): user agent mismatch - logged out")
	}
	if matchedToken.IPAddress != ip {
		go sendWebhookAlert(s.webhookURL, matchedToken.UserID, ip)
	}
	if err := s.repository.MarkTokenUsed(ctx, matchedToken.TokenHash); err != nil {
		return "", "", fmt.Errorf("error(RefreshTokens): failed to mark token used: %w", err)
	}
	return s.GenerateTokens(ctx, matchedToken.UserID, userAgent, ip)
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
