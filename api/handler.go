package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"github.com/Tommych123/auth-service/service"
)

// swagger:model TokenResponse
type TokenResponse struct {
	AccessToken  string `json:"access_token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
	RefreshToken string `json:"refresh_token" example:"d1a4f8a2c7e9f06..."`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" example:"d1a4f8a2c7e9f06..."`
	UserID       string `json:"user_id" example:"123e4567-e89b-12d3-a456-426614174000"`
}

type MeResponse struct {
	UserID string `json:"user_id" example:"123e4567-e89b-12d3-a456-426614174000"`
}

type Handler struct {
	service *service.Service
}

func NewHandler(service *service.Service) *Handler {
	return &Handler{service: service}
}

// Token godoc
// @Summary      Generate access and refresh tokens
// @Description  Generate tokens for a user by user_id query parameter
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        user_id  query  string  true  "User ID"  example("123e4567-e89b-12d3-a456-426614174000")
// @Success      200  {object}  auth.TokenResponse
// @Failure      400  {string}  string "error(Token):missing user_id"
// @Failure      500  {string}  string "error(Token):generate tokens"
// @Router       /token [post]
func (h *Handler) Token(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		http.Error(w, "error(Token):missing user_id", http.StatusBadRequest)
		return
	}
	userAgent := r.UserAgent()
	ip := strings.Split(r.RemoteAddr, ":")[0]

	access, refresh, err := h.service.GenerateTokens(r.Context(), userID, userAgent, ip)
	if err != nil {
		http.Error(w, fmt.Sprintf("error(Token):generate tokens %v", err), http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(w).Encode(TokenResponse{
		AccessToken:  access,
		RefreshToken: refresh,
	}); err != nil {
		log.Printf("error(Token):failed to write response %v", err)
	}
}

// Refresh godoc
// @Summary      Refresh access and refresh tokens
// @Description  Refresh tokens by sending refresh_token and user_id in JSON body
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request body RefreshRequest true "Refresh token request"
// @Success      200  {object}  TokenResponse
// @Failure      400  {string}  string "error(Refresh):invalid request"
// @Failure      401  {string}  string "error(Refresh):unauthorized"
// @Router       /refresh [post]
func (h *Handler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "error(Refresh):invalid request", http.StatusBadRequest)
		return
	}
	userAgent := r.UserAgent()
	ip := strings.Split(r.RemoteAddr, ":")[0]

	access, refresh, err := h.service.RefreshTokens(r.Context(), req.RefreshToken, req.UserID, userAgent, ip)
	if err != nil {
		http.Error(w, fmt.Sprintf("error(Refresh):refresh tokens %v", err), http.StatusUnauthorized)
		return
	}

	if err := json.NewEncoder(w).Encode(TokenResponse{
		AccessToken:  access,
		RefreshToken: refresh,
	}); err != nil {
		log.Printf("error(Refresh):failed to write response %v", err)
	}
}

// Me godoc
// @Summary      Get current user ID
// @Description  Get user_id from Authorization Bearer token
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        Authorization  header  string  true  "Bearer access_token"  example("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
// @Success      200  {object}  MeResponse
// @Failure      401  {string}  string "error(Me):missing or invalid Authorization header or invalid token"
// @Router       /me [get]
func (h *Handler) Me(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "error(Me):missing or invalid Authorization header", http.StatusUnauthorized)
		return
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")
	userID, err := h.service.GetUserIDFromToken(token)
	if err != nil {
		http.Error(w, "error(Me):invalid token", http.StatusUnauthorized)
		return
	}
	if err := json.NewEncoder(w).Encode(MeResponse{UserID: userID}); err != nil {
		log.Printf("error(Me):failed to write response %v", err)
	}
}

// Logout godoc
// @Summary      Logout user
// @Description  Deauthorize user by access token
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        Authorization  header  string  true  "Bearer access_token"  example("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
// @Success      200  "OK"
// @Failure      401  {string}  string "error(Logout):missing or invalid Authorization header or invalid token"
// @Failure      500  {string}  string "error(Logout):failed to logout"
// @Router       /logout [post]
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "error(Logout):missing or invalid Authorization header", http.StatusUnauthorized)
		return
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")
	userID, err := h.service.GetUserIDFromToken(token)
	if err != nil {
		http.Error(w, "error(Logout):invalid token", http.StatusUnauthorized)
		return
	}
	if err := h.service.Deauthorize(r.Context(), userID); err != nil {
		http.Error(w, "error(Logout):failed to logout", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}
