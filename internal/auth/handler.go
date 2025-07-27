package auth

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
)

type Handler struct {
	service *Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

// POST /token?user_id=...
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
		http.Error(w, fmt.Sprintf("error(Token):generate tokkens %v", err), http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(w).Encode(map[string]string{
		"access_token":  access,
		"refresh_token": refresh,
	}); err != nil {
		log.Printf("error(Token):failed to write response %v", err)
	}
}

// POST /refresh
func (h *Handler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
		UserID       string `json:"user_id"`
	}
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

	if err := json.NewEncoder(w).Encode(map[string]string{
		"access_token":  access,
		"refresh_token": refresh,
	}); err != nil {
		log.Printf("error(Refresh):failed to write response %v", err)
	}
}

// GET /me
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
	if err := json.NewEncoder(w).Encode(map[string]string{"user_id": userID}); err != nil {
		log.Printf("error(Me):failed to write response  %v", err)
	}

}

// POST /logout
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
