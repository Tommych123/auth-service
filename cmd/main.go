// @title Auth Service API
// @version 1.0
// @description Auth microservice for token generation, refreshing, user identity and logout
// @BasePath /
// @schemes http

package main

import (
	"fmt"
	"github.com/Tommych123/auth-service/api/auth"
	_ "github.com/Tommych123/auth-service/internal/docs"
	"github.com/Tommych123/auth-service/pkg/db"
	"github.com/Tommych123/auth-service/service/config"
	"github.com/swaggo/http-swagger"
	"log"
	"net/http"
)

func enableCors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	cfg := config.LoadEnv()
	database := db.NewPostgresDB(cfg)
	repo := auth.NewRepository(database)
	service := auth.NewService(repo, cfg.JWTSecret, cfg.WebhookURL)
	handler := auth.NewHandler(service)
	mux := http.NewServeMux()
	mux.HandleFunc("/token", handler.Token)
	mux.HandleFunc("/refresh", handler.Refresh)
	mux.HandleFunc("/me", handler.Me)
	mux.HandleFunc("/logout", handler.Logout)
	mux.Handle("/swagger/", httpSwagger.WrapHandler)
	addr := fmt.Sprintf(":%s", cfg.Port)
	log.Println("Server started at http://localhost" + addr)
	log.Fatal(http.ListenAndServe(addr, enableCors(mux)))
}
