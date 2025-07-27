package main

import (
	"fmt"
	"log"
	"net/http"
	"github.com/Tommych123/auth-service/internal/auth"
	"github.com/Tommych123/auth-service/internal/config"
	"github.com/Tommych123/auth-service/internal/db"
)

func main() {
	cfg := config.LoadEnv()

	database := db.NewPostgresDB(cfg)

	repo := auth.NewRepository(database)
	service := auth.NewService(repo, cfg.JWTSecret, cfg.WebhookURL)
	handler := auth.NewHandler(service)

	http.HandleFunc("/token", handler.Token)       // POST /token?user_id=...
	http.HandleFunc("/refresh", handler.Refresh)   // POST { user_id, refresh_token }
	http.HandleFunc("/me", handler.Me)             // GET with token
	http.HandleFunc("/logout", handler.Logout)     // POST with token

	addr := fmt.Sprintf(":%s", cfg.Port)
	log.Println("Server started at http://localhost" + addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}
