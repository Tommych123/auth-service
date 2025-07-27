package db

import (
    "database/sql"
    _ "github.com/lib/pq"
    "fmt"
    "github.com/Tommych123/auth-service/internal/config"
    "log"
)


func NewPostgresDB(cfg *config.Config) *sql.DB {
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		cfg.DBHost, cfg.DBPort, cfg.DBUser, cfg.DBPassword, cfg.DBName)
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		log.Fatalf("error(NewPostgresDB):of connection to DB: %v", err)
	}
	if err := db.Ping(); err != nil {
		log.Fatalf("error(NewPostgresDB):of ping DB: %v", err)
	}
	return db
}
