package config

import (
	"log"
	"os"
)

type Config struct {
	DBHost     string
	DBPort     string
	DBUser     string
	DBPassword string
	DBName     string
	JWTSecret  string
	Port       string
	WebhookURL string
}

func LoadEnv() *Config {
	return &Config{
		DBHost:     getEnvRequired("DB_HOST"),
		DBPort:     getEnvRequired("DB_PORT"),
		DBUser:     getEnvRequired("DB_USER"),
		DBPassword: getEnvRequired("DB_PASSWORD"),
		DBName:     getEnvRequired("DB_NAME"),
		JWTSecret:  getEnvRequired("JWT_SECRET"),
		Port:       getEnvRequired("PORT"),
		WebhookURL: getEnvRequired("WEBHOOK_URL"),
	}
}

func getEnvRequired(key string) string {
	val, ok := os.LookupEnv(key)
	if !ok || val == "" {
		log.Fatalf("error(getEnvRequired):of validate: %v", key)
	}
	return val
}
