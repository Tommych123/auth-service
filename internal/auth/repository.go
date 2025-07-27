package auth

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

type Repository struct {
	db *sql.DB
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{db: db}
}

type RefreshToken struct {
	ID        int
	UserID    string
	TokenHash string
	UserAgent string
	IPAddress string
	CreatedAt time.Time
	ExpiresAt time.Time
	Used      bool
}

func (r *Repository) SaveRefreshToken(ctx context.Context, userID string, tokenHash string, userAgent string, IP string, expiresAt time.Time) error {
	_, err := r.db.ExecContext(ctx, "INSERT INTO refresh_tokens (user_id, token_hash, user_agent, ip_address, expires_at) VALUES ($1, $2, $3, $4, $5)",
		userID, tokenHash, userAgent, IP, expiresAt)
	return err
}

func (r *Repository) GetRefreshTokensByUser(ctx context.Context, userID string) ([]RefreshToken, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT id, user_id, token_hash, user_agent, ip_address, created_at, expires_at, used FROM refresh_tokens WHERE user_id = $1", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tokens []RefreshToken
	for rows.Next() {
		var rt RefreshToken
		err := rows.Scan(&rt.ID, &rt.UserID, &rt.TokenHash, &rt.UserAgent, &rt.IPAddress, &rt.CreatedAt, &rt.ExpiresAt, &rt.Used)
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, rt)
	}
	return tokens, nil
}

func (r *Repository) MarkTokenUsed(ctx context.Context, tokenHash string) error {
	_, err := r.db.ExecContext(ctx, "UPDATE refresh_tokens SET used = true WHERE token_hash = $1", tokenHash)
	if err != nil {
		return fmt.Errorf("error(MarkTokenUsed):mark token as used: %w", err)
	}
	return nil
}

func (r *Repository) DeleteTokensByUserID(ctx context.Context, userID string) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM refresh_tokens WHERE user_id = $1", userID)
	if err != nil {
		return fmt.Errorf("error(DeleteTokensByUserID):delete tokens by user ID: %w", err)
	}
	return nil
}
