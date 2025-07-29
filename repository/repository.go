package repository

import (
	"context"
	"fmt"
	"github.com/jmoiron/sqlx"
	"time"
)

type Repository struct {
	db *sqlx.DB
}

func NewRepository(db *sqlx.DB) *Repository {
	return &Repository{db: db}
}

type RefreshToken struct {
	ID        int       `db:"id"`
	UserID    string    `db:"user_id"`
	TokenHash string    `db:"token_hash"`
	UserAgent string    `db:"user_agent"`
	IPAddress string    `db:"ip_address"`
	CreatedAt time.Time `db:"created_at"`
	ExpiresAt time.Time `db:"expires_at"`
	Used      bool      `db:"used"`
	TokenID   string    `db:"token_id"`
}

func (r *Repository) SaveRefreshToken(ctx context.Context, userID, tokenHash, userAgent, ip string, expiresAt time.Time, tokenID string) error {
	_, err := r.db.ExecContext(ctx, "INSERT INTO refresh_tokens (user_id, token_hash, user_agent, ip_address, created_at, expires_at, used, token_id) VALUES ($1, $2, $3, $4, NOW(), $5, false, $6)",
		userID, tokenHash, userAgent, ip, expiresAt, tokenID)
	if err != nil {
		return fmt.Errorf("error(SaveRefreshToken): save refresh token: %w", err)
	}
	return nil
}

func (r *Repository) GetRefreshTokensByUser(ctx context.Context, userID string) ([]RefreshToken, error) {
	rows, err := r.db.QueryxContext(ctx, "SELECT id, user_id, token_hash, user_agent, ip_address, created_at, expires_at, used, token_id FROM refresh_tokens WHERE user_id = $1",
		userID)
	if err != nil {
		return nil, fmt.Errorf("error(GetRefreshTokensByUser): query refresh tokens: %w", err)
	}
	defer rows.Close()
	var tokens []RefreshToken
	for rows.Next() {
		var rt RefreshToken
		if err := rows.StructScan(&rt); err != nil {
			return nil, fmt.Errorf("error(GetRefreshTokensByUser): scan refresh token: %w", err)
		}
		tokens = append(tokens, rt)
	}
	return tokens, nil
}

func (r *Repository) MarkTokenUsed(ctx context.Context, tokenHash string) error {
	_, err := r.db.ExecContext(ctx, "UPDATE refresh_tokens SET used = true WHERE token_hash = $1", tokenHash)
	if err != nil {
		return fmt.Errorf("error(MarkTokenUsed): mark token as used: %w", err)
	}
	return nil
}

func (r *Repository) DeleteTokensByUserID(ctx context.Context, userID string) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM refresh_tokens WHERE user_id = $1", userID)
	if err != nil {
		return fmt.Errorf("error(DeleteTokensByUserID): delete tokens by user ID: %w", err)
	}
	return nil
}
