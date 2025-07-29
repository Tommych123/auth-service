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
	TokenID   string
}

func (r *Repository) SaveRefreshToken(ctx context.Context, userID, tokenHash, userAgent, ip string, expiresAt time.Time, tokenID string) error {
	_, err := r.db.ExecContext(ctx,
		"INSERT INTO refresh_tokens (user_id, token_hash, user_agent, ip_address, created_at, expires_at, used, token_id) VALUES ($1, $2, $3, $4, NOW(), $5, false, $6)",
		userID, tokenHash, userAgent, ip, expiresAt, tokenID)
	if err != nil {
		return fmt.Errorf("error(SaveRefreshToken): save refresh token: %w", err)
	}
	return nil
}

func (r *Repository) GetRefreshTokensByUser(ctx context.Context, userID string) ([]RefreshToken, error) {
	rows, err := r.db.QueryContext(ctx,
		"SELECT id, user_id, token_hash, user_agent, ip_address, created_at, expires_at, used, token_id FROM refresh_tokens WHERE user_id = $1",
		userID)
	if err != nil {
		return nil, fmt.Errorf("error(GetRefreshTokensByUser): query refresh tokens: %w", err)
	}
	defer rows.Close()

	var tokens []RefreshToken
	for rows.Next() {
		var rt RefreshToken
		if err := rows.Scan(
			&rt.ID, &rt.UserID, &rt.TokenHash, &rt.UserAgent, &rt.IPAddress, &rt.CreatedAt, &rt.ExpiresAt, &rt.Used, &rt.TokenID,
		); err != nil {
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
