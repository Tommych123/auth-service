CREATE TABLE IF NOT EXISTS refresh_tokens (
    id SERIAL PRIMARY KEY,
    user_id UUID NOT NULL,
    token_hash TEXT NOT NULL,
    user_agent TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    used BOOLEAN DEFAULT FALSE
);
