CREATE TABLE IF NOT EXISTS clients (
    client_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    api_key_hash TEXT NOT NULL,
    scope TEXT NOT NULL,
    quota_per_minute INTEGER NOT NULL DEFAULT 60,
    permissions TEXT NOT NULL DEFAULT 'TOKENIZE,DETOKENIZE',
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS vault_records (
    token_id TEXT PRIMARY KEY,
    encrypted_dek TEXT NOT NULL,
    encrypted_payload TEXT NOT NULL,
    format_type TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_logs (
    log_id SERIAL PRIMARY KEY,
    client_id TEXT NOT NULL,
    action TEXT NOT NULL,
    status TEXT NOT NULL,
    timestamp TIMESTAMP NOT NULL DEFAULT NOW(),
    ip_address TEXT NOT NULL,
    details JSONB NOT NULL DEFAULT '{}'
    , duration_ms INTEGER NULL
);

CREATE TABLE IF NOT EXISTS admin_users (
    admin_id SERIAL PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'admin',
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

ALTER TABLE clients ADD COLUMN IF NOT EXISTS name TEXT;
UPDATE clients SET name = client_id WHERE name IS NULL;
ALTER TABLE clients ALTER COLUMN name SET NOT NULL;
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS duration_ms INTEGER NULL;

INSERT INTO clients (client_id, name, api_key_hash, scope, quota_per_minute, permissions, created_at, revoked)
VALUES ('demo-client', 'Demo client', '526611f5471704df082918c85aed580d2b8ee418a8f2c9e5375dfceb3d88cadd', 'TOKENIZE,DETOKENIZE', 1000, 'TOKENIZE,DETOKENIZE', NOW(), FALSE)
ON CONFLICT (client_id) DO NOTHING;
