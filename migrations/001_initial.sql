-- ASM Platform — Initial PostgreSQL Schema (v3)
-- Drop everything for idempotent re-creation (dev only)

BEGIN;

-- ═══════════════════════ CORE TABLES ═══════════════════════

CREATE TABLE IF NOT EXISTS schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS admins (
    id            TEXT PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    email         TEXT NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login    TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS companies (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    domains      JSONB NOT NULL DEFAULT '[]',
    color        TEXT NOT NULL DEFAULT '#00c9a7',
    tags         JSONB NOT NULL DEFAULT '[]',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_companies_name ON companies (name);

CREATE TABLE IF NOT EXISTS schedules (
    company_id     TEXT PRIMARY KEY,
    profile        TEXT NOT NULL DEFAULT 'standard',
    interval_hours INTEGER NOT NULL DEFAULT 24,
    enabled        BOOLEAN NOT NULL DEFAULT true,
    next_run       TIMESTAMPTZ,
    last_run       TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS webhooks (
    id         TEXT PRIMARY KEY,
    type       TEXT NOT NULL DEFAULT 'generic',
    url        TEXT NOT NULL DEFAULT '',
    chat_id    TEXT NOT NULL DEFAULT '',
    events     JSONB NOT NULL DEFAULT '[]',
    config     JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS whitelist_entries (
    id            TEXT PRIMARY KEY,
    company_id    TEXT NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    host          TEXT NOT NULL DEFAULT '',
    title         TEXT NOT NULL DEFAULT '',
    reason        TEXT NOT NULL DEFAULT '',
    suppressed_by TEXT NOT NULL DEFAULT '',
    suppressed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_whitelist_company ON whitelist_entries (company_id);

CREATE TABLE IF NOT EXISTS audit_log (
    id      BIGSERIAL PRIMARY KEY,
    ts      TIMESTAMPTZ NOT NULL DEFAULT now(),
    "user"  TEXT NOT NULL DEFAULT 'system',
    action  TEXT NOT NULL,
    target  TEXT NOT NULL DEFAULT '',
    details TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_log_ts ON audit_log (ts DESC);

-- ═══════════════════════ ATTACK SURFACE DATA ═══════════════════════

CREATE TABLE IF NOT EXISTS asm_data_state (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    data       JSONB NOT NULL DEFAULT '{}',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS snapshots (
    company_id TEXT NOT NULL,
    slot       TEXT NOT NULL CHECK (slot IN ('current', 'previous')),
    ts         TIMESTAMPTZ NOT NULL DEFAULT now(),
    data       JSONB NOT NULL,
    PRIMARY KEY (company_id, slot)
);

-- ═══════════════════════ ASSET TIMELINE ═══════════════════════

CREATE TABLE IF NOT EXISTS host_timeline (
    id           BIGSERIAL PRIMARY KEY,
    company_id   TEXT NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    host         TEXT NOT NULL,
    ip           TEXT NOT NULL DEFAULT '',
    ports        JSONB NOT NULL DEFAULT '[]',
    status_code  INTEGER,
    title        TEXT NOT NULL DEFAULT '',
    server       TEXT NOT NULL DEFAULT '',
    technologies JSONB NOT NULL DEFAULT '[]',
    waf          TEXT NOT NULL DEFAULT '',
    cdn          BOOLEAN NOT NULL DEFAULT false,
    source       TEXT NOT NULL DEFAULT '',
    scan_ts      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (company_id, host, scan_ts)
);
CREATE INDEX IF NOT EXISTS idx_host_timeline_cid ON host_timeline (company_id);
CREATE INDEX IF NOT EXISTS idx_host_timeline_host ON host_timeline (company_id, host, scan_ts DESC);

CREATE TABLE IF NOT EXISTS subdomain_history (
    id          BIGSERIAL PRIMARY KEY,
    company_id  TEXT NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    subdomain   TEXT NOT NULL,
    event       TEXT NOT NULL CHECK (event IN ('discovered', 'resolved', 'removed', 'changed')),
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
    is_alive    BOOLEAN NOT NULL DEFAULT false,
    source      TEXT NOT NULL DEFAULT '',
    details     JSONB NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_subhistory_cid ON subdomain_history (company_id);
CREATE INDEX IF NOT EXISTS idx_subhistory_sub ON subdomain_history (subdomain);

-- ═══════════════════════ ALERTS ═══════════════════════

CREATE TABLE IF NOT EXISTS alert_rules (
    id          TEXT PRIMARY KEY,
    company_id  TEXT NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    name        TEXT NOT NULL DEFAULT '',
    rule_type   TEXT NOT NULL CHECK (rule_type IN ('new_host', 'new_port', 'new_tech', 'cert_expiring', 'status_change', 'cve_critical', 'waf_change')),
    channels    JSONB NOT NULL DEFAULT '[]',
    enabled     BOOLEAN NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_alert_rules_cid ON alert_rules (company_id);

CREATE TABLE IF NOT EXISTS alerts (
    id           BIGSERIAL PRIMARY KEY,
    company_id   TEXT NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    rule_type    TEXT NOT NULL,
    title        TEXT NOT NULL,
    description  TEXT NOT NULL DEFAULT '',
    severity     TEXT NOT NULL DEFAULT 'info' CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    data         JSONB NOT NULL DEFAULT '{}',
    acknowledged BOOLEAN NOT NULL DEFAULT false,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_alerts_cid ON alerts (company_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (severity);

-- ═══════════════════════ API KEYS ═══════════════════════

CREATE TABLE IF NOT EXISTS api_keys (
    id          TEXT PRIMARY KEY,
    company_id  TEXT REFERENCES companies(id) ON DELETE CASCADE,
    name        TEXT NOT NULL DEFAULT '',
    key_hash    TEXT NOT NULL UNIQUE,
    permissions JSONB NOT NULL DEFAULT '["read"]',
    expires_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used   TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_api_keys_cid ON api_keys (company_id);

-- Seed
INSERT INTO schema_meta (key, value) VALUES ('schema_version', '3')
ON CONFLICT (key) DO UPDATE SET value = '3';

COMMIT;
