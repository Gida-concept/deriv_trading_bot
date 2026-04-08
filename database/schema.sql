-- =============================================================================
-- BINANCE FUTURES TRADING BOT - Complete PostgreSQL Schema v3.0
-- Database: trading_db
-- SECURITY: Proper Argon2 hashing, encrypted API key storage
-- VERSION: 3.0 (Binance Futures)
-- =============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- -----------------------------------------------------------------------------
-- TABLE: admin_accounts
-- ===========================================================================
CREATE TABLE IF NOT EXISTS admin_accounts (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'disabled', 'deleted')),
    is_active BOOLEAN DEFAULT TRUE,
    last_login TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_admin_email ON admin_accounts(email);
CREATE INDEX IF NOT EXISTS idx_admin_is_active ON admin_accounts(is_active);

-- -----------------------------------------------------------------------------
-- TABLE: users
-- ===========================================================================
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    email_verified BOOLEAN DEFAULT FALSE,
    verification_token VARCHAR(255),
    verification_token_hash VARCHAR(255),
    reset_token VARCHAR(255),
    reset_token_expiry TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP,
    last_login TIMESTAMP,
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'disabled', 'deleted', 'pending')),
    role VARCHAR(20) DEFAULT 'user' CHECK (role IN ('user', 'admin'))
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
CREATE INDEX IF NOT EXISTS idx_users_email_verified ON users(email_verified);

-- -----------------------------------------------------------------------------
-- TABLE: user_api_keys (Binance API Key + Secret)
-- ===========================================================================
CREATE TABLE IF NOT EXISTS user_api_keys (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    api_key_encrypted TEXT NOT NULL,
    api_secret_encrypted TEXT NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    deleted_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP,
    UNIQUE(user_id)
);

CREATE INDEX IF NOT EXISTS idx_user_api_keys_user_id ON user_api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_user_api_keys_active ON user_api_keys(is_active);
CREATE INDEX IF NOT EXISTS idx_user_api_keys_deleted_at ON user_api_keys(deleted_at);

-- -----------------------------------------------------------------------------
-- TABLE: bot_sessions
-- ===========================================================================
CREATE TABLE IF NOT EXISTS bot_sessions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    bot_state VARCHAR(50) DEFAULT 'inactive' CHECK (bot_state IN ('active', 'stopped', 'error', 'paused', 'inactive')),
    timeframe VARCHAR(20) NOT NULL,
    strategy_type VARCHAR(100),
    demo_live VARCHAR(20) DEFAULT 'demo' CHECK (demo_live IN ('demo', 'live')),
    risk_percentage DECIMAL(5,2),
    current_stake DECIMAL(10,2),
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    stopped_at TIMESTAMP,
    error_message TEXT,
    UNIQUE(user_id, timeframe)
);

CREATE INDEX IF NOT EXISTS idx_bot_sessions_user_id ON bot_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_bot_sessions_status ON bot_sessions(bot_state);
CREATE INDEX IF NOT EXISTS idx_bot_sessions_timeframe ON bot_sessions(timeframe);

-- -----------------------------------------------------------------------------
-- TABLE: timeframe_locks
-- ===========================================================================
CREATE TABLE IF NOT EXISTS timeframe_locks (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    timeframe VARCHAR(20) NOT NULL,
    last_trade_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    trade_count INTEGER DEFAULT 0,
    lock_until TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, timeframe)
);

CREATE INDEX IF NOT EXISTS idx_timeframe_locks_user_timeframe ON timeframe_locks(user_id, timeframe);
CREATE INDEX IF NOT EXISTS idx_timeframe_locks_user_id ON timeframe_locks(user_id);

-- -----------------------------------------------------------------------------
-- TABLE: trades (Binance Futures)
-- ===========================================================================
CREATE TABLE IF NOT EXISTS trades (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    bot_session_id INTEGER REFERENCES bot_sessions(id) ON DELETE SET NULL,
    contract_type VARCHAR(50),
    transaction_ref VARCHAR(255),
    symbol VARCHAR(50),
    entry_price DECIMAL(20, 8),
    exit_price DECIMAL(20, 8),
    stake_amount DECIMAL(10,2),
    leverage INTEGER DEFAULT 5,
    stop_loss DECIMAL(20, 8),
    take_profit DECIMAL(20, 8),
    profit_loss DECIMAL(10,2),
    duration_seconds INTEGER,
    timeframe VARCHAR(20),
    decision_source VARCHAR(50),
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('open', 'won', 'lost', 'void', 'pending')),
    decision_details JSONB,
    opened_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    closed_at TIMESTAMP,
    synced_to_platform BOOLEAN DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_trades_user_id ON trades(user_id);
CREATE INDEX IF NOT EXISTS idx_trades_timeframe ON trades(timeframe);
CREATE INDEX IF NOT EXISTS idx_trades_status ON trades(status);
CREATE INDEX IF NOT EXISTS idx_trades_opened_at ON trades(opened_at);
CREATE INDEX IF NOT EXISTS idx_trades_profit_loss ON trades(profit_loss);
CREATE INDEX IF NOT EXISTS idx_trades_symbol ON trades(symbol);

-- -----------------------------------------------------------------------------
-- TABLE: system_settings
-- ===========================================================================
CREATE TABLE IF NOT EXISTS system_settings (
    id SERIAL PRIMARY KEY,
    setting_key VARCHAR(100) UNIQUE NOT NULL,
    setting_value TEXT NOT NULL,
    setting_type VARCHAR(20) DEFAULT 'string' CHECK (setting_type IN ('string', 'int', 'decimal', 'boolean', 'json')),
    description TEXT,
    is_system_default BOOLEAN DEFAULT FALSE,
    updated_by INTEGER REFERENCES admin_accounts(id) ON DELETE SET NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- System-wide settings
INSERT INTO system_settings (setting_key, setting_value, setting_type, description, is_system_default) VALUES
('default_risk_percentage', '1.0', 'decimal', 'Default percentage of balance to risk per trade', TRUE),
('max_stake_per_trade', '100.00', 'decimal', 'Maximum allowed stake amount for any single trade', TRUE),
('min_account_balance', '10.00', 'decimal', 'Minimum account balance required to start trading', TRUE),
('default_leverage', '5', 'int', 'Default leverage for futures positions', TRUE),
('take_profit_percent', '10.0', 'decimal', 'Default take profit percentage', TRUE),
('stop_loss_percent', '3.0', 'decimal', 'Default stop loss percentage', TRUE),
('monitored_pairs', '["BTCUSDT","ETHUSDT","BNBUSDT","SOLUSDT","XRPUSDT","DOGEUSDT"]', 'json', 'Default trading pairs to monitor', TRUE),
('enabled_timeframes', '["1m","3m","5m","15m","30m","1h","4h"]', 'json', 'Array of enabled timeframes', TRUE),
('max_concurrent_positions', '3', 'int', 'Maximum number of open positions at once', TRUE),
('server_version', '3.0.0', 'string', 'Current system version number', TRUE)
ON CONFLICT (setting_key) DO NOTHING;

CREATE INDEX IF NOT EXISTS idx_system_settings_key ON system_settings(setting_key);

-- -----------------------------------------------------------------------------
-- TABLE: auth_tokens
-- ===========================================================================
CREATE TABLE IF NOT EXISTS auth_tokens (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_type VARCHAR(20) NOT NULL CHECK (token_type IN ('email_verification', 'password_reset')),
    token_hash VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    is_used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ip_address VARCHAR(45),
    user_agent TEXT
);

CREATE INDEX IF NOT EXISTS idx_auth_tokens_token_hash ON auth_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_auth_tokens_user_id ON auth_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_auth_tokens_expires ON auth_tokens(expires_at);

-- -----------------------------------------------------------------------------
-- TABLE: audit_log
-- ===========================================================================
CREATE TABLE IF NOT EXISTS audit_log (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    admin_id INTEGER REFERENCES admin_accounts(id) ON DELETE SET NULL,
    event_type VARCHAR(100) NOT NULL,
    details JSONB,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_admin_id ON audit_log(admin_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_log_event_type ON audit_log(event_type);

-- -----------------------------------------------------------------------------
-- TABLE: rate_limits
-- ===========================================================================
CREATE TABLE IF NOT EXISTS rate_limits (
    id SERIAL PRIMARY KEY,
    identifier VARCHAR(100) NOT NULL,
    endpoint VARCHAR(255) NOT NULL,
    limit_count INTEGER DEFAULT 100,
    window_seconds INTEGER DEFAULT 60,
    current_count INTEGER DEFAULT 0,
    window_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(identifier, endpoint, window_start)
);

CREATE INDEX IF NOT EXISTS idx_rate_limits_identifier ON rate_limits(identifier);
CREATE INDEX IF NOT EXISTS idx_rate_limits_window ON rate_limits(window_start);
CREATE INDEX IF NOT EXISTS idx_rate_limits_endpoint ON rate_limits(endpoint);

-- -----------------------------------------------------------------------------
-- TABLE: signals (Shared AI signals for all users)
-- ===========================================================================
CREATE TABLE IF NOT EXISTS signals (
    id SERIAL PRIMARY KEY,
    symbol VARCHAR(50) NOT NULL,
    signal VARCHAR(20) NOT NULL CHECK (signal IN ('LONG', 'SHORT', 'NEUTRAL')),
    confidence INTEGER NOT NULL,
    entry_price DECIMAL(20, 8),
    stop_loss DECIMAL(20, 8),
    take_profit DECIMAL(20, 8),
    timeframe VARCHAR(20) NOT NULL,
    reasoning TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP DEFAULT (CURRENT_TIMESTAMP + INTERVAL '1 hour')
);

CREATE INDEX IF NOT EXISTS idx_signals_symbol ON signals(symbol);
CREATE INDEX IF NOT EXISTS idx_signals_created_at ON signals(created_at);
CREATE INDEX IF NOT EXISTS idx_signals_signal ON signals(signal);

-- -----------------------------------------------------------------------------
-- TABLE: user_settings
-- ===========================================================================
CREATE TABLE IF NOT EXISTS user_settings (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE UNIQUE,
    notification_enabled BOOLEAN DEFAULT TRUE,
    email_notifications BOOLEAN DEFAULT TRUE,
    push_notifications BOOLEAN DEFAULT FALSE,
    two_factor_enabled BOOLEAN DEFAULT FALSE,
    timezone VARCHAR(50) DEFAULT 'UTC',
    currency_preference VARCHAR(3) DEFAULT 'USD',
    dark_mode BOOLEAN DEFAULT TRUE,
    show_pnl_in_chart BOOLEAN DEFAULT TRUE,
    auto_backup_trades BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_user_settings_user_id ON user_settings(user_id);

-- -----------------------------------------------------------------------------
-- TRIGGERS & FUNCTIONS
-- ===========================================================================

-- Function to automatically update timestamps
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply trigger to all tables with updated_at column
CREATE TRIGGER trigger_update_admin_accounts
    BEFORE UPDATE ON admin_accounts FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER trigger_update_users
    BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER trigger_update_system_settings
    BEFORE UPDATE ON system_settings FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER trigger_update_user_settings
    BEFORE UPDATE ON user_settings FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Create default user settings on registration
CREATE OR REPLACE FUNCTION create_default_user_settings()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO user_settings (user_id, notification_enabled, email_notifications, timezone, currency_preference)
    VALUES (NEW.id, TRUE, TRUE, 'UTC', 'USD');
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER trigger_create_user_settings
    AFTER INSERT ON users FOR EACH ROW EXECUTE FUNCTION create_default_user_settings();

-- -----------------------------------------------------------------------------
-- VERIFICATION & MESSAGES
-- ===========================================================================
DO $$
DECLARE
    table_count INT;
BEGIN
    SELECT COUNT(*) INTO table_count FROM information_schema.tables WHERE table_schema = 'public';

    RAISE NOTICE '✅ % tables created successfully!', table_count;

    IF table_count < 10 THEN
        RAISE EXCEPTION '❌ Fewer than expected tables created! Please check for errors.';
    END IF;

    RAISE NOTICE 'Database schema initialization complete!';
    RAISE NOTICE '';
    RAISE NOTICE '⚠️  IMPORTANT: Create admin account using Python script after setup';
    RAISE NOTICE '   Run: python scripts/create_admin.py';
END $$;

-- =============================================================================
-- ADMIN ACCOUNT CREATION HELP (NOT AUTO-SEATED FOR SECURITY)
-- =============================================================================
-- Admin accounts MUST be created via secure method (Python script) after
-- database setup to ensure proper Argon2 hashing with correct parameters.
-- DO NOT insert manually - password validation will fail!
-- =============================================================================
