-- =============================================
-- GROUP OCCASION REMINDER DATABASE SCHEMA
-- PostgreSQL 14+
-- UTC-FIRST APPROACH: All timestamps stored and returned in UTC
-- =============================================

-- Set session timezone to UTC for all connections
SET TIME ZONE 'UTC';

-- Drop existing types if they exist
DROP TYPE IF EXISTS auth_provider_type CASCADE;
DROP TYPE IF EXISTS occasion_role_type CASCADE;
DROP TYPE IF EXISTS occasion_recurrence_type CASCADE;
DROP TYPE IF EXISTS reminder_channel_type CASCADE;
DROP TYPE IF EXISTS reminder_offset_type CASCADE;
DROP TYPE IF EXISTS notification_status_type CASCADE;
DROP TYPE IF EXISTS member_status_type CASCADE;

-- =============================================
-- ENUM TYPES
-- =============================================

-- Authentication provider types
CREATE TYPE auth_provider_type AS ENUM (
    'password',
    'google',
    'phone_otp'
);

-- Occasion member roles
CREATE TYPE occasion_role_type AS ENUM (
    'creator',
    'member'
);

-- Recurrence patterns
CREATE TYPE occasion_recurrence_type AS ENUM (
    'none',
    'daily',
    'weekly',
    'monthly',
    'yearly'
);

-- Notification channels
CREATE TYPE reminder_channel_type AS ENUM (
    'in_app',
    'push',
    'email',
    'sms'
);

-- Reminder time offsets
CREATE TYPE reminder_offset_type AS ENUM (
    '5m',    -- 5 minutes
    '15m',   -- 15 minutes
    '30m',   -- 30 minutes
    '1h',    -- 1 hour
    '3h',    -- 3 hours
    '6h',    -- 6 hours
    '12h',   -- 12 hours
    '1d',    -- 1 day
    '3d',    -- 3 days
    '7d',    -- 1 week
    '14d',   -- 2 weeks
    '30d'    -- 1 month
);

-- Notification delivery status
CREATE TYPE notification_status_type AS ENUM (
    'pending',
    'sent',
    'failed',
    'cancelled'
);

-- Member invitation status
CREATE TYPE member_status_type AS ENUM (
    'pending',
    'active',
    'inactive',
    'blocked'
);

-- =============================================
-- USERS & AUTHENTICATION
-- =============================================

-- Users table (core user entity)
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(50) UNIQUE,
    email VARCHAR(255) UNIQUE,
    phone VARCHAR(20) UNIQUE,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    display_name VARCHAR(150),
    avatar_url VARCHAR(500),
    is_email_verified BOOLEAN DEFAULT FALSE,
    is_phone_verified BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    last_login_at TIMESTAMPTZ,

    -- Ensure at least one identifier exists
    CONSTRAINT chk_has_identifier CHECK (
        username IS NOT NULL OR
        email IS NOT NULL OR
        phone IS NOT NULL
    )
);

-- Authentication credentials
CREATE TABLE user_authentications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    auth_provider auth_provider_type NOT NULL,
    provider_user_id VARCHAR(255), -- External ID for OAuth providers
    password_hash VARCHAR(255), -- For password auth only
    otp_secret VARCHAR(100), -- For phone OTP
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    -- One auth method per provider per user
    UNIQUE(user_id, auth_provider),
    -- External ID must be unique per provider
    UNIQUE(auth_provider, provider_user_id)
);

-- Session management
CREATE TABLE user_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    refresh_token VARCHAR(500) UNIQUE NOT NULL,
    access_token_jti VARCHAR(255) UNIQUE, -- JWT ID for access token tracking
    device_info JSONB, -- Store device/browser info
    ip_address INET,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    last_used_at TIMESTAMPTZ DEFAULT NOW(),
    is_revoked BOOLEAN DEFAULT FALSE
);

-- User preferences for notifications
CREATE TABLE user_preferences (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    enable_in_app BOOLEAN DEFAULT TRUE,
    enable_push BOOLEAN DEFAULT TRUE,
    enable_email BOOLEAN DEFAULT TRUE,
    enable_sms BOOLEAN DEFAULT FALSE,
    quiet_hours_start TIME,
    quiet_hours_end TIME,
    timezone VARCHAR(50) DEFAULT 'UTC',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- =============================================
-- OCCASIONS
-- =============================================

-- Main occasions table
CREATE TABLE occasions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title VARCHAR(255) NOT NULL,
    description TEXT,
    location VARCHAR(500),
    location_coordinates POINT, -- PostgreSQL geometric type for lat/long
    date_time TIMESTAMPTZ NOT NULL,
    end_date_time TIMESTAMPTZ,
    recurrence_type occasion_recurrence_type DEFAULT 'none',
    recurrence_end_date DATE,
    recurrence_interval INTEGER DEFAULT 1, -- Every N days/weeks/months
    recurrence_days_of_week INTEGER[], -- For weekly: 0=Sun, 6=Sat
    recurrence_day_of_month INTEGER, -- For monthly: 1-31
    created_by UUID NOT NULL REFERENCES users(id),
    banner_image_url VARCHAR(500),
    color_theme VARCHAR(7), -- Hex color code
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    -- Validate recurrence interval
    CONSTRAINT chk_recurrence_interval CHECK (recurrence_interval > 0)
);

-- Occasion members (many-to-many with roles)
CREATE TABLE occasion_members (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    occasion_id UUID NOT NULL REFERENCES occasions(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role occasion_role_type NOT NULL DEFAULT 'member',
    status member_status_type NOT NULL DEFAULT 'active',
    joined_at TIMESTAMPTZ DEFAULT NOW(),
    invited_by UUID REFERENCES users(id),
    last_viewed_at TIMESTAMPTZ,

    -- One membership per user per occasion
    UNIQUE(occasion_id, user_id)
);

-- Invitation codes for sharing
CREATE TABLE occasion_invitations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    occasion_id UUID NOT NULL REFERENCES occasions(id) ON DELETE CASCADE,
    invite_code VARCHAR(20) UNIQUE NOT NULL,
    qr_code_url VARCHAR(500),
    created_by UUID NOT NULL REFERENCES users(id),
    max_uses INTEGER, -- NULL = unlimited
    current_uses INTEGER DEFAULT 0,
    expires_at TIMESTAMPTZ,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),

    -- Ensure expiry is in the future when created
    CONSTRAINT chk_expires_future CHECK (expires_at IS NULL OR expires_at > NOW())
);

-- =============================================
-- REMINDERS & NOTIFICATIONS
-- =============================================

-- Reminder configurations per occasion
CREATE TABLE occasion_reminders (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    occasion_id UUID NOT NULL REFERENCES occasions(id) ON DELETE CASCADE,
    channel reminder_channel_type NOT NULL,
    remind_before reminder_offset_type NOT NULL,
    message_template TEXT, -- Custom message template
    is_active BOOLEAN DEFAULT TRUE,
    created_by UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    -- One reminder per channel per offset per occasion
    UNIQUE(occasion_id, channel, remind_before)
);

-- User-specific reminder preferences (override occasion defaults)
CREATE TABLE user_reminder_preferences (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    occasion_id UUID NOT NULL REFERENCES occasions(id) ON DELETE CASCADE,
    reminder_id UUID NOT NULL REFERENCES occasion_reminders(id) ON DELETE CASCADE,
    is_enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    -- One preference per user per reminder
    UNIQUE(user_id, reminder_id)
);

-- Scheduled notifications queue
CREATE TABLE notification_queue (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    occasion_id UUID NOT NULL REFERENCES occasions(id) ON DELETE CASCADE,
    reminder_id UUID NOT NULL REFERENCES occasion_reminders(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    channel reminder_channel_type NOT NULL,
    scheduled_for TIMESTAMPTZ NOT NULL,
    status notification_status_type DEFAULT 'pending',
    retry_count INTEGER DEFAULT 0,
    max_retries INTEGER DEFAULT 3,
    message_payload JSONB, -- Store rendered message content
    created_at TIMESTAMPTZ DEFAULT NOW(),
    processed_at TIMESTAMPTZ,

    -- Prevent duplicate notifications
    UNIQUE(occasion_id, reminder_id, user_id, scheduled_for)
);

-- Notification delivery log
CREATE TABLE notification_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    queue_id UUID REFERENCES notification_queue(id) ON DELETE SET NULL,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    occasion_id UUID NOT NULL REFERENCES occasions(id) ON DELETE CASCADE,
    channel reminder_channel_type NOT NULL,
    status notification_status_type NOT NULL,
    error_message TEXT,
    metadata JSONB, -- Store delivery-specific data (message ID, tracking info)
    sent_at TIMESTAMPTZ DEFAULT NOW()
);

-- =============================================
-- INDEXES FOR QUERY OPTIMIZATION
-- =============================================

-- User authentication lookups
CREATE INDEX idx_users_email_lower ON users(LOWER(email)) WHERE email IS NOT NULL;
CREATE INDEX idx_users_phone ON users(phone) WHERE phone IS NOT NULL;
CREATE INDEX idx_users_username_lower ON users(LOWER(username)) WHERE username IS NOT NULL;
CREATE INDEX idx_user_auth_provider ON user_authentications(user_id, auth_provider);
CREATE INDEX idx_user_sessions_token ON user_sessions(refresh_token) WHERE is_revoked = FALSE;
CREATE INDEX idx_user_sessions_expiry ON user_sessions(expires_at) WHERE is_revoked = FALSE;

-- Occasion queries
CREATE INDEX idx_occasions_creator ON occasions(created_by);
CREATE INDEX idx_occasions_datetime ON occasions(date_time) WHERE is_active = TRUE;
CREATE INDEX idx_occasions_recurrence ON occasions(recurrence_type) WHERE recurrence_type != 'none';
CREATE INDEX idx_occasion_members_user ON occasion_members(user_id, status) WHERE status = 'active';
CREATE INDEX idx_occasion_members_occasion ON occasion_members(occasion_id, status) WHERE status = 'active';
CREATE INDEX idx_invitations_code ON occasion_invitations(invite_code) WHERE is_active = TRUE;

-- Reminder and notification queries
CREATE INDEX idx_reminders_occasion ON occasion_reminders(occasion_id) WHERE is_active = TRUE;
CREATE INDEX idx_user_reminder_prefs ON user_reminder_preferences(user_id, occasion_id);
CREATE INDEX idx_notification_queue_scheduled ON notification_queue(scheduled_for, status) WHERE status = 'pending';
CREATE INDEX idx_notification_queue_user ON notification_queue(user_id, status);
CREATE INDEX idx_notification_log_user_date ON notification_log(user_id, sent_at);

-- =============================================
-- TRIGGERS FOR UPDATED_AT
-- =============================================

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply trigger to relevant tables
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_user_auth_updated_at BEFORE UPDATE ON user_authentications
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_occasions_updated_at BEFORE UPDATE ON occasions
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_reminders_updated_at BEFORE UPDATE ON occasion_reminders
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_user_prefs_updated_at BEFORE UPDATE ON user_preferences
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Function to get current UTC timestamp (explicit)
CREATE OR REPLACE FUNCTION utc_now()
RETURNS TIMESTAMPTZ AS $$
BEGIN
    RETURN CURRENT_TIMESTAMP AT TIME ZONE 'UTC';
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Function to ensure UTC output format
CREATE OR REPLACE FUNCTION format_utc_iso8601(ts TIMESTAMPTZ)
RETURNS TEXT AS $$
BEGIN
    -- Return ISO 8601 format with 'Z' suffix for UTC
    RETURN to_char(ts AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- =============================================
-- SAMPLE QUERIES (UTC-focused with optimization notes)
-- =============================================

-- Query 1: Get all active occasions for a user (returns UTC)
-- Uses: idx_occasion_members_user
/*
SELECT
    o.id,
    o.title,
    o.description,
    o.location,
    format_utc_iso8601(o.date_time) as date_time_utc,
    format_utc_iso8601(o.end_date_time) as end_date_time_utc,
    o.recurrence_type,
    om.role,
    format_utc_iso8601(o.created_at) as created_at_utc
FROM occasions o
INNER JOIN occasion_members om ON o.id = om.occasion_id
WHERE om.user_id = $1
  AND om.status = 'active'
  AND o.is_active = TRUE
ORDER BY o.date_time;
*/

-- Query 2: Get upcoming reminders for a user (UTC-based calculation)
-- Uses: idx_notification_queue_scheduled, idx_notification_queue_user
/*
SELECT
    nq.id,
    nq.occasion_id,
    o.title,
    format_utc_iso8601(o.date_time) as occasion_time_utc,
    format_utc_iso8601(nq.scheduled_for) as reminder_time_utc,
    nq.channel,
    nq.status
FROM notification_queue nq
INNER JOIN occasions o ON nq.occasion_id = o.id
WHERE nq.user_id = $1
  AND nq.status = 'pending'
  AND nq.scheduled_for BETWEEN utc_now() AND utc_now() + INTERVAL '7 days'
ORDER BY nq.scheduled_for;
*/

-- Query 3: Get members with their timezone info
-- Uses: idx_occasion_members_occasion
/*
SELECT
    u.id,
    u.display_name,
    u.email,
    u.avatar_url,
    om.role,
    format_utc_iso8601(om.joined_at) as joined_at_utc,
    up.timezone as user_timezone  -- Frontend uses this for conversion
FROM users u
INNER JOIN occasion_members om ON u.id = om.user_id
LEFT JOIN user_preferences up ON u.id = up.user_id
WHERE om.occasion_id = $1
  AND om.status = 'active'
ORDER BY om.role, om.joined_at;
*/

-- =============================================
-- VIEWS FOR CONSISTENT UTC OUTPUT
-- =============================================

-- -- View for occasions with UTC timestamps
-- CREATE OR REPLACE VIEW v_occasions_utc AS
-- SELECT
--     o.*,
--     format_utc_iso8601(o.date_time) as date_time_iso,
--     format_utc_iso8601(o.end_date_time) as end_date_time_iso,
--     format_utc_iso8601(o.created_at) as created_at_iso,
--     format_utc_iso8601(o.updated_at) as updated_at_iso
-- FROM occasions o;
--
-- -- View for notification queue with UTC timestamps
-- CREATE OR REPLACE VIEW v_notification_queue_utc AS
-- SELECT
--     nq.*,
--     format_utc_iso8601(nq.scheduled_for) as scheduled_for_iso,
--     format_utc_iso8601(nq.created_at) as created_at_iso,
--     format_utc_iso8601(nq.processed_at) as processed_at_iso
-- FROM notification_queue nq;

-- =============================================
-- APPLICATION CONNECTION SETUP
-- =============================================

/*
-- PostgreSQL connection configuration (in application):

// Node.js with pg library
const pool = new Pool({
    // ... other config
    options: {
        // Force UTC timezone for this connection
        '-c timezone=UTC'
    }
});

// OR set after connection
pool.on('connect', (client) => {
    client.query("SET timezone = 'UTC'");
});

// Python with psycopg2
conn = psycopg2.connect(
    "... options='-c timezone=UTC'"
)

// Go with pq
db, err := sql.Open("postgres",
    "... timezone=UTC"
)

*/