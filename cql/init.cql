CREATE KEYSPACE IF NOT EXISTS accesscore WITH replication = {
    'class': 'NetworkTopologyStrategy',
    'replication_factor': 3
};

USE accesscore;

CREATE TABLE IF NOT EXISTS tenants (
    tenant_id ASCII,
    name TEXT,
    host TEXT,
    created_at TIMESTAMP,
    PRIMARY KEY (tenant_id)
);

CREATE MATERIALIZED VIEW IF NOT EXISTS tenants_by_host AS
    SELECT tenant_id, host
    FROM tenants
    WHERE host IS NOT NULL
        AND tenant_id IS NOT NULL
    PRIMARY KEY (host, tenant_id);

CREATE TABLE IF NOT EXISTS tenants_by_admin_users (
    user_id ASCII,
    tenant_id ASCII,
    PRIMARY KEY (user_id, tenant_id)
);

CREATE MATERIALIZED VIEW IF NOT EXISTS admin_users_by_tenant AS
    SELECT user_id, tenant_id
    FROM tenants_by_admin_users
    WHERE user_id IS NOT NULL
        AND tenant_id IS NOT NULL
    PRIMARY KEY (tenant_id, user_id);

CREATE TABLE IF NOT EXISTS oauth_provider_settings (
    tenant_id ASCII,
    provider ASCII,
    client_id ASCII,
    client_secret ASCII,
    is_active BOOLEAN,
    metadata MAP<ASCII,TEXT>,
    PRIMARY KEY (tenant_id, provider)
);

CREATE TABLE IF NOT EXISTS tenant_settings (
    tenant_id ASCII,
    category TINYINT,
    key ASCII,
    value TEXT,
    PRIMARY KEY ((tenant_id), category, key)
);

CREATE TABLE IF NOT EXISTS organizations (
    tenant_id ASCII,
    organization_id ASCII,
    name TEXT,
    metadata MAP<ASCII,ASCII>,
    PRIMARY KEY ((tenant_id, organization_id))
);

CREATE TABLE IF NOT EXISTS organizations_by_user (
    tenant_id ASCII,
    user_id ASCII,
    organization_id ASCII,
    PRIMARY KEY ((tenant_id, user_id), organization_id)
);

CREATE MATERIALIZED VIEW IF NOT EXISTS users_by_organization AS
    SELECT tenant_id, user_id, organization_id
    FROM organizations_by_user
    WHERE tenant_id IS NOT NULL
        AND user_id IS NOT NULL
        AND organization_id IS NOT NULL
    PRIMARY KEY ((tenant_id, organization_id), user_id);

CREATE TYPE IF NOT EXISTS user_name (
    first TEXT,
    middle TEXT,
    last TEXT,
    prefix TEXT,
    suffix TEXT
);

CREATE TYPE IF NOT EXISTS user_employment (
    title TEXT,
    manager_id ASCII,
    cost_center TEXT,
    organization TEXT,
    division TEXT,
    department TEXT
);

CREATE TABLE IF NOT EXISTS users (
    user_id ASCII,
    tenant_id ASCII,
    username TEXT,
    name FROZEN<user_name>,
    location TEXT,
    locale ASCII,  -- {ISO 639-3}{ISO 15924}{ISO 3166}.
    can_access_tenant BOOLEAN,
    timezone ASCII,
    is_verified BOOLEAN,
    is_locked BOOLEAN,
    is_suspended BOOLEAN,
    roles SET<TEXT>,
    employment FROZEN<user_employment>,
    last_login TIMESTAMP,
    login_count INT,
    metadata MAP<ASCII,ASCII>,
    permissions SET<ASCII>,
    password ASCII,
    security_question_id SMALLINT,
    security_question_answer ASCII,
    created_at TIMESTAMP,
    updated_at TIMESTAMP,
    PRIMARY KEY ((user_id, tenant_id))
);

CREATE MATERIALIZED VIEW IF NOT EXISTS users_by_username AS
    SELECT tenant_id, user_id, username
    FROM users
    WHERE tenant_id IS NOT NULL
        AND user_id IS NOT NULL
        AND username IS NOT NULL
    PRIMARY KEY ((tenant_id, username), user_id);

CREATE TABLE IF NOT EXISTS emails (
    tenant_id ASCII,
    user_id ASCII,
    email TEXT,
    is_main BOOLEAN,
    is_work BOOLEAN,
    is_verified BOOLEAN,
    created_at TIMESTAMP,
    verified_at TIMESTAMP,
    PRIMARY KEY ((tenant_id, user_id), email)
);

CREATE MATERIALIZED VIEW IF NOT EXISTS users_by_email AS
    SELECT tenant_id, user_id, email
    FROM emails
    WHERE tenant_id IS NOT NULL
        AND user_id IS NOT NULL
        AND email IS NOT NULL
    PRIMARY KEY ((tenant_id, email), user_id);

CREATE TABLE IF NOT EXISTS phone_numbers (
    tenant_id ASCII,
    user_id ASCII,
    number ASCII,
    is_main BOOLEAN,
    is_work BOOLEAN,
    is_verified BOOLEAN,
    created_at TIMESTAMP,
    verified_at TIMESTAMP,
    PRIMARY KEY ((tenant_id, user_id))
);

CREATE MATERIALIZED VIEW IF NOT EXISTS users_by_phone_number AS
    SELECT tenant_id, user_id, number
    FROM phone_numbers
    WHERE tenant_id IS NOT NULL
        AND user_id IS NOT NULL
        AND number IS NOT NULL
    PRIMARY KEY ((tenant_id, number), user_id);

CREATE TABLE IF NOT EXISTS oauth_accounts (
    tenant_id ASCII,
    user_id ASCII,
    provider ASCII,
    external_id ASCII,
    name TEXT,
    access_token ASCII,
    refresh_token ASCII,
    access_token_expires_at TIMESTAMP,
    refresh_token_expires_at TIMESTAMP,
    scopes SET<ASCII>,
    is_active BOOLEAN,
    PRIMARY KEY ((tenant_id, user_id), provider, external_id)
);

CREATE MATERIALIZED VIEW IF NOT EXISTS users_by_oauth_account AS
    SELECT tenant_id, user_id, provider, external_id
    FROM oauth_accounts
    WHERE tenant_id IS NOT NULL
        AND user_id IS NOT NULL
        AND provider IS NOT NULL
        AND external_id IS NOT NULL
    PRIMARY KEY ((tenant_id, provider, external_id), user_id);

CREATE TABLE IF NOT EXISTS mfa_codes (
    tenant_id ASCII,
    user_id ASCII,
    code INT,
    code_type TINYINT,
    created_at TIMESTAMP,
    PRIMARY KEY ((tenant_id, user_id, code_type))
) WITH default_time_to_live = 900;  -- 15 minutes.

CREATE TABLE IF NOT EXISTS passwords (
    tenant_id ASCII,
    user_id ASCII,
    hash ASCII,
    changed_at TIMESTAMP,
    PRIMARY KEY ((tenant_id, user_id), changed_at)
) WITH default_time_to_live = 15811200;  -- 6 months.

CREATE TABLE IF NOT EXISTS devices (
    tenant_id ASCII,
    user_id ASCII,
    device_id ASCII,
    os ASCII,
    os_version ASCII,
    family TEXT,
    brand TEXT,
    model TEXT,
    client_id ASCII,
    ip INET,
    location TEXT,
    created_at TIMESTAMP,
    last_login TIMESTAMP,
    PRIMARY KEY ((tenant_id, user_id), device_id)
);

CREATE TABLE IF NOT EXISTS api_tokens (
    tenant_id ASCII,
    user_id ASCII,
    api_token BLOB,
    is_refresh BOOLEAN,
    scopes SET<ASCII>,
    device_id ASCII,
    client_id ASCII,
    created_at TIMESTAMP,
    PRIMARY KEY ((tenant_id, api_token), is_refresh, user_id)
) WITH default_time_to_live = 2592000;  -- A month.

CREATE MATERIALIZED VIEW IF NOT EXISTS api_tokens_by_user AS
    SELECT tenant_id, user_id, api_token, is_refresh
    FROM api_tokens
    WHERE tenant_id IS NOT NULL
        AND user_id IS NOT NULL
        AND api_token IS NOT NULL
        AND is_refresh IS NOT NULL
    PRIMARY KEY ((tenant_id, user_id), is_refresh, api_token);

CREATE TABLE IF NOT EXISTS api_clients (
    tenant_id ASCII,
    client_id ASCII,
    secret ASCII,
    name TEXT,
    client_type TINYINT,
    PRIMARY KEY ((tenant_id, client_id))
);

CREATE TABLE IF NOT EXISTS groups (
    tenant_id ASCII,
    group_id ASCII,
    name TEXT,
    description TEXT,
    permissions SET<ASCII>,
    priority SMALLINT,
    color INT,
    PRIMARY KEY ((tenant_id, group_id), priority)
);

CREATE TABLE IF NOT EXISTS users_by_group (
    tenant_id ASCII,
    group_id ASCII,
    user_id ASCII,
    PRIMARY KEY ((tenant_id, group_id), user_id)
);

CREATE MATERIALIZED VIEW IF NOT EXISTS groups_by_user AS
    SELECT tenant_id, group_id, user_id
    FROM users_by_group
    WHERE tenant_id IS NOT NULL
        AND group_id IS NOT NULL
        AND user_id IS NOT NULL
    PRIMARY KEY ((tenant_id, user_id), group_id);

CREATE TABLE IF NOT EXISTS activity_logs (
    tenant_id ASCII,
    request_id ASCII,
    user_id ASCII,
    data ASCII,
    timestamp TIMESTAMP,
    PRIMARY KEY (tenant_id, request_id)
);

CREATE TABLE IF NOT EXISTS notification_recipients (
    tenant_id ASCII,
    notification_id ASCII,
    user_id ASCII,
    status TINYINT,
    delivered_at TIMESTAMP,
    read_at TIMESTAMP,
    notification_type TINYINT,
    PRIMARY KEY ((tenant_id, user_id), notification_id)
) WITH default_time_to_live = 7776000  -- 3 months.
    AND CLUSTERING ORDER BY (notification_id DESC);

CREATE TABLE IF NOT EXISTS notifications (
    tenant_id ASCII,
    notification_id ASCII,
    event_type SMALLINT,
    notification_type TINYINT,
    title TEXT,
    message TEXT,
    data MAP<ASCII,TEXT>,
    priority TINYINT,
    created_at TIMESTAMP,
    PRIMARY KEY (tenant_id, notification_id)
) WITH default_time_to_live = 7776000;  -- 3 months.

INSERT INTO tenants (tenant_id, name, host) VALUES ('accesscore', 'AccessCore', 'localhost:3000');
INSERT INTO users (
    tenant_id,
    user_id,
    username,
    can_access_tenant,
    is_verified,
    is_locked,
    is_suspended,
    password,
    location,
    locale,
    roles,
    permissions,
    login_count,
    metadata,
    created_at,
    updated_at
) VALUES (
    'accesscore',
    'admin',
    'admin',
    true,
    true,
    false,
    false,
    '$2y$10$hUfIyQqviGw8WC4OAlqtdegouWzSToQ8qu4ppOubBx0LEiuQPASWO',
    'Buenos Aires, Argentina',
    'spaLatnAR',
    {},
    {},
    0,
    {},
    toTimestamp(now()),
    toTimestamp(now())
);
