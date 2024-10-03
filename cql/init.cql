CREATE KEYSPACE IF NOT EXISTS accesscore WITH replication = {
    'class': 'NetworkTopologyStrategy',
    'replication_factor': 3
};

USE accesscore;

CREATE TABLE IF NOT EXISTS tenants (
    id ASCII,
    name TEXT,
    host TEXT,
    PRIMARY KEY (id)
);

CREATE MATERIALIZED VIEW IF NOT EXISTS tenants_by_host AS
    SELECT id, host
    FROM tenants
    WHERE host IS NOT NULL AND id IS NOT NULL
    PRIMARY KEY (host, id);

CREATE TABLE IF NOT EXISTS tenants_by_admin_users (
    user_id ASCII,
    role TINYINT,
    tenant_id ASCII,
    PRIMARY KEY (user_id, tenant_id)
);

CREATE TABLE IF NOT EXISTS admin_users_by_tenant (
    user_id ASCII,
    role TINYINT,
    tenant_id ASCII,
    PRIMARY KEY (tenant_id, user_id)
);

CREATE TABLE IF NOT EXISTS oauth_provider_settings (
    tenant_id ASCII,
    provider ASCII,
    client_id ASCII,
    client_secret ASCII,
    active BOOLEAN,
    metadata MAP<ASCII,TEXT>,
    PRIMARY KEY (tenant_id, provider)
);

CREATE TABLE IF NOT EXISTS tenant_settings (
    tenant_id ASCII,
    type TINYINT,  -- (0) SECURITY, (1) LOGIN, ...
    key ASCII,
    value TEXT,
    PRIMARY KEY ((tenant_id, type), key)
);

CREATE TABLE IF NOT EXISTS organizations (
    tenant_id ASCII,
    id ASCII,
    name TEXT,
    metadata MAP<ASCII,ASCII>,
    PRIMARY KEY ((tenant_id, id))
);

CREATE TABLE IF NOT EXISTS organizations_by_user (
    tenant_id ASCII,
    user_id ASCII,
    organization_id ASCII,
    PRIMARY KEY ((tenant_id, user_id), organization_id)
);

CREATE TABLE IF NOT EXISTS users_by_organization (
    tenant_id ASCII,
    user_id ASCII,
    organization_id ASCII,
    PRIMARY KEY ((tenant_id, organization_id), user_id)
);

CREATE TABLE IF NOT EXISTS users (
    id ASCII,
    tenant_id ASCII,
    username TEXT,
    first_name TEXT,
    middle_name TEXT,
    last_name TEXT,
    honorific_prefix TEXT,           -- Ex. "Mr.", "Ms.", "Dr.".
    honorific_suffix TEXT,           -- Ex. "III".
    location TEXT,                   -- Ex. "New York, USA", "Buenos Aires, Argentina".
    locale ASCII,                    -- {ISO 639-3}{ISO 15924}{ISO 3166}.
    preferred_language ASCII,        -- {ISO 639-3}{ISO 15924}{ISO 3166}.
    type TINYINT,                    -- USER (0) or MANAGER (1). It specifies who can access the tenant's settings.
    timezone ASCII,
    status TINYINT,                  -- UNVERIFIED (0), ACTIVE (1), LOCKED (2), SUSPENDED (3), ON_DELETION (4).
    title TEXT,
    -- groups SET<ASCII>,
    manager ASCII,                   -- The user's manager ID.
    roles SET<TEXT>,                 -- A list of the user's roles.
    employee_number INT,
    cost_center TEXT,
    organization TEXT,
    division TEXT,
    department TEXT,
    last_login TIMESTAMP,
    login_count INT,
    metadata MAP<ASCII,ASCII>,
    permissions SET<ASCII>,
    -- image_id ASCII,               -- Use something like {base-cdn}/tenants/{tenant-id}/avatars/{user-id}.
    password ASCII,                  -- 60-char-long bcrypt hash.
    security_question_id SMALLINT,   -- The security question's ID. An ID is kept instead of the question itself to support translation.
    security_question_answer ASCII,  -- 60-char-long bcrypt hash.
    created_at TIMESTAMP,
    updated_at TIMESTAMP,
    delete_at TIMESTAMP,
    PRIMARY KEY ((id, tenant_id))
);

CREATE MATERIALIZED VIEW IF NOT EXISTS users_by_username AS
    SELECT tenant_id, id, username
    FROM users
    WHERE tenant_id IS NOT NULL
        AND id IS NOT NULL
        AND username IS NOT NULL
    PRIMARY KEY ((tenant_id, username), id);

CREATE TABLE IF NOT EXISTS emails (
    tenant_id ASCII,
    user_id ASCII,
    email TEXT,
    main BOOLEAN,
    type TINYINT,   -- PERSONAL (0), WORK (1)
    status TINYINT, -- UNVERIFIED (0), VERIFIED (1)
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
    main BOOLEAN,
    type TINYINT,    -- PERSONAL (0), WORK (1)
    status TINYINT,  -- UNVERIFIED (0), VERIFIED (1)
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
    access_token ASCII,
    refresh_token ASCII,
    access_token_expires_at TIMESTAMP,
    refresh_token_expires_at TIMESTAMP,
    status TINYINT,  -- (0) NORMAL, (1) REQUIRES_RELOGIN
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
    type TINYINT,  -- (0) EMAIL, (1) SMS, (2) WHATSAPP, (3) PUSH_NOTIFICATION
    created_at TIMESTAMP,
    PRIMARY KEY ((tenant_id, user_id, type))
) WITH default_time_to_live = 900;  -- 15 minutes.

CREATE TABLE IF NOT EXISTS passwords (
    tenant_id ASCII,
    user_id ASCII,
    changed_at TIMESTAMP,
    hash ASCII,
    PRIMARY KEY ((tenant_id, user_id), changed_at)
) WITH default_time_to_live = 15811200;  -- 6 months.

CREATE TABLE IF NOT EXISTS devices (
    tenant_id ASCII,
    user_id ASCII,
    id ASCII,
    name ASCII,
    os ASCII,
    client ASCII,
    ip INET,
    location TEXT,
    last_login TIMESTAMP,
    created_at TIMESTAMP,
    PRIMARY KEY ((tenant_id, user_id), id)
);

CREATE TABLE IF NOT EXISTS api_tokens (
    tenant_id ASCII,
    user_id ASCII,
    api_token ASCII,
    type TINYINT,  -- (0) ACCESS, (1) REFRESH
    scopes SET<ASCII>,
    device_id ASCII,
    created_at TIMESTAMP,
    client_id ASCII,
    PRIMARY KEY ((tenant_id, api_token), user_id)
) WITH default_time_to_live = 2592000;  -- A month.

CREATE TABLE IF NOT EXISTS api_clients (
    tenant_id ASCII,
    id ASCII,
    name TEXT,
    type TINYINT, -- (0) INTERNAL, (1) WEB, (2) DESKTOP, (3) MOBILE, (4) CONSOLE, (5) IOT
    PRIMARY KEY ((tenant_id, id))
);

CREATE TABLE IF NOT EXISTS groups (
    tenant_id ASCII,
    id ASCII,
    name TEXT,
    description TEXT,
    permissions SET<ASCII>,
    priority SMALLINT,
    color INT,
    PRIMARY KEY ((tenant_id, id), priority)
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
    organization_id ASCII,
    user_id ASCII,
    group_id ASCII,
    request_id ASCII,
    timestamp TIMESTAMP,
    details ASCII,
    PRIMARY KEY (tenant_id)
);

CREATE TABLE IF NOT EXISTS notification_recipients (
    tenant_id ASCII,
    notification_id ASCII,
    user_id ASCII,
    status TINYINT,             -- (0) DELIVERING, (1) DELIVERED, (2) FAILED
    delivered_at TIMESTAMP,
    read_at TIMESTAMP,
    notification_type TINYINT,  -- (0) IN_APP, (1) EMAIL, (2) SMS, (3) WHATSAPP, (4) PUSH
    PRIMARY KEY ((tenant_id, user_id), notification_id)
) WITH default_time_to_live = 7776000  -- 3 months.
    AND CLUSTERING ORDER BY (notification_id DESC);

CREATE TABLE IF NOT EXISTS notifications (
    tenant_id ASCII,
    id ASCII,
    event_type SMALLINT,  -- (0) NEW_LOGIN, (1) UNRECOGNIZED_LOGIN, (2) ...
    type TINYINT,         -- (0) IN_APP, (1) EMAIL, (2) SMS, (3) WHATSAPP, (4) PUSH
    title TEXT,
    message TEXT,
    data MAP<ASCII,TEXT>,
    priority TINYINT,     -- (0) LOW, (1) MEDIUM, (2) HIGH, (3) CRITICAL
    created_at TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
) WITH default_time_to_live = 7776000;  -- 3 months.

INSERT INTO tenants (id, name, host) VALUES ('accesscore', 'AccessCore', 'localhost:3000');
INSERT INTO users (
    tenant_id,
    id,
    username,
    type,
    status,
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
    1,
    1,
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
