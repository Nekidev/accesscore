CREATE KEYSPACE IF NOT EXISTS accesscore WITH replication = {
    'class': 'NetworkTopologyStrategy',
    'replication_factor': 3
};

USE accesscore;

CREATE TABLE IF NOT EXISTS users (
    id ASCII,
    tenant_id ASCII,
    username ASCII,
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
    metadata MAP<TEXT,TEXT>,
    permissions SET<ASCII>,
    -- image_id ASCII,               -- Use something like {base-cdn}/tenants/{tenant-id}/avatars/{user-id}.
    password ASCII,                  -- 60-char-long bcrypt hash.
    security_question_id SMALLINT,   -- The security question's ID. An ID is kept instead of the question itself to support translation.
    security_question_answer ASCII,  -- 60-char-long bcrypt hash.
    created_at TIMESTAMP,
    updated_at TIMESTAMP,
    delete_at TIMESTAMP,
    PRIMARY KEY ((id, tenant_id), username)
);

CREATE TABLE IF NOT EXISTS users_by_username (
    tenant_id ASCII,
    username ASCII,
    user_id ASCII,
    PRIMARY KEY ((tenant_id, username))
);

CREATE TABLE IF NOT EXISTS emails (
    tenant_id ASCII,
    user_id ASCII,
    email TEXT,
    primary BOOL,
    type TINYINT,   -- PERSONAL (0), WORK (1)
    status TINYINT, -- UNVERIFIED (0), VERIFIED (1)
    created_at TIMESTAMP,
    verified_at TIMESTAMP,
    PRIMARY KEY ((tenant_id, user_id), email)
);

CREATE TABLE IF NOT EXISTS users_by_email (
    tenant_id ASCII,
    user_id ASCII,
    email TEXT,
    PRIMARY KEY((tenant_id, email), user_id)
);

CREATE TABLE IF NOT EXISTS phone_numbers (
    tenant_id ASCII,
    user_id ASCII,
    number ASCII,
    primary BOOL,
    type TINYINT,    -- PERSONAL (0), WORK (1)
    status TINYINT,  -- UNVERIFIED (0), VERIFIED (1)
    created_at TIMESTAMP,
    verified_at TIMESTAMP,
    PRIMARY KEY ((tenant_id, user_id), number)
);

CREATE TABLE IF NOT EXISTS users_by_phone_number (
    tenant_id ASCII,
    user_id ASCII,
    number ASCII,
    PRIMARY KEY ((tenant_id, number), user_id)
);

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
    PRIMARY KEY ((tenant_id, user_id), (provider, external_id))
);

CREATE TABLE IF NOT EXISTS users_by_oauth_account (
    tenant_id ASCII,
    user_id ASCII,
    provider ASCII,
    external_id ASCII,
    PRIMARY KEY ((tenant_id, provider, external_id), user_id)
);

CREATE TABLE IF NOT EXISTS mfa_codes (
    tenant_id ASCII,
    user_id ASCII,
    code INT,
    type TINYINT,  -- (0) EMAIL, (1) SMS, (2) WHATSAPP, (3) PUSH_NOTIFICATION
    created_at TIMESTAMP,
    PRIMARY KEY ((tenant_id, user_id, type))
) WITH default_time_to_live = 900;  -- 15 minutes.

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
    token ASCII,
    type TINYINT,  -- (0) ACCESS, (1) REFRESH
    scopes SET<ASCII>,
    device_id ASCII,
    created_at TIMESTAMP,
    client_id ASCII,
    PRIMARY KEY ((tenant_id, token), user_id)
) WITH default_time_to_live = 2592000;  -- A month.

CREATE TABLE IF NOT EXISTS api_clients (
    tenant_id ASCII,
    id ASCII,
    type TINYINT, -- (0) INTERNAL, (1) WEB, (2) DESKTOP, (3) MOBILE, (4) CONSOLE, (5) IOT
    
);