-- Authentication schema for MySQL 5.7.
-- Run against an existing empty database.

SET NAMES utf8mb4;
SET time_zone = '+00:00';

CREATE TABLE IF NOT EXISTS app_role (
    role_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    role_code ENUM('buyer', 'merchant', 'admin', 'payment_agency') NOT NULL,
    role_name VARCHAR(64) NOT NULL,
    role_type ENUM('internal', 'external_system') NOT NULL,
    description VARCHAR(255) NULL,
    status ENUM('active', 'disabled') NOT NULL DEFAULT 'active',
    is_system TINYINT(1) NOT NULL DEFAULT 0,
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
        ON UPDATE CURRENT_TIMESTAMP(3),
    PRIMARY KEY (role_id),
    UNIQUE KEY uq_app_role_code (role_code),
    KEY idx_app_role_type_status (role_type, status),
    CONSTRAINT chk_app_role_system CHECK (is_system IN (0, 1))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS user_account (
    user_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    username VARCHAR(32) NOT NULL,
    password_algo VARCHAR(32) NOT NULL DEFAULT 'pbkdf2_sha256',
    password_iterations INT UNSIGNED NOT NULL DEFAULT 600000,
    password_salt VARCHAR(22) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    password_derived VARCHAR(43) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    phone_ciphertext VARBINARY(256) NOT NULL,
    phone_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    email_ciphertext VARBINARY(512) NULL,
    email_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
    nickname VARCHAR(32) NULL,
    avatar_url VARCHAR(512) NULL,
    status ENUM('active', 'locked', 'disabled') NOT NULL DEFAULT 'active',
    failed_login_count SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    locked_until DATETIME(3) NULL,
    last_login_at DATETIME(3) NULL,
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
        ON UPDATE CURRENT_TIMESTAMP(3),
    deleted_at DATETIME(3) NULL,
    PRIMARY KEY (user_id),
    UNIQUE KEY uq_user_account_username (username),
    UNIQUE KEY uq_user_account_phone_hash (phone_hash),
    UNIQUE KEY uq_user_account_email_hash (email_hash),
    KEY idx_user_account_status (status),
    KEY idx_user_account_created_at (created_at),
    KEY idx_user_account_last_login_at (last_login_at),
    CONSTRAINT chk_user_password_algo
        CHECK (password_algo = 'pbkdf2_sha256'),
    CONSTRAINT chk_user_password_iterations
        CHECK (password_iterations >= 600000),
    CONSTRAINT chk_user_password_salt_length
        CHECK (CHAR_LENGTH(password_salt) = 22),
    CONSTRAINT chk_user_password_derived_length
        CHECK (CHAR_LENGTH(password_derived) = 43)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS user_role_relation (
    user_role_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id BIGINT UNSIGNED NOT NULL,
    role_id BIGINT UNSIGNED NOT NULL,
    is_primary TINYINT(1) NOT NULL DEFAULT 0,
    status ENUM('active', 'revoked', 'expired') NOT NULL DEFAULT 'active',
    assigned_by BIGINT UNSIGNED NULL,
    assigned_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    expires_at DATETIME(3) NULL,
    revoked_at DATETIME(3) NULL,
    reason VARCHAR(255) NULL,
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
        ON UPDATE CURRENT_TIMESTAMP(3),
    active_primary_user_id BIGINT UNSIGNED
        GENERATED ALWAYS AS (
            CASE
                WHEN status = 'active' AND is_primary = 1 THEN user_id
                ELSE NULL
            END
        ) STORED,
    PRIMARY KEY (user_role_id),
    UNIQUE KEY uq_user_role_relation (user_id, role_id),
    UNIQUE KEY uq_user_role_active_primary (active_primary_user_id),
    KEY idx_user_role_user_status (user_id, status),
    KEY idx_user_role_role_status (role_id, status),
    CONSTRAINT fk_user_role_user
        FOREIGN KEY (user_id) REFERENCES user_account (user_id)
        ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_user_role_role
        FOREIGN KEY (role_id) REFERENCES app_role (role_id)
        ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_user_role_assigned_by
        FOREIGN KEY (assigned_by) REFERENCES user_account (user_id)
        ON DELETE SET NULL ON UPDATE RESTRICT,
    CONSTRAINT chk_user_role_primary CHECK (is_primary IN (0, 1))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS session_token (
    session_token_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id BIGINT UNSIGNED NOT NULL,
    token_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    token_family_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    issued_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    expires_at DATETIME(3) NOT NULL,
    revoked_at DATETIME(3) NULL,
    revoke_reason VARCHAR(32) NULL,
    client_ip VARBINARY(16) NULL,
    user_agent VARCHAR(512) NULL,
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    PRIMARY KEY (session_token_id),
    UNIQUE KEY uq_session_token_hash (token_hash),
    KEY idx_session_token_user_state (user_id, revoked_at, expires_at),
    KEY idx_session_token_expires_at (expires_at),
    CONSTRAINT fk_session_token_user
        FOREIGN KEY (user_id) REFERENCES user_account (user_id)
        ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_session_token_expiry CHECK (expires_at > issued_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS login_log (
    login_log_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id BIGINT UNSIGNED NULL,
    account_ref_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
    account_masked VARCHAR(64) NULL,
    result ENUM('success', 'failure', 'locked', 'blocked') NOT NULL,
    failure_code VARCHAR(32) NULL,
    client_ip VARBINARY(16) NULL,
    user_agent VARCHAR(512) NULL,
    trace_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    PRIMARY KEY (login_log_id),
    KEY idx_login_log_user_time (user_id, created_at),
    KEY idx_login_log_result_time (result, created_at),
    KEY idx_login_log_ip_time (client_ip, created_at),
    KEY idx_login_log_trace_id (trace_id),
    CONSTRAINT fk_login_log_user
        FOREIGN KEY (user_id) REFERENCES user_account (user_id)
        ON DELETE SET NULL ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO app_role
    (role_code, role_name, role_type, description, status, is_system)
VALUES
    ('buyer', 'Buyer', 'internal', 'Registered buyer account', 'active', 1),
    ('merchant', 'Merchant', 'internal', 'Approved merchant account', 'active', 1),
    ('admin', 'Administrator', 'internal', 'Platform administrator', 'active', 1),
    ('payment_agency', 'Payment agency', 'external_system',
     'External payment integration identity', 'active', 1)
ON DUPLICATE KEY UPDATE
    role_name = VALUES(role_name),
    role_type = VALUES(role_type),
    description = VALUES(description),
    status = VALUES(status),
    is_system = VALUES(is_system);
