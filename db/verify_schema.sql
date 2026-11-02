-- Run after schema.sql while connected to the target database.
-- Every check should return PASS.

SET @table_count = (
    SELECT COUNT(*)
    FROM information_schema.tables
    WHERE table_schema = DATABASE()
      AND table_name IN (
          'app_role',
          'user_account',
          'user_role_relation',
          'session_token',
          'login_log'
      )
      AND table_type = 'BASE TABLE'
);

SELECT
    'authentication_tables' AS check_name,
    IF(@table_count = 5, 'PASS', 'FAIL') AS result,
    @table_count AS actual,
    5 AS expected;

SET @password_column_count = (
    SELECT COUNT(*)
    FROM information_schema.columns
    WHERE table_schema = DATABASE()
      AND table_name = 'user_account'
      AND column_name LIKE 'password%'
);

SELECT
    'password_columns' AS check_name,
    IF(@password_column_count = 4, 'PASS', 'FAIL') AS result,
    @password_column_count AS actual,
    4 AS expected;

SELECT
    GROUP_CONCAT(column_name ORDER BY ordinal_position SEPARATOR ', ')
        AS password_column_names
FROM information_schema.columns
WHERE table_schema = DATABASE()
  AND table_name = 'user_account'
  AND column_name LIKE 'password%';

SET @password_hash_count = (
    SELECT COUNT(*)
    FROM information_schema.columns
    WHERE table_schema = DATABASE()
      AND table_name = 'user_account'
      AND column_name = 'password_hash'
);

SELECT
    'no_password_hash_column' AS check_name,
    IF(@password_hash_count = 0, 'PASS', 'FAIL') AS result,
    @password_hash_count AS actual,
    0 AS expected;

SET @role_count = (
    SELECT COUNT(*)
    FROM app_role
    WHERE role_code IN ('buyer', 'merchant', 'admin', 'payment_agency')
);

SELECT
    'system_roles' AS check_name,
    IF(@role_count = 4, 'PASS', 'FAIL') AS result,
    @role_count AS actual,
    4 AS expected;

SET @foreign_key_count = (
    SELECT COUNT(*)
    FROM information_schema.key_column_usage
    WHERE table_schema = DATABASE()
      AND referenced_table_name IS NOT NULL
);

SELECT
    'foreign_keys' AS check_name,
    IF(@foreign_key_count = 5, 'PASS', 'FAIL') AS result,
    @foreign_key_count AS actual,
    5 AS expected;

SET @innodb_count = (
    SELECT COUNT(*)
    FROM information_schema.tables
    WHERE table_schema = DATABASE()
      AND table_name IN (
          'app_role',
          'user_account',
          'user_role_relation',
          'session_token',
          'login_log'
      )
      AND engine = 'InnoDB'
);

SELECT
    'innodb_tables' AS check_name,
    IF(@innodb_count = 5, 'PASS', 'FAIL') AS result,
    @innodb_count AS actual,
    5 AS expected;

SET @primary_role_index_count = (
    SELECT COUNT(DISTINCT index_name)
    FROM information_schema.statistics
    WHERE table_schema = DATABASE()
      AND table_name = 'user_role_relation'
      AND index_name = 'uq_user_role_active_primary'
      AND non_unique = 0
);

SELECT
    'single_active_primary_role' AS check_name,
    IF(@primary_role_index_count = 1, 'PASS', 'FAIL') AS result,
    @primary_role_index_count AS actual,
    1 AS expected;

SELECT
    role_code,
    role_name,
    role_type,
    status
FROM app_role
ORDER BY role_id;
