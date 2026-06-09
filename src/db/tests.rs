use super::*;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::str::FromStr;

async fn memory_pool() -> SqlitePool {
    SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::from_str("sqlite::memory:")
                .unwrap()
                .foreign_keys(true),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn migrate_creates_all_tables() {
    let pool = memory_pool().await;
    migrate(&pool).await.unwrap();

    let expected_tables = [
        "accounts",
        "caldav_sources",
        "calendars",
        "events",
        "event_types",
        "availability_rules",
        "availability_overrides",
        "bookings",
        "users",
        "sessions",
        "auth_config",
        "smtp_config",
        "groups",
        "user_groups",
        "event_type_calendars",
        "booking_invites",
        "booking_attendees",
        "event_type_watchers",
        "booking_claim_tokens",
    ];

    for table in &expected_tables {
        let exists: (i64,) = sqlx::query_as(&format!(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='{}'",
            table
        ))
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            exists.0, 1,
            "Table '{}' should exist after migration",
            table
        );
    }
}

#[tokio::test]
async fn migrate_tracks_applied_migrations() {
    let pool = memory_pool().await;
    migrate(&pool).await.unwrap();

    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM _migrations")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count.0, 56, "All 56 migrations should be tracked");
}

#[tokio::test]
async fn migrate_is_idempotent() {
    let pool = memory_pool().await;
    migrate(&pool).await.unwrap();
    // Running again should not fail or double-apply
    migrate(&pool).await.unwrap();

    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM _migrations")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count.0, 56, "Still 56 migrations after second run");
}

#[tokio::test]
async fn migrate_migration_count_matches_files() {
    // This test catches the "forgot to register migration" bug.
    // Count .sql files in migrations/ dir
    let migration_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
    let sql_files: Vec<_> = std::fs::read_dir(&migration_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "sql"))
        .collect();

    let pool = memory_pool().await;
    migrate(&pool).await.unwrap();

    let registered: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM _migrations")
        .fetch_one(&pool)
        .await
        .unwrap();

    assert_eq!(
        sql_files.len() as i64,
        registered.0,
        "Number of .sql files ({}) must match registered migrations ({}). Did you forget to register a migration in db.rs?",
        sql_files.len(),
        registered.0,
    );
}

#[tokio::test]
async fn migrate_foreign_keys_work() {
    let pool = memory_pool().await;
    migrate(&pool).await.unwrap();

    // Insert a user and account
    let user_id = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO users (id, email, name, role, auth_provider, username, enabled) VALUES (?, 'fk@test.com', 'FK Test', 'user', 'local', 'fktest', 1)")
        .bind(&user_id)
        .execute(&pool).await.unwrap();

    let account_id = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO accounts (id, name, email, timezone, user_id) VALUES (?, 'FK Test', 'fk@test.com', 'UTC', ?)")
        .bind(&account_id)
        .bind(&user_id)
        .execute(&pool).await.unwrap();

    // Insert a caldav source referencing the account
    let source_id = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO caldav_sources (id, account_id, name, url, username, enabled) VALUES (?, ?, 'Test', 'https://example.com', 'user', 1)")
        .bind(&source_id)
        .bind(&account_id)
        .execute(&pool).await.unwrap();

    // Deleting the account should cascade-delete the source
    sqlx::query("DELETE FROM accounts WHERE id = ?")
        .bind(&account_id)
        .execute(&pool)
        .await
        .unwrap();

    let source_exists: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM caldav_sources WHERE id = ?")
        .bind(&source_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        source_exists.0, 0,
        "Source should be cascade-deleted with account"
    );
}

#[tokio::test]
async fn migrate_orphaned_accounts_links_to_user() {
    let pool = memory_pool().await;

    // Run migrations first to get schema
    migrate(&pool).await.unwrap();

    // Insert an orphaned account (user_id = NULL)
    let account_id = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO accounts (id, name, email, timezone, user_id) VALUES (?, 'Orphan', 'orphan@test.com', 'UTC', NULL)")
        .bind(&account_id)
        .execute(&pool).await.unwrap();

    // Run migration again → should create user and link
    migrate(&pool).await.unwrap();

    // Account should now have a user_id
    let linked: Option<(String,)> =
        sqlx::query_as("SELECT user_id FROM accounts WHERE id = ? AND user_id IS NOT NULL")
            .bind(&account_id)
            .fetch_optional(&pool)
            .await
            .unwrap();
    assert!(
        linked.is_some(),
        "Orphaned account should be linked to a user"
    );
}

#[tokio::test]
async fn generate_usernames_from_email() {
    let pool = memory_pool().await;
    migrate(&pool).await.unwrap();

    let user_id = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO users (id, email, name, role, auth_provider, username, enabled) VALUES (?, 'john.doe@example.com', 'John', 'user', 'local', NULL, 1)")
        .bind(&user_id)
        .execute(&pool).await.unwrap();

    generate_missing_usernames(&pool).await.unwrap();

    let username: Option<(String,)> = sqlx::query_as("SELECT username FROM users WHERE id = ?")
        .bind(&user_id)
        .fetch_optional(&pool)
        .await
        .unwrap();
    assert_eq!(
        username.unwrap().0,
        "john-doe",
        "john.doe@example.com → john-doe"
    );
}

#[tokio::test]
async fn migrate_passwords_encrypts_plaintext_oidc_secret() {
    // Simulates an upgrade: a pre-existing plaintext OIDC client secret
    // sitting in auth_config should be transparently re-encrypted on
    // the next startup.
    let pool = memory_pool().await;
    migrate(&pool).await.unwrap();
    let key = [7u8; 32];
    let plaintext = "my-keycloak-client-secret";

    sqlx::query("UPDATE auth_config SET oidc_client_secret = ? WHERE id = 'singleton'")
        .bind(plaintext)
        .execute(&pool)
        .await
        .unwrap();

    migrate_passwords(&pool, &key).await.unwrap();

    let stored: (String,) =
        sqlx::query_as("SELECT oidc_client_secret FROM auth_config WHERE id = 'singleton'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        crate::crypto::is_encrypted_value(&stored.0),
        "oidc_client_secret should be in enc:v1: format after migration, got {:?}",
        stored.0
    );
    assert_eq!(
        crate::crypto::decrypt_value(&key, &stored.0).unwrap(),
        plaintext,
    );
}

#[tokio::test]
async fn migrate_passwords_handles_plaintext_starting_with_prefix() {
    // Pathological case: a plaintext OIDC secret that literally begins
    // with the "enc:v1:" sentinel. With prefix-only detection the
    // migration would skip it and the read path would fail. With the
    // try-decrypt belt-and-suspenders, decryption fails (the bytes
    // after the prefix aren't valid AES-GCM ciphertext) so we treat
    // it as plaintext and encrypt it normally.
    let pool = memory_pool().await;
    migrate(&pool).await.unwrap();
    let key = [11u8; 32];
    let plaintext = "enc:v1:looks-encrypted-but-isnt";

    sqlx::query("UPDATE auth_config SET oidc_client_secret = ? WHERE id = 'singleton'")
        .bind(plaintext)
        .execute(&pool)
        .await
        .unwrap();

    migrate_passwords(&pool, &key).await.unwrap();

    let stored: (String,) =
        sqlx::query_as("SELECT oidc_client_secret FROM auth_config WHERE id = 'singleton'")
            .fetch_one(&pool)
            .await
            .unwrap();
    // The stored value roundtrips back to the original plaintext.
    assert_eq!(
        crate::crypto::decrypt_value(&key, &stored.0).unwrap(),
        plaintext,
    );
}

#[tokio::test]
async fn migrate_passwords_is_idempotent_for_oidc_secret() {
    // Running the migration twice must not double-encrypt the value.
    let pool = memory_pool().await;
    migrate(&pool).await.unwrap();
    let key = [9u8; 32];
    let plaintext = "another-secret";

    sqlx::query("UPDATE auth_config SET oidc_client_secret = ? WHERE id = 'singleton'")
        .bind(plaintext)
        .execute(&pool)
        .await
        .unwrap();

    migrate_passwords(&pool, &key).await.unwrap();
    let after_first: (String,) =
        sqlx::query_as("SELECT oidc_client_secret FROM auth_config WHERE id = 'singleton'")
            .fetch_one(&pool)
            .await
            .unwrap();

    migrate_passwords(&pool, &key).await.unwrap();
    let after_second: (String,) =
        sqlx::query_as("SELECT oidc_client_secret FROM auth_config WHERE id = 'singleton'")
            .fetch_one(&pool)
            .await
            .unwrap();

    // The stored value is unchanged on the second run (we don't
    // re-encrypt, which would otherwise produce a different
    // ciphertext from the random nonce).
    assert_eq!(after_first.0, after_second.0);
    assert_eq!(
        crate::crypto::decrypt_value(&key, &after_second.0).unwrap(),
        plaintext,
    );
}

#[tokio::test]
async fn migrate_passwords_encrypts_plaintext_google_oauth2_secret() {
    // Pre-existing plaintext Google OAuth2 client secret should be
    // transparently re-encrypted on the next startup, matching the
    // OIDC client secret migration.
    let pool = memory_pool().await;
    migrate(&pool).await.unwrap();
    let key = [13u8; 32];
    let plaintext = "GOCSPX-my-google-client-secret";

    sqlx::query("UPDATE auth_config SET google_oauth2_client_secret = ? WHERE id = 'singleton'")
        .bind(plaintext)
        .execute(&pool)
        .await
        .unwrap();

    migrate_passwords(&pool, &key).await.unwrap();

    let stored: (String,) = sqlx::query_as(
        "SELECT google_oauth2_client_secret FROM auth_config WHERE id = 'singleton'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        crate::crypto::is_encrypted_value(&stored.0),
        "google_oauth2_client_secret should be in enc:v1: format after migration, got {:?}",
        stored.0
    );
    assert_eq!(
        crate::crypto::decrypt_value(&key, &stored.0).unwrap(),
        plaintext,
    );
}

#[tokio::test]
async fn migrate_passwords_handles_plaintext_google_secret_starting_with_prefix() {
    // Pathological case: a plaintext Google client secret that
    // literally begins with the "enc:v1:" sentinel. Try-decrypt
    // belt-and-suspenders means the migration treats it as plaintext.
    let pool = memory_pool().await;
    migrate(&pool).await.unwrap();
    let key = [17u8; 32];
    let plaintext = "enc:v1:looks-encrypted-but-isnt";

    sqlx::query("UPDATE auth_config SET google_oauth2_client_secret = ? WHERE id = 'singleton'")
        .bind(plaintext)
        .execute(&pool)
        .await
        .unwrap();

    migrate_passwords(&pool, &key).await.unwrap();

    let stored: (String,) = sqlx::query_as(
        "SELECT google_oauth2_client_secret FROM auth_config WHERE id = 'singleton'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        crate::crypto::decrypt_value(&key, &stored.0).unwrap(),
        plaintext,
    );
}

#[tokio::test]
async fn migrate_passwords_is_idempotent_for_google_oauth2_secret() {
    let pool = memory_pool().await;
    migrate(&pool).await.unwrap();
    let key = [19u8; 32];
    let plaintext = "another-google-secret";

    sqlx::query("UPDATE auth_config SET google_oauth2_client_secret = ? WHERE id = 'singleton'")
        .bind(plaintext)
        .execute(&pool)
        .await
        .unwrap();

    migrate_passwords(&pool, &key).await.unwrap();
    let after_first: (String,) = sqlx::query_as(
        "SELECT google_oauth2_client_secret FROM auth_config WHERE id = 'singleton'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();

    migrate_passwords(&pool, &key).await.unwrap();
    let after_second: (String,) = sqlx::query_as(
        "SELECT google_oauth2_client_secret FROM auth_config WHERE id = 'singleton'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(after_first.0, after_second.0);
    assert_eq!(
        crate::crypto::decrypt_value(&key, &after_second.0).unwrap(),
        plaintext,
    );
}
