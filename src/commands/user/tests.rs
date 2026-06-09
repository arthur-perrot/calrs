use super::*;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::str::FromStr;

async fn setup_db() -> SqlitePool {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::from_str("sqlite::memory:")
                .unwrap()
                .foreign_keys(true),
        )
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    pool
}

/// Insert a user directly (bypasses interactive prompts in UserCommands::Create)
async fn insert_user(pool: &SqlitePool, email: &str, name: &str, role: &str) -> String {
    let user_id = Uuid::new_v4().to_string();
    let password_hash = crate::auth::hash_password("testpass123").unwrap();
    let username = crate::auth::generate_username(pool, email).await.unwrap();
    sqlx::query(
        "INSERT INTO users (id, email, name, timezone, password_hash, role, auth_provider, username, enabled)
         VALUES (?, ?, ?, 'UTC', ?, ?, 'local', ?, 1)",
    )
    .bind(&user_id)
    .bind(email)
    .bind(name)
    .bind(&password_hash)
    .bind(role)
    .bind(&username)
    .execute(pool)
    .await
    .unwrap();

    // Create a linked account
    let account_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO accounts (id, name, email, timezone, user_id) VALUES (?, ?, ?, 'UTC', ?)",
    )
    .bind(&account_id)
    .bind(name)
    .bind(email)
    .bind(&user_id)
    .execute(pool)
    .await
    .unwrap();

    user_id
}

/// Wrapper around `auth::create_local_user` that handles the bookkeeping
/// the production handler also handles (UUID, password hash, username).
/// Calls the same helper the `Create` command uses, so the atomic CASE
/// in the production code path is what's actually under test.
async fn create_user_returning_role(pool: &SqlitePool, email: &str, admin: bool) -> String {
    let user_id = Uuid::new_v4().to_string();
    let password_hash = crate::auth::hash_password("testpass123").unwrap();
    let username = crate::auth::generate_username(pool, email).await.unwrap();
    crate::auth::create_local_user(
        pool,
        &user_id,
        email,
        "Test",
        &password_hash,
        &username,
        admin,
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn first_user_create_gets_admin_role_atomically() {
    let pool = setup_db().await;
    let role = create_user_returning_role(&pool, "first@test.com", false).await;
    assert_eq!(role, "admin");
}

#[tokio::test]
async fn subsequent_user_create_gets_user_role() {
    let pool = setup_db().await;
    insert_user(&pool, "first@test.com", "First", "admin").await;
    let role = create_user_returning_role(&pool, "second@test.com", false).await;
    assert_eq!(role, "user");
}

#[tokio::test]
async fn explicit_admin_flag_overrides_user_role() {
    // `--admin` flag set + existing users: the operator's choice wins.
    let pool = setup_db().await;
    insert_user(&pool, "first@test.com", "First", "admin").await;
    let role = create_user_returning_role(&pool, "second@test.com", true).await;
    assert_eq!(role, "admin");
}

#[tokio::test]
async fn test_list_users_empty() {
    let pool = setup_db().await;
    let result = run(&pool, &std::env::temp_dir(), UserCommands::List).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_list_users_with_data() {
    let pool = setup_db().await;
    insert_user(&pool, "alice@test.com", "Alice", "admin").await;
    insert_user(&pool, "bob@test.com", "Bob", "user").await;

    let result = run(&pool, &std::env::temp_dir(), UserCommands::List).await;
    assert!(result.is_ok());

    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count.0, 2);
}

#[tokio::test]
async fn test_promote_user() {
    let pool = setup_db().await;
    insert_user(&pool, "alice@test.com", "Alice", "admin").await;
    insert_user(&pool, "bob@test.com", "Bob", "user").await;

    let result = run(
        &pool,
        &std::env::temp_dir(),
        UserCommands::Promote {
            email: "bob@test.com".to_string(),
        },
    )
    .await;
    assert!(result.is_ok());

    let role: (String,) = sqlx::query_as("SELECT role FROM users WHERE email = 'bob@test.com'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(role.0, "admin");
}

#[tokio::test]
async fn test_demote_user() {
    let pool = setup_db().await;
    insert_user(&pool, "alice@test.com", "Alice", "admin").await;
    insert_user(&pool, "bob@test.com", "Bob", "admin").await;

    let result = run(
        &pool,
        &std::env::temp_dir(),
        UserCommands::Demote {
            email: "bob@test.com".to_string(),
        },
    )
    .await;
    assert!(result.is_ok());

    let role: (String,) = sqlx::query_as("SELECT role FROM users WHERE email = 'bob@test.com'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(role.0, "user");
}

#[tokio::test]
async fn test_demote_last_admin_prevented() {
    let pool = setup_db().await;
    insert_user(&pool, "alice@test.com", "Alice", "admin").await;

    // Attempting to demote the only admin should not change the role
    let result = run(
        &pool,
        &std::env::temp_dir(),
        UserCommands::Demote {
            email: "alice@test.com".to_string(),
        },
    )
    .await;
    assert!(result.is_ok());

    let role: (String,) = sqlx::query_as("SELECT role FROM users WHERE email = 'alice@test.com'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(role.0, "admin", "Last admin should not be demoted");
}

#[tokio::test]
async fn test_disable_user() {
    let pool = setup_db().await;
    insert_user(&pool, "bob@test.com", "Bob", "user").await;

    let result = run(
        &pool,
        &std::env::temp_dir(),
        UserCommands::Disable {
            email: "bob@test.com".to_string(),
        },
    )
    .await;
    assert!(result.is_ok());

    let enabled: (bool,) = sqlx::query_as("SELECT enabled FROM users WHERE email = 'bob@test.com'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(!enabled.0, "User should be disabled");
}

#[tokio::test]
async fn test_enable_user() {
    let pool = setup_db().await;
    insert_user(&pool, "bob@test.com", "Bob", "user").await;

    // Disable first
    run(
        &pool,
        &std::env::temp_dir(),
        UserCommands::Disable {
            email: "bob@test.com".to_string(),
        },
    )
    .await
    .unwrap();

    // Then re-enable
    let result = run(
        &pool,
        &std::env::temp_dir(),
        UserCommands::Enable {
            email: "bob@test.com".to_string(),
        },
    )
    .await;
    assert!(result.is_ok());

    let enabled: (bool,) = sqlx::query_as("SELECT enabled FROM users WHERE email = 'bob@test.com'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(enabled.0, "User should be enabled");
}

#[tokio::test]
async fn test_disable_nonexistent_user() {
    let pool = setup_db().await;
    // Should succeed (no error), just print "not found"
    let result = run(
        &pool,
        &std::env::temp_dir(),
        UserCommands::Disable {
            email: "nobody@test.com".to_string(),
        },
    )
    .await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_promote_nonexistent_user() {
    let pool = setup_db().await;
    let result = run(
        &pool,
        &std::env::temp_dir(),
        UserCommands::Promote {
            email: "nobody@test.com".to_string(),
        },
    )
    .await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_delete_user_with_yes_flag() {
    let pool = setup_db().await;
    // Two admins so the LastAdmin guard doesn't fire on Bob.
    insert_user(&pool, "alice@test.com", "Alice", "admin").await;
    insert_user(&pool, "bob@test.com", "Bob", "admin").await;

    let result = run(
        &pool,
        &std::env::temp_dir(),
        UserCommands::Delete {
            email: "bob@test.com".to_string(),
            yes: true,
        },
    )
    .await;
    assert!(result.is_ok());

    let bob_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM users WHERE email = 'bob@test.com'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(bob_count.0, 0, "Bob should be gone");
}

#[tokio::test]
async fn test_delete_nonexistent_user() {
    let pool = setup_db().await;
    // Should not error; just print "not found".
    let result = run(
        &pool,
        &std::env::temp_dir(),
        UserCommands::Delete {
            email: "ghost@test.com".to_string(),
            yes: true,
        },
    )
    .await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_disable_invalidates_sessions() {
    let pool = setup_db().await;
    let user_id = insert_user(&pool, "bob@test.com", "Bob", "user").await;

    // Create a session for Bob
    let session_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, datetime('now', '+30 days'))",
    )
    .bind(&session_id)
    .bind(&user_id)
    .execute(&pool)
    .await
    .unwrap();

    // Disable Bob
    run(
        &pool,
        &std::env::temp_dir(),
        UserCommands::Disable {
            email: "bob@test.com".to_string(),
        },
    )
    .await
    .unwrap();

    // Session should be deleted
    let session_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM sessions WHERE user_id = ?")
        .bind(&user_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(session_count.0, 0, "Sessions should be deleted on disable");
}
