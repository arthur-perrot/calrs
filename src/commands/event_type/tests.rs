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

/// Seed a user + account so event_type create can find an account
async fn seed_account(pool: &SqlitePool) -> (String, String) {
    let user_id = Uuid::new_v4().to_string();
    let username = crate::auth::generate_username(pool, "host@test.com")
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO users (id, email, name, timezone, role, auth_provider, username, enabled)
         VALUES (?, 'host@test.com', 'Host', 'UTC', 'admin', 'local', ?, 1)",
    )
    .bind(&user_id)
    .bind(&username)
    .execute(pool)
    .await
    .unwrap();

    let account_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO accounts (id, name, email, timezone, user_id) VALUES (?, 'Host', 'host@test.com', 'UTC', ?)",
    )
    .bind(&account_id)
    .bind(&user_id)
    .execute(pool)
    .await
    .unwrap();

    (user_id, account_id)
}

#[tokio::test]
async fn test_create_event_type() {
    let pool = setup_db().await;
    seed_account(&pool).await;

    let result = run(
        &pool,
        EventTypeCommands::Create {
            title: "30min Call".to_string(),
            slug: "intro".to_string(),
            duration: 30,
            description: Some("A quick intro call".to_string()),
            buffer_before: 5,
            buffer_after: 5,
        },
    )
    .await;
    assert!(result.is_ok());

    // Verify event type was created
    let et: (String, String, i32, i32, i32) = sqlx::query_as(
        "SELECT title, slug, duration_min, buffer_before, buffer_after FROM event_types WHERE slug = 'intro'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(et.0, "30min Call");
    assert_eq!(et.1, "intro");
    assert_eq!(et.2, 30);
    assert_eq!(et.3, 5);
    assert_eq!(et.4, 5);
}

#[tokio::test]
async fn test_create_event_type_default_availability() {
    let pool = setup_db().await;
    seed_account(&pool).await;

    run(
        &pool,
        EventTypeCommands::Create {
            title: "Meeting".to_string(),
            slug: "meeting".to_string(),
            duration: 60,
            description: None,
            buffer_before: 0,
            buffer_after: 0,
        },
    )
    .await
    .unwrap();

    // Should have 5 availability rules (Mon-Fri)
    let rules: Vec<(i32, String, String)> = sqlx::query_as(
        "SELECT day_of_week, start_time, end_time FROM availability_rules
         WHERE event_type_id = (SELECT id FROM event_types WHERE slug = 'meeting')
         ORDER BY day_of_week",
    )
    .fetch_all(&pool)
    .await
    .unwrap();

    assert_eq!(rules.len(), 5, "Should have Mon-Fri availability rules");
    // Days 1-5 = Mon-Fri
    for (i, (day, start, end)) in rules.iter().enumerate() {
        assert_eq!(*day, (i + 1) as i32);
        assert_eq!(start, "09:00");
        assert_eq!(end, "17:00");
    }
}

#[tokio::test]
async fn test_create_event_type_no_account() {
    let pool = setup_db().await;
    // No account seeded — should fail
    let result = run(
        &pool,
        EventTypeCommands::Create {
            title: "Test".to_string(),
            slug: "test".to_string(),
            duration: 30,
            description: None,
            buffer_before: 0,
            buffer_after: 0,
        },
    )
    .await;
    assert!(result.is_err(), "Should fail without an account");
}

#[tokio::test]
async fn test_list_event_types_empty() {
    let pool = setup_db().await;
    let result = run(&pool, EventTypeCommands::List).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_list_event_types() {
    let pool = setup_db().await;
    seed_account(&pool).await;

    // Create two event types
    run(
        &pool,
        EventTypeCommands::Create {
            title: "Quick Chat".to_string(),
            slug: "quick".to_string(),
            duration: 15,
            description: None,
            buffer_before: 0,
            buffer_after: 0,
        },
    )
    .await
    .unwrap();

    run(
        &pool,
        EventTypeCommands::Create {
            title: "Deep Dive".to_string(),
            slug: "deep".to_string(),
            duration: 60,
            description: None,
            buffer_before: 0,
            buffer_after: 0,
        },
    )
    .await
    .unwrap();

    let result = run(&pool, EventTypeCommands::List).await;
    assert!(result.is_ok());

    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM event_types")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count.0, 2);
}

#[tokio::test]
async fn test_create_duplicate_slug_fails() {
    let pool = setup_db().await;
    seed_account(&pool).await;

    run(
        &pool,
        EventTypeCommands::Create {
            title: "First".to_string(),
            slug: "same-slug".to_string(),
            duration: 30,
            description: None,
            buffer_before: 0,
            buffer_after: 0,
        },
    )
    .await
    .unwrap();

    // Second with same slug should fail (UNIQUE constraint)
    let result = run(
        &pool,
        EventTypeCommands::Create {
            title: "Second".to_string(),
            slug: "same-slug".to_string(),
            duration: 30,
            description: None,
            buffer_before: 0,
            buffer_after: 0,
        },
    )
    .await;
    assert!(result.is_err(), "Duplicate slug should fail");
}
