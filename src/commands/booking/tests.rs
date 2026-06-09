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

/// Seed a user, account, and event type. Returns (user_id, account_id, event_type_id).
async fn seed_event_type(pool: &SqlitePool) -> (String, String, String) {
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

    let et_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO event_types (id, account_id, title, slug, duration_min, buffer_before, buffer_after, min_notice_min, enabled)
         VALUES (?, ?, 'Test Meeting', 'test-meeting', 30, 0, 0, 0, 1)",
    )
    .bind(&et_id)
    .bind(&account_id)
    .execute(pool)
    .await
    .unwrap();

    // Add availability Mon-Fri 09:00-17:00
    for day in [1, 2, 3, 4, 5] {
        let rule_id = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO availability_rules (id, event_type_id, day_of_week, start_time, end_time)
             VALUES (?, ?, ?, '09:00', '17:00')",
        )
        .bind(&rule_id)
        .bind(&et_id)
        .bind(day)
        .execute(pool)
        .await
        .unwrap();
    }

    (user_id, account_id, et_id)
}

/// Insert a booking directly into the DB (bypasses interactive prompts and time checks)
async fn insert_booking(
    pool: &SqlitePool,
    et_id: &str,
    guest_name: &str,
    guest_email: &str,
    start: &str,
    end: &str,
    status: &str,
) -> String {
    let id = Uuid::new_v4().to_string();
    let uid = format!("{}@calrs", Uuid::new_v4());
    let cancel_token = Uuid::new_v4().to_string();
    let reschedule_token = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token)
         VALUES (?, ?, ?, ?, ?, 'UTC', ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(et_id)
    .bind(&uid)
    .bind(guest_name)
    .bind(guest_email)
    .bind(start)
    .bind(end)
    .bind(status)
    .bind(&cancel_token)
    .bind(&reschedule_token)
    .execute(pool)
    .await
    .unwrap();
    id
}

#[tokio::test]
async fn test_list_bookings_empty() {
    let pool = setup_db().await;
    let key = [0u8; 32];
    let result = run(&pool, &key, BookingCommands::List { upcoming: false }).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_list_bookings_with_data() {
    let pool = setup_db().await;
    let key = [0u8; 32];
    let (_user_id, _account_id, et_id) = seed_event_type(&pool).await;

    insert_booking(
        &pool,
        &et_id,
        "Alice Guest",
        "alice@guest.com",
        "2026-06-15T10:00:00",
        "2026-06-15T10:30:00",
        "confirmed",
    )
    .await;

    insert_booking(
        &pool,
        &et_id,
        "Bob Guest",
        "bob@guest.com",
        "2026-06-16T14:00:00",
        "2026-06-16T14:30:00",
        "confirmed",
    )
    .await;

    let result = run(&pool, &key, BookingCommands::List { upcoming: false }).await;
    assert!(result.is_ok());

    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM bookings")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count.0, 2);
}

#[tokio::test]
async fn test_list_bookings_upcoming_filter() {
    let pool = setup_db().await;
    let key = [0u8; 32];
    let (_user_id, _account_id, et_id) = seed_event_type(&pool).await;

    // Past booking
    insert_booking(
        &pool,
        &et_id,
        "Past Guest",
        "past@guest.com",
        "2020-01-01T10:00:00",
        "2020-01-01T10:30:00",
        "confirmed",
    )
    .await;

    // Future booking
    insert_booking(
        &pool,
        &et_id,
        "Future Guest",
        "future@guest.com",
        "2030-06-15T10:00:00",
        "2030-06-15T10:30:00",
        "confirmed",
    )
    .await;

    // List upcoming only should succeed (not error out)
    let result = run(&pool, &key, BookingCommands::List { upcoming: true }).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_cancel_nonexistent_booking() {
    let pool = setup_db().await;
    let key = [0u8; 32];
    // Cancelling a non-existent booking should succeed (prints "not found")
    let result = run(
        &pool,
        &key,
        BookingCommands::Cancel {
            id: "nonexistent".to_string(),
        },
    )
    .await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_booking_status_lifecycle() {
    let pool = setup_db().await;
    let (_user_id, _account_id, et_id) = seed_event_type(&pool).await;

    let booking_id = insert_booking(
        &pool,
        &et_id,
        "Lifecycle Guest",
        "life@guest.com",
        "2026-06-15T10:00:00",
        "2026-06-15T10:30:00",
        "confirmed",
    )
    .await;

    // Verify initial status
    let status: (String,) = sqlx::query_as("SELECT status FROM bookings WHERE id = ?")
        .bind(&booking_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status.0, "confirmed");

    // Cancel directly via SQL (since Cancel command requires interactive prompt)
    sqlx::query("UPDATE bookings SET status = 'cancelled' WHERE id = ?")
        .bind(&booking_id)
        .execute(&pool)
        .await
        .unwrap();

    let status: (String,) = sqlx::query_as("SELECT status FROM bookings WHERE id = ?")
        .bind(&booking_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status.0, "cancelled");
}

#[tokio::test]
async fn test_double_booking_prevention() {
    let pool = setup_db().await;
    let (_user_id, _account_id, et_id) = seed_event_type(&pool).await;

    // First booking succeeds
    insert_booking(
        &pool,
        &et_id,
        "Guest 1",
        "g1@test.com",
        "2026-06-15T10:00:00",
        "2026-06-15T10:30:00",
        "confirmed",
    )
    .await;

    // Second booking at the same time should fail (partial unique index)
    let id2 = Uuid::new_v4().to_string();
    let result = sqlx::query(
        "INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token)
         VALUES (?, ?, ?, 'Guest 2', 'g2@test.com', 'UTC', '2026-06-15T10:00:00', '2026-06-15T10:30:00', 'confirmed', ?, ?)",
    )
    .bind(&id2)
    .bind(&et_id)
    .bind(format!("{}@calrs", Uuid::new_v4()))
    .bind(Uuid::new_v4().to_string())
    .bind(Uuid::new_v4().to_string())
    .execute(&pool)
    .await;

    assert!(
        result.is_err(),
        "Double booking at the same time/event_type should be prevented by unique index"
    );
}
