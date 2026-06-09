use super::*;

#[test]
fn expand_pattern_replaces_known_tokens() {
    let tokens = PatternTokens {
        username: "alice",
        event_slug: "intro-call",
        start_at: "2026-06-05T10:00:00",
    };
    let out = expand_pattern("{username}-{event}-{date}", &tokens);
    assert_eq!(out, "alice-intro-call-20260605");
}

#[test]
fn expand_pattern_keeps_unknown_tokens_verbatim() {
    let tokens = PatternTokens {
        username: "alice",
        event_slug: "x",
        start_at: "2026-06-05",
    };
    let out = expand_pattern("hello-{foo}-{username}", &tokens);
    assert_eq!(out, "hello-{foo}-alice");
}

#[test]
fn expand_pattern_random_is_8_alphanumeric() {
    let tokens = PatternTokens {
        username: "a",
        event_slug: "b",
        start_at: "2026-06-05",
    };
    let out = expand_pattern("{random}", &tokens);
    assert_eq!(out.len(), 8);
    assert!(out
        .chars()
        .all(|c| c.is_ascii_alphanumeric() && !c.is_ascii_uppercase()));
}

#[test]
fn expand_pattern_unterminated_brace_kept() {
    let tokens = PatternTokens {
        username: "a",
        event_slug: "b",
        start_at: "2026-06-05",
    };
    let out = expand_pattern("oops-{username", &tokens);
    assert_eq!(out, "oops-{username");
}

#[test]
fn sanitize_room_strips_unsafe_chars() {
    assert_eq!(sanitize_room("Alice O'Brien"), "aliceobrien");
    assert_eq!(sanitize_room("../etc/passwd"), "etcpasswd");
    assert_eq!(sanitize_room(""), "x");
    assert_eq!(sanitize_room("a_b-c"), "a_b-c");
    // Curly braces survive so an unknown placeholder like `{foo}` stays
    // visible in the URL rather than being silently swallowed.
    assert_eq!(sanitize_room("hello {foo}"), "hello{foo}");
}

#[test]
fn expand_pattern_sanitizes_pattern_literal() {
    // The pattern itself (not just the token values) is settable from the
    // per-event-type override form, so any `?`, `#`, space or unicode in
    // the literal must be stripped before it lands in a URL.
    let tokens = PatternTokens {
        username: "alice",
        event_slug: "intro",
        start_at: "2026-06-05",
    };
    let out = expand_pattern("intro call ?session#{username}", &tokens);
    assert_eq!(out, "introcallsessionalice");
}

#[test]
fn extract_date_handles_iso_with_t() {
    assert_eq!(extract_date("2026-06-05T10:00:00"), "20260605");
}

#[test]
fn extract_date_handles_iso_with_space() {
    assert_eq!(extract_date("2026-06-05 10:00:00"), "20260605");
}

#[test]
fn extract_date_rejects_bad_input() {
    // Short and non-numeric inputs are rejected. The function does not
    // enforce a specific separator between Y/M/D — `bookings.start_at`
    // is always written in `YYYY-MM-DDTHH:MM:SS` form by calrs itself.
    assert_eq!(extract_date("nope"), "");
    assert_eq!(extract_date("short"), "");
    assert_eq!(extract_date("abcd-ef-gh"), "");
}

#[test]
fn build_jitsi_url_uses_override_when_set() {
    let cfg = JitsiConfig {
        base_url: "https://meet.dyb.fr".to_string(),
        pattern: "{event}-{random}".to_string(),
        display_name: None,
    };
    let tokens = PatternTokens {
        username: "alice",
        event_slug: "intro",
        start_at: "2026-06-05",
    };
    let url = build_jitsi_url(&cfg, Some("custom-{username}"), &tokens);
    assert_eq!(url, "https://meet.dyb.fr/custom-alice");
}

#[test]
fn build_jitsi_url_falls_back_to_default_pattern() {
    let cfg = JitsiConfig {
        base_url: "https://meet.dyb.fr/".to_string(),
        pattern: String::new(),
        display_name: None,
    };
    let tokens = PatternTokens {
        username: "alice",
        event_slug: "intro",
        start_at: "2026-06-05",
    };
    let url = build_jitsi_url(&cfg, None, &tokens);
    // default pattern is "{event}-{random}" → "intro-<8 chars>"
    assert!(url.starts_with("https://meet.dyb.fr/intro-"));
    assert_eq!(url.len(), "https://meet.dyb.fr/intro-".len() + 8);
}

#[test]
fn hmac_sha256_known_vector() {
    // RFC 4231 test case 1
    let key = b"\x0b".repeat(20);
    let data = b"Hi There";
    let sig = sign_hmac_sha256(&key, data);
    assert_eq!(
        sig,
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );
}

#[test]
fn random_alphanumeric_lengths() {
    assert_eq!(random_alphanumeric(0).len(), 0);
    assert_eq!(random_alphanumeric(1).len(), 1);
    assert_eq!(random_alphanumeric(32).len(), 32);
}

#[test]
fn webhook_auth_mode_roundtrip() {
    assert_eq!(WebhookAuthMode::from_str("hmac").as_str(), "hmac");
    assert_eq!(WebhookAuthMode::from_str("none").as_str(), "none");
    assert_eq!(WebhookAuthMode::from_str("").as_str(), "none");
    assert_eq!(WebhookAuthMode::from_str("garbage").as_str(), "none");
}

use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::str::FromStr;

async fn memory_pool_migrated() -> SqlitePool {
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

/// Minimal seed for the user / account / event_type / booking chain used
/// by the reminder query. Returns (booking_id, event_type_id).
async fn seed_auto_provider_booking(
    pool: &SqlitePool,
    meeting_url: Option<&str>,
    static_location_value: &str,
) -> (String, String) {
    let user_id = uuid::Uuid::new_v4().to_string();
    let account_id = uuid::Uuid::new_v4().to_string();
    let event_type_id = uuid::Uuid::new_v4().to_string();
    let booking_id = uuid::Uuid::new_v4().to_string();

    sqlx::query(
        "INSERT INTO users (id, email, name, role, auth_provider) \
         VALUES (?, ?, ?, 'user', 'local')",
    )
    .bind(&user_id)
    .bind("alice@example.com")
    .bind("Alice")
    .execute(pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO accounts (id, user_id, name, email, timezone) \
         VALUES (?, ?, ?, ?, 'UTC')",
    )
    .bind(&account_id)
    .bind(&user_id)
    .bind("Alice")
    .bind("alice@example.com")
    .execute(pool)
    .await
    .unwrap();

    // location_type=jitsi_auto + location_value left as a static fallback
    // string so we can prove the COALESCE prefers meeting_url over it.
    // reminder_minutes is set so the reminder predicate would match.
    sqlx::query(
        "INSERT INTO event_types (id, account_id, slug, title, duration_min, \
         location_type, location_value, reminder_minutes) \
         VALUES (?, ?, 'intro', 'Intro', 30, 'jitsi_auto', ?, 10)",
    )
    .bind(&event_type_id)
    .bind(&account_id)
    .bind(static_location_value)
    .execute(pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, \
         guest_timezone, start_at, end_at, status, cancel_token, reschedule_token, \
         meeting_url) \
         VALUES (?, ?, ?, 'Bob', 'bob@example.com', 'UTC', \
         datetime('now', '+1 hour'), datetime('now', '+90 minutes'), \
         'confirmed', ?, ?, ?)",
    )
    .bind(&booking_id)
    .bind(&event_type_id)
    .bind(format!("{}@calrs", booking_id))
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(meeting_url)
    .execute(pool)
    .await
    .unwrap();

    (booking_id, event_type_id)
}

/// Regression test for the owner's review of PR #45-followup: the
/// reminder loop must read the per-booking `meeting_url` (set by
/// `generate_and_persist` for jitsi_auto / webhook_auto event types),
/// not the empty `event_types.location_value`. Before the fix the
/// reminder went out with no meeting link.
#[tokio::test]
async fn reminder_query_prefers_meeting_url_over_location_value() {
    let pool = memory_pool_migrated().await;
    let (_bid, _et) = seed_auto_provider_booking(
        &pool,
        Some("https://meet.dyb.fr/intro-abc12345"),
        "", // location_value empty as it would be for an auto provider
    )
    .await;

    // Same projection the reminder loop uses for `location_value`.
    let location: Option<String> = sqlx::query_scalar(
        "SELECT COALESCE(NULLIF(b.meeting_url, ''), et.location_value) \
         FROM bookings b \
         JOIN event_types et ON et.id = b.event_type_id \
         WHERE b.status = 'confirmed'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(
        location.as_deref(),
        Some("https://meet.dyb.fr/intro-abc12345"),
        "reminder query must surface bookings.meeting_url, not the empty event_types.location_value"
    );
}

/// Confirms the COALESCE falls back to the static value when no auto URL
/// has been persisted, so static-location event types still get a link.
#[tokio::test]
async fn reminder_query_falls_back_to_location_value() {
    let pool = memory_pool_migrated().await;
    let (_bid, _et) =
        seed_auto_provider_booking(&pool, None, "https://meet.example.com/static-room").await;

    let location: Option<String> = sqlx::query_scalar(
        "SELECT COALESCE(NULLIF(b.meeting_url, ''), et.location_value) \
         FROM bookings b \
         JOIN event_types et ON et.id = b.event_type_id \
         WHERE b.status = 'confirmed'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(
        location.as_deref(),
        Some("https://meet.example.com/static-room")
    );
}

/// `generate_and_persist` must be idempotent — re-calling it on a booking
/// that already has `meeting_url` set must return the stored URL rather
/// than rotating the `{random}` segment. Locks in the race-avoidance
/// guarantee called out in the PR review.
#[tokio::test]
async fn generate_and_persist_is_idempotent() {
    let pool = memory_pool_migrated().await;
    let preset = "https://meet.dyb.fr/intro-already-there";
    let (booking_id, event_type_id) = seed_auto_provider_booking(&pool, Some(preset), "").await;

    let key = [0u8; 32];
    // No jitsi config / webhook config is set up at all — if the function
    // were not idempotent it would return None here and never produce the
    // URL. Because `meeting_url` is already populated it must short-circuit
    // and return the stored value before touching any provider.
    let url = generate_and_persist(
        &pool,
        &key,
        &booking_id,
        &event_type_id,
        None,
        "Bob",
        "bob@example.com",
    )
    .await;

    assert_eq!(url.as_deref(), Some(preset));
}
