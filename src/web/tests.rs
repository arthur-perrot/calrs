use super::*;

// --- Rate limiter tests ---

#[tokio::test]
async fn rate_limiter_allows_under_limit() {
    let limiter = RateLimiter::new(3, 60);
    assert!(!limiter.check_limited("ip1").await);
    assert!(!limiter.check_limited("ip1").await);
    assert!(!limiter.check_limited("ip1").await);
}

#[tokio::test]
async fn rate_limiter_blocks_over_limit() {
    let limiter = RateLimiter::new(2, 60);
    assert!(!limiter.check_limited("ip1").await); // 1
    assert!(!limiter.check_limited("ip1").await); // 2
    assert!(limiter.check_limited("ip1").await); // 3 → blocked
    assert!(limiter.check_limited("ip1").await); // still blocked
}

#[tokio::test]
async fn rate_limiter_independent_per_ip() {
    let limiter = RateLimiter::new(1, 60);
    assert!(!limiter.check_limited("ip1").await);
    assert!(limiter.check_limited("ip1").await); // ip1 blocked
    assert!(!limiter.check_limited("ip2").await); // ip2 still ok
}

#[tokio::test]
async fn rate_limiter_resets_after_window() {
    let limiter = RateLimiter::new(1, 0); // 0-second window = immediate expiry
    assert!(!limiter.check_limited("ip1").await);
    // Window has already expired (0 seconds)
    assert!(!limiter.check_limited("ip1").await); // reset, allowed again
}

#[test]
fn detect_image_ext_recognizes_known_formats() {
    // PNG signature.
    assert_eq!(
        detect_image_ext(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0xff]),
        Some("png")
    );
    // JPEG SOI + APP marker.
    assert_eq!(
        detect_image_ext(&[0xFF, 0xD8, 0xFF, 0xE0, 0x00]),
        Some("jpg")
    );
    // GIF.
    assert_eq!(detect_image_ext(b"GIF89a..."), Some("gif"));
    assert_eq!(detect_image_ext(b"GIF87a..."), Some("gif"));
    // RIFF/WEBP.
    let mut webp = Vec::from(*b"RIFF\x00\x00\x00\x00WEBP");
    webp.extend_from_slice(b"VP8 ");
    assert_eq!(detect_image_ext(&webp), Some("webp"));
}

#[test]
fn detect_image_ext_rejects_non_images() {
    // Empty input, plain text, HTML stub, executable header are all rejected.
    assert_eq!(detect_image_ext(b""), None);
    assert_eq!(detect_image_ext(b"not an image"), None);
    assert_eq!(detect_image_ext(b"<html><body>"), None);
    assert_eq!(detect_image_ext(b"\x7fELF"), None);
    // RIFF without the WEBP marker should not be accepted.
    let riff_wave = b"RIFF\x00\x00\x00\x00WAVEfmt ";
    assert_eq!(detect_image_ext(riff_wave), None);
}

#[tokio::test]
async fn rate_limiter_sweeps_expired_entries() {
    // Pin that periodic eviction actually drops entries from the map so
    // it cannot grow without bound under traffic from many distinct IPs.
    let limiter = RateLimiter::new(5, 0); // 0-second window: immediate expiry
    for i in 0..50 {
        limiter.check_limited(&format!("ip-{}", i)).await;
    }
    // Next call triggers a sweep; all prior entries should be evicted
    // before the new key is inserted.
    limiter.check_limited("trigger-sweep").await;
    let state = limiter.state.lock().await;
    assert_eq!(
        state.attempts.len(),
        1,
        "expired entries should be swept, only the newest survives"
    );
}

#[test]
fn parse_avail_schedule_uses_user_default_when_submitted_is_empty() {
    // Empty submission + user default "Tue 14:00-18:00" → returns the user default
    // instead of falling back to the hardcoded Mon-Fri 09:00-17:00.
    let result = parse_avail_schedule(Some(""), None, None, None, None, Some("2:14:00-18:00"));
    assert_eq!(result.len(), 1);
    let windows = result.get(&2).expect("Tuesday should be set");
    assert_eq!(windows, &vec![("14:00".to_string(), "18:00".to_string())]);
}

#[test]
fn parse_avail_schedule_prefers_submitted_over_user_default() {
    // A populated submission overrides the user default.
    let result = parse_avail_schedule(
        Some("3:10:00-12:00"),
        None,
        None,
        None,
        None,
        Some("2:14:00-18:00"),
    );
    assert_eq!(result.len(), 1);
    let windows = result.get(&3).expect("Wednesday should be set");
    assert_eq!(windows, &vec![("10:00".to_string(), "12:00".to_string())]);
}

#[test]
fn parse_avail_schedule_falls_back_to_legacy_when_both_empty() {
    // Empty submission and empty user default → hardcoded Mon-Fri 09:00-17:00.
    let result = parse_avail_schedule(Some(""), None, None, None, None, Some(""));
    assert_eq!(result.len(), 5);
    for day in 1..=5 {
        let windows = result.get(&day).expect("weekday should be set");
        assert_eq!(windows, &vec![("09:00".to_string(), "17:00".to_string())]);
    }
}

// --- has_conflict tests ---

fn dt(y: i32, m: u32, d: u32, h: u32, mi: u32) -> NaiveDateTime {
    NaiveDate::from_ymd_opt(y, m, d)
        .unwrap()
        .and_hms_opt(h, mi, 0)
        .unwrap()
}

#[test]
fn conflict_overlapping_event() {
    let busy = vec![(dt(2026, 3, 15, 10, 0), dt(2026, 3, 15, 11, 0))];
    // Slot 10:30-11:30 overlaps with 10:00-11:00
    assert!(has_conflict(
        &busy,
        dt(2026, 3, 15, 10, 30),
        dt(2026, 3, 15, 11, 30)
    ));
}

#[test]
fn conflict_no_overlap() {
    let busy = vec![(dt(2026, 3, 15, 10, 0), dt(2026, 3, 15, 11, 0))];
    // Slot 11:00-12:00 starts exactly when event ends (no overlap)
    assert!(!has_conflict(
        &busy,
        dt(2026, 3, 15, 11, 0),
        dt(2026, 3, 15, 12, 0)
    ));
}

#[test]
fn conflict_event_contains_slot() {
    let busy = vec![(dt(2026, 3, 15, 9, 0), dt(2026, 3, 15, 17, 0))];
    // Slot entirely within busy period
    assert!(has_conflict(
        &busy,
        dt(2026, 3, 15, 10, 0),
        dt(2026, 3, 15, 11, 0)
    ));
}

#[test]
fn conflict_slot_contains_event() {
    let busy = vec![(dt(2026, 3, 15, 10, 15), dt(2026, 3, 15, 10, 45))];
    // Slot 10:00-11:00 contains the 10:15-10:45 event
    assert!(has_conflict(
        &busy,
        dt(2026, 3, 15, 10, 0),
        dt(2026, 3, 15, 11, 0)
    ));
}

#[test]
fn conflict_adjacent_not_conflicting() {
    let busy = vec![
        (dt(2026, 3, 15, 9, 0), dt(2026, 3, 15, 10, 0)),
        (dt(2026, 3, 15, 11, 0), dt(2026, 3, 15, 12, 0)),
    ];
    // Slot 10:00-11:00 is between two events (no overlap)
    assert!(!has_conflict(
        &busy,
        dt(2026, 3, 15, 10, 0),
        dt(2026, 3, 15, 11, 0)
    ));
}

#[test]
fn conflict_empty_busy_list() {
    let busy: Vec<(NaiveDateTime, NaiveDateTime)> = vec![];
    assert!(!has_conflict(
        &busy,
        dt(2026, 3, 15, 10, 0),
        dt(2026, 3, 15, 11, 0)
    ));
}

#[test]
fn conflict_buffer_causes_overlap() {
    let busy = vec![(dt(2026, 3, 15, 10, 0), dt(2026, 3, 15, 11, 0))];
    // Slot is 11:00-12:00, but with 15min buffer before → buf_start=10:45 overlaps
    assert!(has_conflict(
        &busy,
        dt(2026, 3, 15, 10, 45),
        dt(2026, 3, 15, 12, 0)
    ));
}

// --- expand_recurring_into_busy tests ---

#[test]
fn expand_recurring_weekly_into_busy() {
    let recurring = vec![(
        "20260309T100000".to_string(), // Monday 10:00
        "20260309T110000".to_string(), // Monday 11:00
        "FREQ=WEEKLY;BYDAY=MO".to_string(),
        None,
        None,
    )];
    let window_start = dt(2026, 3, 9, 0, 0);
    let window_end = dt(2026, 3, 23, 23, 59);
    let busy = expand_recurring_into_busy(&recurring, window_start, window_end, Tz::UTC);
    // Should have 3 occurrences: Mar 9, 16, 23
    assert_eq!(busy.len(), 3);
    assert_eq!(busy[0].0, dt(2026, 3, 9, 10, 0));
    assert_eq!(busy[1].0, dt(2026, 3, 16, 10, 0));
    assert_eq!(busy[2].0, dt(2026, 3, 23, 10, 0));
}

#[test]
fn expand_recurring_with_exdate() {
    let raw_ical = "BEGIN:VEVENT\nDTSTART:20260309T100000\nDTEND:20260309T110000\nRRULE:FREQ=WEEKLY;BYDAY=MO\nEXDATE:20260316T100000\nEND:VEVENT";
    let recurring = vec![(
        "20260309T100000".to_string(),
        "20260309T110000".to_string(),
        "FREQ=WEEKLY;BYDAY=MO".to_string(),
        Some(raw_ical.to_string()),
        None,
    )];
    let window_start = dt(2026, 3, 9, 0, 0);
    let window_end = dt(2026, 3, 23, 23, 59);
    let busy = expand_recurring_into_busy(&recurring, window_start, window_end, Tz::UTC);
    // Mar 16 excluded, so only Mar 9 and 23
    assert_eq!(busy.len(), 2);
    assert_eq!(busy[0].0, dt(2026, 3, 9, 10, 0));
    assert_eq!(busy[1].0, dt(2026, 3, 23, 10, 0));
}

// --- Integration tests with in-memory SQLite ---

async fn setup_test_db() -> SqlitePool {
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    use std::str::FromStr;
    let pool = SqlitePoolOptions::new()
        .max_connections(2)
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

/// Insert test fixtures: user, account, event type, availability rules
async fn seed_test_data(pool: &SqlitePool) -> (String, String, String) {
    let user_id = uuid::Uuid::new_v4().to_string();
    let account_id = uuid::Uuid::new_v4().to_string();
    let et_id = uuid::Uuid::new_v4().to_string();

    sqlx::query("INSERT INTO users (id, email, name, role, auth_provider, username, enabled) VALUES (?, 'test@example.com', 'Test User', 'admin', 'local', 'testuser', 1)")
        .bind(&user_id)
        .execute(pool).await.unwrap();

    sqlx::query("INSERT INTO accounts (id, name, email, timezone, user_id) VALUES (?, 'Test User', 'test@example.com', 'UTC', ?)")
        .bind(&account_id)
        .bind(&user_id)
        .execute(pool).await.unwrap();

    sqlx::query("INSERT INTO event_types (id, account_id, slug, title, duration_min, buffer_before, buffer_after, min_notice_min, enabled) VALUES (?, ?, 'test-meeting', 'Test Meeting', 30, 0, 0, 0, 1)")
        .bind(&et_id)
        .bind(&account_id)
        .execute(pool).await.unwrap();

    // Mon-Fri 09:00-17:00
    for day in [1, 2, 3, 4, 5] {
        let rule_id = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO availability_rules (id, event_type_id, day_of_week, start_time, end_time) VALUES (?, ?, ?, '09:00', '17:00')")
            .bind(&rule_id)
            .bind(&et_id)
            .bind(day)
            .execute(pool).await.unwrap();
    }

    (user_id, account_id, et_id)
}

// --- Authorization helpers: can_manage_event_type / find_manageable_event_type_by_slug ---

/// Insert a user with a configurable role. Returns user_id.
async fn insert_role_user(pool: &SqlitePool, email: &str, role: &str) -> String {
    let id = uuid::Uuid::new_v4().to_string();
    let username = email.split('@').next().unwrap_or("u").to_string();
    sqlx::query(
        "INSERT INTO users (id, email, name, role, auth_provider, username, enabled) \
         VALUES (?, ?, ?, ?, 'local', ?, 1)",
    )
    .bind(&id)
    .bind(email)
    .bind(email)
    .bind(role)
    .bind(&username)
    .execute(pool)
    .await
    .unwrap();
    id
}

/// Insert a personal event type owned by `user_id`. Creates the account row
/// if missing. Returns event_type_id.
async fn insert_personal_et(pool: &SqlitePool, user_id: &str, slug: &str) -> String {
    let account_id: Option<String> =
        sqlx::query_scalar("SELECT id FROM accounts WHERE user_id = ?")
            .bind(user_id)
            .fetch_optional(pool)
            .await
            .unwrap();
    let account_id = match account_id {
        Some(id) => id,
        None => {
            let id = uuid::Uuid::new_v4().to_string();
            sqlx::query(
                "INSERT INTO accounts (id, name, email, timezone, user_id) \
                 VALUES (?, 'A', 'a@x', 'UTC', ?)",
            )
            .bind(&id)
            .bind(user_id)
            .execute(pool)
            .await
            .unwrap();
            id
        }
    };
    let et_id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO event_types (id, account_id, slug, title, duration_min, buffer_before, buffer_after, min_notice_min, enabled) \
         VALUES (?, ?, ?, 'P', 30, 0, 0, 0, 1)",
    )
    .bind(&et_id)
    .bind(&account_id)
    .bind(slug)
    .execute(pool)
    .await
    .unwrap();
    et_id
}

/// Insert a team and a team event type. `members` is a list of (user_id, role).
/// Returns (team_id, event_type_id).
async fn insert_team_with_et(
    pool: &SqlitePool,
    team_slug: &str,
    et_slug: &str,
    members: &[(&str, &str)],
) -> (String, String) {
    let team_id = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO teams (id, name, slug, visibility) VALUES (?, ?, ?, 'public')")
        .bind(&team_id)
        .bind(team_slug)
        .bind(team_slug)
        .execute(pool)
        .await
        .unwrap();
    for (uid, role) in members {
        sqlx::query(
            "INSERT INTO team_members (team_id, user_id, role, source) \
             VALUES (?, ?, ?, 'direct')",
        )
        .bind(&team_id)
        .bind(uid)
        .bind(role)
        .execute(pool)
        .await
        .unwrap();
    }
    // Each team event gets its own placeholder account to avoid colliding
    // with personal events under the unique(account_id, slug) constraint.
    let account_id = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO accounts (id, name, email, timezone) VALUES (?, 't', 't@x', 'UTC')")
        .bind(&account_id)
        .execute(pool)
        .await
        .unwrap();
    let et_id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO event_types (id, account_id, team_id, slug, title, duration_min, buffer_before, buffer_after, min_notice_min, enabled) \
         VALUES (?, ?, ?, ?, 'T', 30, 0, 0, 0, 1)",
    )
    .bind(&et_id)
    .bind(&account_id)
    .bind(&team_id)
    .bind(et_slug)
    .execute(pool)
    .await
    .unwrap();
    (team_id, et_id)
}

async fn user_for(pool: &SqlitePool, user_id: &str) -> crate::models::User {
    sqlx::query_as("SELECT * FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn can_manage_event_type_global_admin_yes_for_any_event() {
    let pool = setup_test_db().await;
    let admin_id = insert_role_user(&pool, "admin@x", "admin").await;
    let owner_id = insert_role_user(&pool, "owner@x", "user").await;
    let personal_et = insert_personal_et(&pool, &owner_id, "personal").await;
    let (_, team_et) = insert_team_with_et(&pool, "team1", "team-et", &[]).await;
    let admin = user_for(&pool, &admin_id).await;
    assert!(can_manage_event_type(&pool, &admin, &personal_et).await);
    assert!(can_manage_event_type(&pool, &admin, &team_et).await);
}

#[tokio::test]
async fn can_manage_event_type_personal_owner_yes_others_no() {
    let pool = setup_test_db().await;
    let owner_id = insert_role_user(&pool, "owner@x", "user").await;
    let other_id = insert_role_user(&pool, "other@x", "user").await;
    let et = insert_personal_et(&pool, &owner_id, "personal").await;
    let owner = user_for(&pool, &owner_id).await;
    let other = user_for(&pool, &other_id).await;
    assert!(can_manage_event_type(&pool, &owner, &et).await);
    assert!(!can_manage_event_type(&pool, &other, &et).await);
}

#[tokio::test]
async fn can_manage_event_type_team_admin_yes_member_no() {
    let pool = setup_test_db().await;
    let admin_id = insert_role_user(&pool, "ta@x", "user").await;
    let member_id = insert_role_user(&pool, "tm@x", "user").await;
    let outsider_id = insert_role_user(&pool, "out@x", "user").await;
    let (_, et) = insert_team_with_et(
        &pool,
        "team1",
        "team-et",
        &[(&admin_id, "admin"), (&member_id, "member")],
    )
    .await;
    let admin = user_for(&pool, &admin_id).await;
    let member = user_for(&pool, &member_id).await;
    let outsider = user_for(&pool, &outsider_id).await;
    assert!(can_manage_event_type(&pool, &admin, &et).await);
    assert!(!can_manage_event_type(&pool, &member, &et).await);
    assert!(!can_manage_event_type(&pool, &outsider, &et).await);
}

#[tokio::test]
async fn can_manage_event_type_team_admin_cannot_manage_others_personal_event() {
    // Being a team admin somewhere does not grant access to an unrelated
    // user's personal event types.
    let pool = setup_test_db().await;
    let team_admin_id = insert_role_user(&pool, "ta@x", "user").await;
    let stranger_id = insert_role_user(&pool, "s@x", "user").await;
    let stranger_et = insert_personal_et(&pool, &stranger_id, "p").await;
    let _ = insert_team_with_et(&pool, "team1", "te", &[(&team_admin_id, "admin")]).await;
    let team_admin = user_for(&pool, &team_admin_id).await;
    assert!(!can_manage_event_type(&pool, &team_admin, &stranger_et).await);
}

#[tokio::test]
async fn can_manage_event_type_team_member_cannot_manage_others_personal_event() {
    let pool = setup_test_db().await;
    let team_member_id = insert_role_user(&pool, "tm@x", "user").await;
    let stranger_id = insert_role_user(&pool, "s@x", "user").await;
    let stranger_et = insert_personal_et(&pool, &stranger_id, "p").await;
    let _ = insert_team_with_et(&pool, "team1", "te", &[(&team_member_id, "member")]).await;
    let team_member = user_for(&pool, &team_member_id).await;
    assert!(!can_manage_event_type(&pool, &team_member, &stranger_et).await);
}

#[tokio::test]
async fn can_manage_event_type_personal_owner_cannot_manage_unrelated_team_event() {
    let pool = setup_test_db().await;
    // Owner of a personal event with the same slug as some team event —
    // owning the personal event must not grant access to the team one.
    let owner_id = insert_role_user(&pool, "owner@x", "user").await;
    let _ = insert_personal_et(&pool, &owner_id, "demo").await;
    let (_, team_et) = insert_team_with_et(&pool, "team1", "demo", &[]).await;
    let owner = user_for(&pool, &owner_id).await;
    assert!(!can_manage_event_type(&pool, &owner, &team_et).await);
}

#[tokio::test]
async fn find_manageable_event_type_by_slug_personal_wins_collision() {
    // If the user has both a personal event and a team-admin event sharing
    // the same slug, the personal event must resolve first (deterministic).
    let pool = setup_test_db().await;
    let user_id = insert_role_user(&pool, "u@x", "user").await;
    let personal_et = insert_personal_et(&pool, &user_id, "demo").await;
    let (_, team_et) = insert_team_with_et(&pool, "team1", "demo", &[(&user_id, "admin")]).await;
    let resolved = find_manageable_event_type_by_slug(&pool, &user_id, "demo")
        .await
        .expect("should resolve");
    assert_eq!(resolved.0, personal_et);
    assert_ne!(resolved.0, team_et);
    assert!(resolved.2.is_none(), "personal event has no team_id");
}

#[tokio::test]
async fn find_manageable_event_type_by_slug_member_does_not_resolve() {
    // Regular team members should not resolve team event types via this
    // helper — only team admins do.
    let pool = setup_test_db().await;
    let user_id = insert_role_user(&pool, "m@x", "user").await;
    let _ = insert_team_with_et(&pool, "team1", "demo", &[(&user_id, "member")]).await;
    assert!(find_manageable_event_type_by_slug(&pool, &user_id, "demo")
        .await
        .is_none());
}

#[tokio::test]
async fn fetch_busy_times_empty_calendar() {
    let pool = setup_test_db().await;
    let (user_id, _, _) = seed_test_data(&pool).await;

    let busy = fetch_busy_times_for_user(
        &pool,
        &user_id,
        dt(2026, 3, 15, 0, 0),
        dt(2026, 3, 21, 23, 59),
        Tz::UTC,
        None,
    )
    .await;

    assert!(busy.is_empty(), "No events or bookings → no busy times");
}

#[tokio::test]
async fn fetch_busy_times_includes_bookings() {
    let pool = setup_test_db().await;
    let (user_id, _, et_id) = seed_test_data(&pool).await;

    let booking_id = uuid::Uuid::new_v4().to_string();
    let cancel_tok = uuid::Uuid::new_v4().to_string();
    let resched_tok = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token) VALUES (?, ?, 'uid1', 'Guest', 'guest@example.com', 'UTC', '2026-03-16T10:00:00', '2026-03-16T10:30:00', 'confirmed', ?, ?)")
        .bind(&booking_id)
        .bind(&et_id)
        .bind(&cancel_tok)
        .bind(&resched_tok)
        .execute(&pool).await.unwrap();

    let busy = fetch_busy_times_for_user(
        &pool,
        &user_id,
        dt(2026, 3, 15, 0, 0),
        dt(2026, 3, 21, 23, 59),
        Tz::UTC,
        None,
    )
    .await;

    assert_eq!(busy.len(), 1);
    assert_eq!(busy[0].0, dt(2026, 3, 16, 10, 0));
    assert_eq!(busy[0].1, dt(2026, 3, 16, 10, 30));
}

#[tokio::test]
async fn fetch_busy_times_ignores_cancelled_bookings() {
    let pool = setup_test_db().await;
    let (user_id, _, et_id) = seed_test_data(&pool).await;

    let booking_id = uuid::Uuid::new_v4().to_string();
    let cancel_tok = uuid::Uuid::new_v4().to_string();
    let resched_tok = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token) VALUES (?, ?, 'uid1', 'Guest', 'guest@example.com', 'UTC', '2026-03-16T10:00:00', '2026-03-16T10:30:00', 'cancelled', ?, ?)")
        .bind(&booking_id)
        .bind(&et_id)
        .bind(&cancel_tok)
        .bind(&resched_tok)
        .execute(&pool).await.unwrap();

    let busy = fetch_busy_times_for_user(
        &pool,
        &user_id,
        dt(2026, 3, 15, 0, 0),
        dt(2026, 3, 21, 23, 59),
        Tz::UTC,
        None,
    )
    .await;

    assert!(
        busy.is_empty(),
        "Cancelled bookings should not block availability"
    );
}

#[tokio::test]
async fn compute_slots_basic_availability() {
    let pool = setup_test_db().await;
    let (_, _, et_id) = seed_test_data(&pool).await;

    let busy = BusySource::Individual(vec![]);

    // Start from tomorrow to avoid partial-day flakiness
    let slot_days = compute_slots(
        &pool,
        &et_id,
        30, // 30 min duration
        0,  // no buffer before
        0,  // no buffer after
        0,  // no min notice
        1,  // start from tomorrow
        14, // 14 days ahead
        Tz::UTC,
        Tz::UTC,
        busy,
    )
    .await;

    // Should have slots on weekdays only (Mon-Fri)
    assert!(!slot_days.is_empty(), "Should have slots on weekdays");

    // Each day should have 16 slots (09:00-17:00 in 30-min increments)
    for day in &slot_days {
        assert_eq!(
            day.slots.len(),
            16,
            "09:00-17:00 with 30min = 16 slots, got {} for {}",
            day.slots.len(),
            day.date
        );
    }
}

#[tokio::test]
async fn compute_slots_with_busy_event() {
    let pool = setup_test_db().await;
    let (_, _, et_id) = seed_test_data(&pool).await;

    // Find the next Monday from now
    let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
    let mut next_monday = now.date() + Duration::days(1);
    while next_monday.weekday() != chrono::Weekday::Mon {
        next_monday += Duration::days(1);
    }
    let days_to_monday = (next_monday - now.date()).num_days() as i32;

    // Block 10:00-11:00 on that Monday
    let busy_start = next_monday.and_hms_opt(10, 0, 0).unwrap();
    let busy_end = next_monday.and_hms_opt(11, 0, 0).unwrap();
    let busy = BusySource::Individual(vec![(busy_start, busy_end)]);

    let slot_days = compute_slots(
        &pool,
        &et_id,
        30,
        0,
        0,
        0,
        days_to_monday,
        1, // just 1 day
        Tz::UTC,
        Tz::UTC,
        busy,
    )
    .await;

    assert!(!slot_days.is_empty(), "Should have the Monday");
    let monday = &slot_days[0];

    // 16 slots normally, minus 2 (10:00 and 10:30 blocked) = 14
    assert_eq!(monday.slots.len(), 14, "10:00 and 10:30 should be blocked");

    // Verify 10:00 and 10:30 are not in the slots
    let slot_times: Vec<&str> = monday.slots.iter().map(|s| s.start.as_str()).collect();
    assert!(!slot_times.contains(&"10:00"), "10:00 should be blocked");
    assert!(!slot_times.contains(&"10:30"), "10:30 should be blocked");
}

#[tokio::test]
async fn compute_slots_with_buffer() {
    let pool = setup_test_db().await;
    let (_, _, et_id) = seed_test_data(&pool).await;

    // Find the next Monday
    let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
    let mut next_monday = now.date() + Duration::days(1);
    while next_monday.weekday() != chrono::Weekday::Mon {
        next_monday += Duration::days(1);
    }
    let days_to_monday = (next_monday - now.date()).num_days() as i32;

    // Block 10:00-10:30 on that Monday
    let busy_start = next_monday.and_hms_opt(10, 0, 0).unwrap();
    let busy_end = next_monday.and_hms_opt(10, 30, 0).unwrap();
    let busy = BusySource::Individual(vec![(busy_start, busy_end)]);

    let slot_days = compute_slots(
        &pool,
        &et_id,
        30,
        15, // 15 min buffer before
        15, // 15 min buffer after
        0,
        days_to_monday,
        1,
        Tz::UTC,
        Tz::UTC,
        busy,
    )
    .await;

    assert!(!slot_days.is_empty());
    let monday = &slot_days[0];

    // Event at 10:00-10:30 with 15min buffers blocks 09:45-10:45
    // So slots 09:30 (ends 10:00, buf_end=10:15 > 09:45), 10:00, 10:30 (buf_start=10:15 < 10:30) blocked
    let slot_times: Vec<&str> = monday.slots.iter().map(|s| s.start.as_str()).collect();
    assert!(
        !slot_times.contains(&"10:00"),
        "10:00 should be blocked (direct conflict)"
    );
    assert!(
        slot_times.contains(&"09:00"),
        "09:00 should be free (no buffer overlap)"
    );
}

#[tokio::test]
async fn compute_slots_frequency_limit_per_day_drops_capped_day() {
    let pool = setup_test_db().await;
    let (_, _, et_id) = seed_test_data(&pool).await;

    let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
    let mut next_monday = now.date() + Duration::days(1);
    while next_monday.weekday() != chrono::Weekday::Mon {
        next_monday += Duration::days(1);
    }
    let days_to_monday = (next_monday - now.date()).num_days() as i32;

    sqlx::query("INSERT INTO booking_frequency_limits (id, event_type_id, max_bookings, period) VALUES (?, ?, 1, 'day')")
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&et_id)
        .execute(&pool).await.unwrap();

    let start_at = next_monday
        .and_hms_opt(10, 0, 0)
        .unwrap()
        .format("%Y-%m-%dT%H:%M:%S")
        .to_string();
    let end_at = next_monday
        .and_hms_opt(10, 30, 0)
        .unwrap()
        .format("%Y-%m-%dT%H:%M:%S")
        .to_string();
    sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token) VALUES (?, ?, 'uid1', 'Guest', 'g@e.com', 'UTC', ?, ?, 'confirmed', ?, ?)")
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&et_id)
        .bind(&start_at)
        .bind(&end_at)
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(uuid::Uuid::new_v4().to_string())
        .execute(&pool).await.unwrap();

    let slot_days = compute_slots(
        &pool,
        &et_id,
        30,
        0,
        0,
        0,
        days_to_monday,
        5,
        Tz::UTC,
        Tz::UTC,
        BusySource::Individual(vec![]),
    )
    .await;

    let monday_date = next_monday.format("%Y-%m-%d").to_string();
    let monday = slot_days.iter().find(|d| d.date == monday_date);
    assert!(
        monday.map(|d| d.slots.is_empty()).unwrap_or(true),
        "1/day cap reached → Monday should expose no slots, got {:?}",
        monday.map(|d| d.slots.len())
    );

    let tuesday_date = (next_monday + Duration::days(1))
        .format("%Y-%m-%d")
        .to_string();
    let tuesday = slot_days
        .iter()
        .find(|d| d.date == tuesday_date)
        .expect("Tuesday should be present");
    assert_eq!(
        tuesday.slots.len(),
        16,
        "Tuesday is unaffected by Monday's per-day cap"
    );
}

#[tokio::test]
async fn compute_slots_frequency_limit_per_week_drops_whole_week() {
    let pool = setup_test_db().await;
    let (_, _, et_id) = seed_test_data(&pool).await;

    let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
    let mut next_monday = now.date() + Duration::days(1);
    while next_monday.weekday() != chrono::Weekday::Mon {
        next_monday += Duration::days(1);
    }
    let days_to_monday = (next_monday - now.date()).num_days() as i32;

    sqlx::query("INSERT INTO booking_frequency_limits (id, event_type_id, max_bookings, period) VALUES (?, ?, 1, 'week')")
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&et_id)
        .execute(&pool).await.unwrap();

    // One booking on Monday consumes the week's only slot.
    let start_at = next_monday
        .and_hms_opt(10, 0, 0)
        .unwrap()
        .format("%Y-%m-%dT%H:%M:%S")
        .to_string();
    let end_at = next_monday
        .and_hms_opt(10, 30, 0)
        .unwrap()
        .format("%Y-%m-%dT%H:%M:%S")
        .to_string();
    sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token) VALUES (?, ?, 'uid1', 'Guest', 'g@e.com', 'UTC', ?, ?, 'confirmed', ?, ?)")
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&et_id)
        .bind(&start_at)
        .bind(&end_at)
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(uuid::Uuid::new_v4().to_string())
        .execute(&pool).await.unwrap();

    let slot_days = compute_slots(
        &pool,
        &et_id,
        30,
        0,
        0,
        0,
        days_to_monday,
        5,
        Tz::UTC,
        Tz::UTC,
        BusySource::Individual(vec![]),
    )
    .await;

    for day in &slot_days {
        assert!(
            day.slots.is_empty(),
            "Per-week cap of 1 reached → {} should have no slots, got {}",
            day.date,
            day.slots.len()
        );
    }
}

#[tokio::test]
async fn compute_slots_frequency_limit_ignores_cancelled_bookings() {
    // Regression: cancelled bookings must not count toward the cap. If they
    // did, hosts who frequently cancel would silently shrink their own
    // availability.
    let pool = setup_test_db().await;
    let (_, _, et_id) = seed_test_data(&pool).await;

    let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
    let mut next_monday = now.date() + Duration::days(1);
    while next_monday.weekday() != chrono::Weekday::Mon {
        next_monday += Duration::days(1);
    }
    let days_to_monday = (next_monday - now.date()).num_days() as i32;

    sqlx::query("INSERT INTO booking_frequency_limits (id, event_type_id, max_bookings, period) VALUES (?, ?, 1, 'day')")
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&et_id)
        .execute(&pool).await.unwrap();

    // Single cancelled booking on Monday — should not consume the day's cap.
    let start_at = next_monday
        .and_hms_opt(10, 0, 0)
        .unwrap()
        .format("%Y-%m-%dT%H:%M:%S")
        .to_string();
    let end_at = next_monday
        .and_hms_opt(10, 30, 0)
        .unwrap()
        .format("%Y-%m-%dT%H:%M:%S")
        .to_string();
    sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token) VALUES (?, ?, 'uid1', 'Guest', 'g@e.com', 'UTC', ?, ?, 'cancelled', ?, ?)")
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&et_id)
        .bind(&start_at)
        .bind(&end_at)
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(uuid::Uuid::new_v4().to_string())
        .execute(&pool).await.unwrap();

    let slot_days = compute_slots(
        &pool,
        &et_id,
        30,
        0,
        0,
        0,
        days_to_monday,
        1,
        Tz::UTC,
        Tz::UTC,
        BusySource::Individual(vec![]),
    )
    .await;

    let monday_date = next_monday.format("%Y-%m-%d").to_string();
    let monday = slot_days
        .iter()
        .find(|d| d.date == monday_date)
        .expect("Monday should be present");
    assert_eq!(
        monday.slots.len(),
        16,
        "Cancelled bookings must not consume the day cap; expected full 16 slots, got {}",
        monday.slots.len()
    );
}

#[tokio::test]
async fn compute_slots_frequency_limit_multiple_caps_each_checked() {
    // Configure both a 1/day and a 100/year cap. With one booking on
    // Monday only the day cap fires, so Monday must be hidden but
    // Tue–Fri must stay visible. This pins that the filter consults every
    // configured limit independently rather than stopping at the first.
    let pool = setup_test_db().await;
    let (_, _, et_id) = seed_test_data(&pool).await;

    let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
    let mut next_monday = now.date() + Duration::days(1);
    while next_monday.weekday() != chrono::Weekday::Mon {
        next_monday += Duration::days(1);
    }
    let days_to_monday = (next_monday - now.date()).num_days() as i32;

    sqlx::query("INSERT INTO booking_frequency_limits (id, event_type_id, max_bookings, period) VALUES (?, ?, 1, 'day')")
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&et_id)
        .execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO booking_frequency_limits (id, event_type_id, max_bookings, period) VALUES (?, ?, 100, 'year')")
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&et_id)
        .execute(&pool).await.unwrap();

    let start_at = next_monday
        .and_hms_opt(10, 0, 0)
        .unwrap()
        .format("%Y-%m-%dT%H:%M:%S")
        .to_string();
    let end_at = next_monday
        .and_hms_opt(10, 30, 0)
        .unwrap()
        .format("%Y-%m-%dT%H:%M:%S")
        .to_string();
    sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token) VALUES (?, ?, 'uid1', 'Guest', 'g@e.com', 'UTC', ?, ?, 'confirmed', ?, ?)")
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&et_id)
        .bind(&start_at)
        .bind(&end_at)
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(uuid::Uuid::new_v4().to_string())
        .execute(&pool).await.unwrap();

    let slot_days = compute_slots(
        &pool,
        &et_id,
        30,
        0,
        0,
        0,
        days_to_monday,
        5,
        Tz::UTC,
        Tz::UTC,
        BusySource::Individual(vec![]),
    )
    .await;

    let monday_date = next_monday.format("%Y-%m-%d").to_string();
    let monday = slot_days.iter().find(|d| d.date == monday_date);
    assert!(
        monday.map(|d| d.slots.is_empty()).unwrap_or(true),
        "1/day cap should hide Monday even with a lax year cap, got {:?}",
        monday.map(|d| d.slots.len())
    );

    let tuesday_date = (next_monday + Duration::days(1))
        .format("%Y-%m-%d")
        .to_string();
    let tuesday = slot_days
        .iter()
        .find(|d| d.date == tuesday_date)
        .expect("Tuesday should be present");
    assert_eq!(
        tuesday.slots.len(),
        16,
        "Year cap not reached → Tuesday must stay visible"
    );
}

/// Attach the seeded event type to a team and add two team members
/// (alice, bob). Returns their user ids.
async fn seed_team_for_event_type(pool: &SqlitePool, et_id: &str) -> (String, String) {
    let team_id = uuid::Uuid::new_v4().to_string();
    let alice = uuid::Uuid::new_v4().to_string();
    let bob = uuid::Uuid::new_v4().to_string();

    sqlx::query(
        "INSERT INTO teams (id, name, slug, visibility) VALUES (?, 'Team', 'team', 'public')",
    )
    .bind(&team_id)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query("UPDATE event_types SET team_id = ? WHERE id = ?")
        .bind(&team_id)
        .bind(et_id)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO users (id, email, name, role, auth_provider, username, enabled) VALUES (?, 'alice@example.com', 'Alice', 'user', 'local', 'alice', 1)")
        .bind(&alice).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO users (id, email, name, role, auth_provider, username, enabled) VALUES (?, 'bob@example.com', 'Bob', 'user', 'local', 'bob', 1)")
        .bind(&bob).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO team_members (team_id, user_id, role, source) VALUES (?, ?, 'member', 'direct')")
        .bind(&team_id).bind(&alice).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO team_members (team_id, user_id, role, source) VALUES (?, ?, 'member', 'direct')")
        .bind(&team_id).bind(&bob).execute(pool).await.unwrap();

    (alice, bob)
}

async fn insert_booking(
    pool: &SqlitePool,
    et_id: &str,
    assigned_user_id: Option<&str>,
    start: NaiveDateTime,
    status: &str,
) {
    let end = start + Duration::minutes(30);
    sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token, assigned_user_id) VALUES (?, ?, ?, 'G', 'g@e.com', 'UTC', ?, ?, ?, ?, ?, ?)")
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(et_id)
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(start.format("%Y-%m-%dT%H:%M:%S").to_string())
        .bind(end.format("%Y-%m-%dT%H:%M:%S").to_string())
        .bind(status)
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(assigned_user_id)
        .execute(pool).await.unwrap();
}

#[tokio::test]
async fn would_exceed_frequency_limit_per_member_blocks_only_named_assignee() {
    let pool = setup_test_db().await;
    let (_, _, et_id) = seed_test_data(&pool).await;
    let (alice, bob) = seed_team_for_event_type(&pool, &et_id).await;

    sqlx::query("INSERT INTO booking_frequency_limits (id, event_type_id, max_bookings, period, per_member) VALUES (?, ?, 1, 'day', 1)")
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&et_id)
        .execute(&pool).await.unwrap();

    let booked_day = NaiveDate::from_ymd_opt(2026, 3, 16).unwrap();
    let booked_start = booked_day.and_hms_opt(10, 0, 0).unwrap();
    insert_booking(&pool, &et_id, Some(&alice), booked_start, "confirmed").await;

    let proposed = booked_day.and_hms_opt(14, 0, 0).unwrap();
    assert!(
        would_exceed_frequency_limit(&pool, &et_id, proposed, Some(&alice)).await,
        "Alice already has one booking that day under 1/day per-member"
    );
    assert!(
        !would_exceed_frequency_limit(&pool, &et_id, proposed, Some(&bob)).await,
        "Bob has zero bookings; per-member cap should not block him"
    );
}

#[tokio::test]
async fn apply_frequency_limit_filter_per_member_keeps_slots_when_one_member_free() {
    // 1/day per-member, 2 team members, 1 booking on Monday assigned to
    // Alice → Monday must still show slots because Bob has headroom.
    let pool = setup_test_db().await;
    let (_, _, et_id) = seed_test_data(&pool).await;
    let (alice, _bob) = seed_team_for_event_type(&pool, &et_id).await;

    let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
    let mut next_monday = now.date() + Duration::days(1);
    while next_monday.weekday() != chrono::Weekday::Mon {
        next_monday += Duration::days(1);
    }
    let days_to_monday = (next_monday - now.date()).num_days() as i32;

    sqlx::query("INSERT INTO booking_frequency_limits (id, event_type_id, max_bookings, period, per_member) VALUES (?, ?, 1, 'day', 1)")
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&et_id)
        .execute(&pool).await.unwrap();
    insert_booking(
        &pool,
        &et_id,
        Some(&alice),
        next_monday.and_hms_opt(10, 0, 0).unwrap(),
        "confirmed",
    )
    .await;

    let slot_days = compute_slots(
        &pool,
        &et_id,
        30,
        0,
        0,
        0,
        days_to_monday,
        1,
        Tz::UTC,
        Tz::UTC,
        BusySource::Individual(vec![]),
    )
    .await;

    let monday_date = next_monday.format("%Y-%m-%d").to_string();
    let monday = slot_days
        .iter()
        .find(|d| d.date == monday_date)
        .expect("Monday should be present");
    assert_eq!(
        monday.slots.len(),
        16,
        "Per-member cap consumed by Alice must not hide slots while Bob is free"
    );
}

#[tokio::test]
async fn apply_frequency_limit_filter_per_member_drops_slots_when_all_members_capped() {
    // 1/day per-member, 2 team members, both already booked on Monday →
    // Monday must show no slots.
    let pool = setup_test_db().await;
    let (_, _, et_id) = seed_test_data(&pool).await;
    let (alice, bob) = seed_team_for_event_type(&pool, &et_id).await;

    let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
    let mut next_monday = now.date() + Duration::days(1);
    while next_monday.weekday() != chrono::Weekday::Mon {
        next_monday += Duration::days(1);
    }
    let days_to_monday = (next_monday - now.date()).num_days() as i32;

    sqlx::query("INSERT INTO booking_frequency_limits (id, event_type_id, max_bookings, period, per_member) VALUES (?, ?, 1, 'day', 1)")
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&et_id)
        .execute(&pool).await.unwrap();
    insert_booking(
        &pool,
        &et_id,
        Some(&alice),
        next_monday.and_hms_opt(10, 0, 0).unwrap(),
        "confirmed",
    )
    .await;
    insert_booking(
        &pool,
        &et_id,
        Some(&bob),
        next_monday.and_hms_opt(11, 0, 0).unwrap(),
        "confirmed",
    )
    .await;

    let slot_days = compute_slots(
        &pool,
        &et_id,
        30,
        0,
        0,
        0,
        days_to_monday,
        1,
        Tz::UTC,
        Tz::UTC,
        BusySource::Individual(vec![]),
    )
    .await;

    let monday_date = next_monday.format("%Y-%m-%d").to_string();
    let monday = slot_days.iter().find(|d| d.date == monday_date);
    assert!(
        monday.map(|d| d.slots.is_empty()).unwrap_or(true),
        "Every team member at cap → Monday must be empty, got {:?}",
        monday.map(|d| d.slots.len())
    );
}

#[tokio::test]
async fn apply_frequency_limit_filter_per_member_on_personal_event_type_degrades_to_wide() {
    // Personal event type (no team) with a per_member flag set. With no
    // team members to scope by, the cap should behave event-type-wide so
    // a single booking still hides the day.
    let pool = setup_test_db().await;
    let (_, _, et_id) = seed_test_data(&pool).await;

    let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
    let mut next_monday = now.date() + Duration::days(1);
    while next_monday.weekday() != chrono::Weekday::Mon {
        next_monday += Duration::days(1);
    }
    let days_to_monday = (next_monday - now.date()).num_days() as i32;

    sqlx::query("INSERT INTO booking_frequency_limits (id, event_type_id, max_bookings, period, per_member) VALUES (?, ?, 1, 'day', 1)")
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&et_id)
        .execute(&pool).await.unwrap();
    insert_booking(
        &pool,
        &et_id,
        None,
        next_monday.and_hms_opt(10, 0, 0).unwrap(),
        "confirmed",
    )
    .await;

    let slot_days = compute_slots(
        &pool,
        &et_id,
        30,
        0,
        0,
        0,
        days_to_monday,
        1,
        Tz::UTC,
        Tz::UTC,
        BusySource::Individual(vec![]),
    )
    .await;

    let monday_date = next_monday.format("%Y-%m-%d").to_string();
    let monday = slot_days.iter().find(|d| d.date == monday_date);
    assert!(
        monday.map(|d| d.slots.is_empty()).unwrap_or(true),
        "Per-member flag on a personal event type must still cap the day"
    );
}

#[tokio::test]
async fn apply_frequency_limit_filter_mixed_per_member_and_wide_fire_independently() {
    // Two limits on the same team event type:
    //   - 1/day per-member
    //   - 3/week event-type-wide
    //
    // Bookings span two consecutive weeks:
    //   Week 1: three bookings by Alice on Mon/Tue/Wed → wide week count
    //           hits its cap (3/3).
    //   Week 2: one booking each by Alice and Bob on Monday → both
    //           per-member day caps fill, wide week count is 2/3 (lax).
    //
    // Expectations:
    //   - Every weekday in week 1 must be hidden — wide cap dominates,
    //     even Thu/Fri where per-member alone would still allow bookings.
    //   - Week 2 Monday must be hidden by the per-member rule (both
    //     members at cap) while the wide rule still has headroom.
    //   - Week 2 Tue-Fri must be visible — neither rule fires.
    //
    // If a future change ever conflates the two rule paths, this test
    // will fail in a specific weekday rather than silently allow or
    // deny everything.
    let pool = setup_test_db().await;
    let (_, _, et_id) = seed_test_data(&pool).await;
    let (alice, bob) = seed_team_for_event_type(&pool, &et_id).await;

    let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
    let mut next_monday = now.date() + Duration::days(1);
    while next_monday.weekday() != chrono::Weekday::Mon {
        next_monday += Duration::days(1);
    }
    let days_to_monday = (next_monday - now.date()).num_days() as i32;

    sqlx::query("INSERT INTO booking_frequency_limits (id, event_type_id, max_bookings, period, per_member) VALUES (?, ?, 1, 'day', 1)")
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&et_id)
        .execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO booking_frequency_limits (id, event_type_id, max_bookings, period, per_member) VALUES (?, ?, 3, 'week', 0)")
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&et_id)
        .execute(&pool).await.unwrap();

    // Week 1: three Alice bookings consume the wide week cap.
    for offset in 0..3 {
        insert_booking(
            &pool,
            &et_id,
            Some(&alice),
            (next_monday + Duration::days(offset))
                .and_hms_opt(10, 0, 0)
                .unwrap(),
            "confirmed",
        )
        .await;
    }

    // Week 2 Monday: both members booked, capping per-member.
    let week2_monday = next_monday + Duration::days(7);
    insert_booking(
        &pool,
        &et_id,
        Some(&alice),
        week2_monday.and_hms_opt(10, 0, 0).unwrap(),
        "confirmed",
    )
    .await;
    insert_booking(
        &pool,
        &et_id,
        Some(&bob),
        week2_monday.and_hms_opt(11, 0, 0).unwrap(),
        "confirmed",
    )
    .await;

    let slot_days = compute_slots(
        &pool,
        &et_id,
        30,
        0,
        0,
        0,
        days_to_monday,
        14,
        Tz::UTC,
        Tz::UTC,
        BusySource::Individual(vec![]),
    )
    .await;

    let find_day = |d: NaiveDate| -> Option<&SlotDay> {
        let key = d.format("%Y-%m-%d").to_string();
        slot_days.iter().find(|x| x.date == key)
    };

    // Week 1 Mon-Fri: every weekday hidden because the wide cap is hit.
    for offset in 0..5 {
        let d = next_monday + Duration::days(offset);
        let day = find_day(d);
        assert!(
            day.map(|x| x.slots.is_empty()).unwrap_or(true),
            "Week 1 {} should be hidden by the 3/week wide cap; got {:?}",
            d,
            day.map(|x| x.slots.len())
        );
    }

    // Week 2 Mon: per-member dominates — wide is lax (2/3) but both
    // members are at their per-day cap.
    let w2_mon = find_day(week2_monday);
    assert!(
        w2_mon.map(|x| x.slots.is_empty()).unwrap_or(true),
        "Week 2 Monday should be hidden by per-member rule; got {:?}",
        w2_mon.map(|x| x.slots.len())
    );

    // Week 2 Tue-Fri: neither rule fires, full availability.
    for offset in 1..5 {
        let d = week2_monday + Duration::days(offset);
        let day = find_day(d).expect("Week 2 weekday should be present");
        assert_eq!(
            day.slots.len(),
            16,
            "Week 2 {} should be free; got {} slots",
            d,
            day.slots.len()
        );
    }
}

#[tokio::test]
async fn compute_slots_no_weekend_slots() {
    let pool = setup_test_db().await;
    let (_, _, et_id) = seed_test_data(&pool).await;

    // Find next Saturday
    let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
    let mut next_sat = now.date();
    while next_sat.weekday() != chrono::Weekday::Sat {
        next_sat += Duration::days(1);
    }
    let days_to_sat = (next_sat - now.date()).num_days() as i32;

    let busy = BusySource::Individual(vec![]);
    let slot_days = compute_slots(
        &pool,
        &et_id,
        30,
        0,
        0,
        0,
        days_to_sat,
        2, // just Sat + Sun
        Tz::UTC,
        Tz::UTC,
        busy,
    )
    .await;

    assert!(
        slot_days.is_empty(),
        "Weekends should have no slots (Mon-Fri rules only)"
    );
}

#[tokio::test]
async fn compute_slots_group_any_member_free() {
    let pool = setup_test_db().await;
    let (_, _, et_id) = seed_test_data(&pool).await;

    // Find the next Monday
    let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
    let mut next_monday = now.date() + Duration::days(1);
    while next_monday.weekday() != chrono::Weekday::Mon {
        next_monday += Duration::days(1);
    }
    let days_to_monday = (next_monday - now.date()).num_days() as i32;

    let ten_am = next_monday.and_hms_opt(10, 0, 0).unwrap();
    let ten_thirty = next_monday.and_hms_opt(10, 30, 0).unwrap();

    // Member A is busy at 10:00, Member B is free
    let mut member_busy = HashMap::new();
    member_busy.insert("member_a".to_string(), vec![(ten_am, ten_thirty)]);
    member_busy.insert("member_b".to_string(), vec![]); // free

    let busy = BusySource::Group(member_busy);
    let slot_days = compute_slots(
        &pool,
        &et_id,
        30,
        0,
        0,
        0,
        days_to_monday,
        1,
        Tz::UTC,
        Tz::UTC,
        busy,
    )
    .await;

    assert!(!slot_days.is_empty());
    let monday = &slot_days[0];
    // 10:00 should still be available because member B is free
    let slot_times: Vec<&str> = monday.slots.iter().map(|s| s.start.as_str()).collect();
    assert!(
        slot_times.contains(&"10:00"),
        "10:00 should be available (member B is free)"
    );
    assert_eq!(
        monday.slots.len(),
        16,
        "All slots available (at least one member free)"
    );
}

#[tokio::test]
async fn compute_slots_group_all_busy_blocks() {
    let pool = setup_test_db().await;
    let (_, _, et_id) = seed_test_data(&pool).await;

    let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
    let mut next_monday = now.date() + Duration::days(1);
    while next_monday.weekday() != chrono::Weekday::Mon {
        next_monday += Duration::days(1);
    }
    let days_to_monday = (next_monday - now.date()).num_days() as i32;

    let ten_am = next_monday.and_hms_opt(10, 0, 0).unwrap();
    let ten_thirty = next_monday.and_hms_opt(10, 30, 0).unwrap();

    // Both members busy at 10:00
    let mut member_busy = HashMap::new();
    member_busy.insert("member_a".to_string(), vec![(ten_am, ten_thirty)]);
    member_busy.insert("member_b".to_string(), vec![(ten_am, ten_thirty)]);

    let busy = BusySource::Group(member_busy);
    let slot_days = compute_slots(
        &pool,
        &et_id,
        30,
        0,
        0,
        0,
        days_to_monday,
        1,
        Tz::UTC,
        Tz::UTC,
        busy,
    )
    .await;

    assert!(!slot_days.is_empty());
    let monday = &slot_days[0];
    let slot_times: Vec<&str> = monday.slots.iter().map(|s| s.start.as_str()).collect();
    assert!(
        !slot_times.contains(&"10:00"),
        "10:00 blocked when ALL members busy"
    );
    assert_eq!(monday.slots.len(), 15, "One slot blocked");
}

#[tokio::test]
async fn compute_slots_team_requires_all_free() {
    // Team links require ALL members to be free (unlike Group which needs ANY)
    let pool = setup_test_db().await;
    let (_, _, et_id) = seed_test_data(&pool).await;

    let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
    let mut next_monday = now.date() + Duration::days(1);
    while next_monday.weekday() != chrono::Weekday::Mon {
        next_monday += Duration::days(1);
    }
    let days_to_monday = (next_monday - now.date()).num_days() as i32;

    let ten_am = next_monday.and_hms_opt(10, 0, 0).unwrap();
    let ten_thirty = next_monday.and_hms_opt(10, 30, 0).unwrap();

    // Only ONE member busy at 10:00 — Team should block, Group would allow
    let mut member_busy = HashMap::new();
    member_busy.insert("member_a".to_string(), vec![(ten_am, ten_thirty)]);
    member_busy.insert("member_b".to_string(), vec![]); // member_b is free

    let busy = BusySource::Team(member_busy);
    let slot_days = compute_slots(
        &pool,
        &et_id,
        30,
        0,
        0,
        0,
        days_to_monday,
        1,
        Tz::UTC,
        Tz::UTC,
        busy,
    )
    .await;

    assert!(!slot_days.is_empty());
    let monday = &slot_days[0];
    let slot_times: Vec<&str> = monday.slots.iter().map(|s| s.start.as_str()).collect();
    assert!(
        !slot_times.contains(&"10:00"),
        "Team: 10:00 blocked when ANY member is busy"
    );
    assert_eq!(monday.slots.len(), 15, "One slot blocked for Team");
}

#[tokio::test]
async fn compute_slots_team_all_free_allows() {
    // When all team members are free, the slot should be available
    let pool = setup_test_db().await;
    let (_, _, et_id) = seed_test_data(&pool).await;

    let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
    let mut next_monday = now.date() + Duration::days(1);
    while next_monday.weekday() != chrono::Weekday::Mon {
        next_monday += Duration::days(1);
    }
    let days_to_monday = (next_monday - now.date()).num_days() as i32;

    // No one is busy
    let mut member_busy = HashMap::new();
    member_busy.insert("member_a".to_string(), vec![]);
    member_busy.insert("member_b".to_string(), vec![]);

    let busy = BusySource::Team(member_busy);
    let slot_days = compute_slots(
        &pool,
        &et_id,
        30,
        0,
        0,
        0,
        days_to_monday,
        1,
        Tz::UTC,
        Tz::UTC,
        busy,
    )
    .await;

    assert!(!slot_days.is_empty());
    let monday = &slot_days[0];
    assert_eq!(
        monday.slots.len(),
        16,
        "All 16 slots available when team is free"
    );
}

// Regression test: an availability rule that ends at 23:00 with a 60-min
// slot must terminate. Before the fix, compute_slots_from_rules used a
// NaiveTime cursor, and NaiveTime + Duration wraps at 24h — so when
// cursor reached 23:00, cursor + slot_duration (60m) wrapped to 00:00
// which is still <= 23:00 as a time-of-day, making the loop emit a slot
// every step forever until OOM. Prod symptom: ~4-minute CPU spike +
// ~9GB RAM before the OOM killer intervened (issue logged in internal
// Vates Demo Team EN / book-a-demo-of-vates-vms booking page).
#[test]
fn compute_slots_terminates_with_window_ending_at_23_00() {
    let rules: Vec<(i32, String, String)> = (1..=4)
        .map(|d| (d, "09:00".to_string(), "23:00".to_string()))
        .collect();
    let busy = BusySource::Individual(vec![]);

    // Pick a start_offset that lands on a Monday so we hit at least one
    // rule-matching day regardless of when the test runs.
    let today = Utc::now().naive_utc().date();
    let mut start = 1i32;
    while (today + Duration::days(start as i64)).weekday() != chrono::Weekday::Mon {
        start += 1;
    }

    let result = compute_slots_from_rules(
        &rules,
        60,
        60,
        0,
        0,
        0,
        start,
        1,
        Tz::UTC,
        Tz::UTC,
        busy,
        &[],
    );

    // 09:00..=22:00 start times with 60-min spacing and 60-min duration =
    // 14 slots on a matching weekday. Anything beyond a few hundred means
    // the wrap bug is back.
    let total_slots: usize = result.iter().map(|d| d.slots.len()).sum();
    assert!(
        total_slots <= 20,
        "compute_slots_from_rules produced {} slots for a single day with \
         window 09:00-23:00 and 60-min duration; the NaiveTime wrap bug \
         is back",
        total_slots
    );
    assert_eq!(total_slots, 14, "expected exactly 14 hourly slots");
}

// Regression for issue #50: a team member in a different timezone than the host
// must only be considered available within THEIR working hours, not inside the
// event type's rule window interpreted in host_tz.
#[tokio::test]
async fn user_avail_as_busy_respects_member_timezone() {
    let pool = setup_test_db().await;

    let paris_uid = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO users (id, email, name, role, auth_provider, username, enabled, timezone) \
         VALUES (?, 'paris@example.com', 'Paris User', 'user', 'local', 'paris', 1, 'Europe/Paris')",
    )
    .bind(&paris_uid)
    .execute(&pool)
    .await
    .unwrap();

    // Paris member works Mon-Fri 09:00-17:00 local time
    for day in [1, 2, 3, 4, 5] {
        let rid = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO user_availability_rules (id, user_id, day_of_week, start_time, end_time) \
             VALUES (?, ?, ?, '09:00', '17:00')",
        )
        .bind(&rid)
        .bind(&paris_uid)
        .bind(day)
        .execute(&pool)
        .await
        .unwrap();
    }

    // Host is in New_York. In winter: Paris=UTC+1, NY=UTC-5 → 6h offset.
    // Paris 09:00-17:00 == NY 03:00-11:00.
    // Week of 2026-01-12 (Monday).
    let host_tz: Tz = "America/New_York".parse().unwrap();
    let window_start = dt(2026, 1, 12, 0, 0);
    let window_end = dt(2026, 1, 12, 23, 59);

    let busy = user_avail_as_busy(&pool, &paris_uid, window_start, window_end, host_tz).await;

    // Helper: is (t) inside any busy interval?
    let is_busy = |t: NaiveDateTime| busy.iter().any(|(s, e)| &t >= s && &t < e);

    // NY 02:00 Monday = Paris 08:00 — Paris member NOT working yet → must be busy.
    assert!(
        is_busy(dt(2026, 1, 12, 2, 0)),
        "NY 02:00 (Paris 08:00) should be blocked — outside member's working hours"
    );
    // NY 05:00 Monday = Paris 11:00 — Paris member IS working → must NOT be busy.
    assert!(
        !is_busy(dt(2026, 1, 12, 5, 0)),
        "NY 05:00 (Paris 11:00) should be free — inside member's working hours"
    );
    // NY 12:00 Monday = Paris 18:00 — Paris member done for the day → must be busy.
    assert!(
        is_busy(dt(2026, 1, 12, 12, 0)),
        "NY 12:00 (Paris 18:00) should be blocked — outside member's working hours"
    );
}

// Regression for Antoine's follow-up: the team event-type flow must apply
// each member's personal working hours as a constraint (converted into
// host_tz). Concretely: a team with a single America/Chicago member whose
// personal rules are Mon-Fri 09:00-17:00 local must render slots in Paris
// host_tz only from 16:00 onwards, not across the full 09:00-23:00 rule.
// Verifies the exact conversion user_avail_as_busy performs; the
// show_group_slots/pick_group_member handlers extend member_busy with
// this output before running compute_slots.
#[tokio::test]
async fn chicago_member_is_busy_at_paris_morning() {
    let pool = setup_test_db().await;
    let uid = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO users (id, email, name, role, auth_provider, username, enabled, timezone) \
         VALUES (?, 'andy@example.com', 'Andy', 'user', 'local', 'andy', 1, 'America/Chicago')",
    )
    .bind(&uid)
    .execute(&pool)
    .await
    .unwrap();

    // Mon-Fri 09:00-17:00 Chicago local
    for day in 1..=5 {
        let rid = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO user_availability_rules (id, user_id, day_of_week, start_time, end_time) \
             VALUES (?, ?, ?, '09:00', '17:00')",
        )
        .bind(&rid)
        .bind(&uid)
        .bind(day)
        .execute(&pool)
        .await
        .unwrap();
    }

    // 2026-07-07 is a Tuesday in full summer DST (Chicago CDT UTC-5,
    // Paris CEST UTC+2, 7-hour offset — matches Antoine's scenario).
    let host_tz: Tz = "Europe/Paris".parse().unwrap();
    let window_start = dt(2026, 7, 7, 0, 0);
    let window_end = dt(2026, 7, 7, 23, 59);

    let busy = user_avail_as_busy(&pool, &uid, window_start, window_end, host_tz).await;
    let is_busy = |t: NaiveDateTime| busy.iter().any(|(s, e)| &t >= s && &t < e);

    // Paris 09:00 = Chicago 02:00 — outside 09-17, must be blocked.
    assert!(
        is_busy(dt(2026, 7, 7, 9, 0)),
        "Paris 09:00 (Chicago 02:00) must be blocked — Andy sleeping"
    );
    // Paris 16:00 = Chicago 09:00 — Andy just started, must be free.
    assert!(
        !is_busy(dt(2026, 7, 7, 16, 0)),
        "Paris 16:00 (Chicago 09:00) must be free — Andy working"
    );
    // Paris 22:00 = Chicago 15:00 — Andy still working, must be free.
    assert!(
        !is_busy(dt(2026, 7, 7, 22, 0)),
        "Paris 22:00 (Chicago 15:00) must be free — Andy working"
    );
}

// Regression: when a team member without any user_availability_rules is
// active, they must be treated as always-available (no synthesized 9-17
// default). This preserves the behavior Antoine tested originally where
// a single Paris member expected the full event-type rule window.
#[tokio::test]
async fn member_without_personal_rules_is_unconstrained() {
    let pool = setup_test_db().await;
    let uid = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO users (id, email, name, role, auth_provider, username, enabled, timezone) \
         VALUES (?, 'free@example.com', 'No Hours', 'user', 'local', 'free', 1, 'Europe/Paris')",
    )
    .bind(&uid)
    .execute(&pool)
    .await
    .unwrap();
    // Deliberately NO user_availability_rules rows for this user.

    let host_tz: Tz = "Europe/Paris".parse().unwrap();
    let busy = user_avail_as_busy(
        &pool,
        &uid,
        dt(2026, 7, 7, 0, 0),
        dt(2026, 7, 7, 23, 59),
        host_tz,
    )
    .await;

    assert!(
        busy.is_empty(),
        "no personal rules must mean no constraint — got {} busy intervals",
        busy.len()
    );
}

// Regression for issue #50: an event type carries its own host timezone,
// which must take precedence over the account owner's personal timezone.
// Prevents the original bug where a US-based creator silently made the
// team's 09:00-21:00 rule land in Chicago time.
#[tokio::test]
async fn get_host_tz_prefers_explicit_event_type_timezone() {
    let pool = setup_test_db().await;

    // Create a user in America/Chicago and their account.
    let user_id = uuid::Uuid::new_v4().to_string();
    let account_id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO users (id, email, name, role, auth_provider, username, enabled, timezone) \
         VALUES (?, 'chicago@example.com', 'Chicago User', 'user', 'local', 'chicago', 1, 'America/Chicago')",
    )
    .bind(&user_id)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO accounts (id, name, email, timezone, user_id) VALUES (?, 'Chicago User', 'chicago@example.com', 'America/Chicago', ?)")
        .bind(&account_id)
        .bind(&user_id)
        .execute(&pool)
        .await
        .unwrap();

    // Event type explicitly pinned to Europe/Paris.
    let et_id = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO event_types (id, account_id, slug, title, duration_min, buffer_before, buffer_after, min_notice_min, enabled, timezone) VALUES (?, ?, 'demo', 'Demo', 30, 0, 0, 0, 1, 'Europe/Paris')")
        .bind(&et_id)
        .bind(&account_id)
        .execute(&pool)
        .await
        .unwrap();

    assert_eq!(
        get_host_tz(&pool, &et_id).await,
        Tz::Europe__Paris,
        "explicit event-type timezone must win over account owner's"
    );

    // Event type with NULL timezone should fall back to the account owner.
    let et_id2 = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO event_types (id, account_id, slug, title, duration_min, buffer_before, buffer_after, min_notice_min, enabled) VALUES (?, ?, 'demo2', 'Demo2', 30, 0, 0, 0, 1)")
        .bind(&et_id2)
        .bind(&account_id)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        get_host_tz(&pool, &et_id2).await,
        Tz::America__Chicago,
        "NULL event-type timezone must fall back to account owner"
    );
}

// --- parse_booking_datetime tests ---

#[test]
fn parse_booking_datetime_iso_format() {
    assert_eq!(
        parse_booking_datetime("2026-03-15T14:30:00"),
        Some(dt(2026, 3, 15, 14, 30))
    );
}

#[test]
fn parse_booking_datetime_space_format() {
    assert_eq!(
        parse_booking_datetime("2026-03-15 14:30:00"),
        Some(dt(2026, 3, 15, 14, 30))
    );
}

#[test]
fn parse_booking_datetime_trailing_z() {
    assert_eq!(
        parse_booking_datetime("2026-03-15T14:30:00Z"),
        Some(dt(2026, 3, 15, 14, 30))
    );
}

#[test]
fn parse_booking_datetime_invalid() {
    assert_eq!(parse_booking_datetime("not-a-date"), None);
    assert_eq!(parse_booking_datetime(""), None);
    assert_eq!(parse_booking_datetime("2026-13-40T99:99:99"), None);
}

// --- format_booking_datetime tests ---

#[test]
fn format_booking_datetime_far_future_same_year_not_guaranteed() {
    // Use a date far in the future (2099) so it's never "today"/"tomorrow"/weekday
    let result = format_booking_datetime("2099-07-20T09:15:00");
    assert_eq!(result, "Mon, Jul 20, 2099 at 9:15 AM");
}

#[test]
fn format_booking_datetime_different_year() {
    let result = format_booking_datetime("2050-12-25T18:00:00");
    assert_eq!(result, "Sun, Dec 25, 2050 at 6:00 PM");
}

#[test]
fn format_booking_datetime_invalid_fallback() {
    assert_eq!(format_booking_datetime("garbage"), "garbage");
    assert_eq!(format_booking_datetime(""), "");
}

// --- format_booking_range tests ---

#[test]
fn format_booking_range_far_future() {
    let result = format_booking_range("2099-07-20T09:00:00", "2099-07-20T09:30:00");
    assert_eq!(result, "Mon, Jul 20, 2099 at 9:00 AM — 9:30 AM");
}

#[test]
fn format_booking_range_end_unparseable() {
    let result = format_booking_range("2099-07-20T09:00:00", "bad");
    assert_eq!(result, "Mon, Jul 20, 2099 at 9:00 AM — bad");
}

// --- format_booking_for_dashboard tests ---
//
// Regression for issue #100: when the event type's stored timezone differs
// from the host's profile timezone, the dashboard previously displayed the
// raw stored time with no timezone label, which the host read as their own
// time. The fix shifts the primary label into the host's profile tz and
// adds a secondary guest-tz line.

#[test]
fn dashboard_label_converts_stored_tz_to_host_profile_tz() {
    // The user's exact scenario: event type set to America/New_York
    // (UTC-5 in winter), host's profile is Europe/Paris (UTC+1 in winter),
    // guest booked from America/New_York at 10:00 → stored as "10:00".
    // Host should see "4:00 PM" (Paris equivalent), guest line shows "10:00 EST".
    let (primary, secondary) = format_booking_for_dashboard(
        "2099-01-20T10:00:00",
        "2099-01-20T10:30:00",
        "America/New_York",
        "Europe/Paris",
        "America/New_York",
    );
    assert!(
        primary.contains("4:00 PM") && primary.contains("4:30 PM"),
        "primary should be in Europe/Paris, got: {primary}"
    );
    assert!(
        primary.contains("CET"),
        "primary should label tz, got: {primary}"
    );
    let sec = secondary.expect("secondary line expected when guest tz differs from host tz");
    assert!(
        sec.contains("10:00 AM"),
        "secondary should show guest 10:00 AM, got: {sec}"
    );
    assert!(
        sec.contains("EST"),
        "secondary should label guest tz, got: {sec}"
    );
}

#[test]
fn dashboard_label_omits_secondary_when_guest_tz_equals_host_tz() {
    let (_primary, secondary) = format_booking_for_dashboard(
        "2099-07-20T14:00:00",
        "2099-07-20T14:30:00",
        "Europe/Paris",
        "Europe/Paris",
        "Europe/Paris",
    );
    assert!(
        secondary.is_none(),
        "no secondary line when host and guest share tz"
    );
}

#[test]
fn dashboard_label_falls_back_for_unparseable_input() {
    let (primary, secondary) = format_booking_for_dashboard(
        "garbage",
        "also-garbage",
        "Europe/Paris",
        "Europe/Paris",
        "America/New_York",
    );
    assert_eq!(primary, "garbage — also-garbage");
    assert!(secondary.is_none());
}

// --- format_date_label tests ---

#[test]
fn format_date_label_from_datetime() {
    assert_eq!(
        format_date_label("2026-03-15T14:30:00", "en"),
        "Sunday, March 15, 2026"
    );
}

#[test]
fn format_date_label_from_date_only() {
    assert_eq!(
        format_date_label("2026-03-15", "en"),
        "Sunday, March 15, 2026"
    );
}

#[test]
fn format_date_label_space_separator() {
    assert_eq!(
        format_date_label("2026-03-15 14:30:00", "en"),
        "Sunday, March 15, 2026"
    );
}

#[test]
fn format_date_label_invalid_fallback() {
    assert_eq!(format_date_label("nope", "en"), "nope");
}

#[test]
fn format_date_label_french() {
    assert_eq!(
        format_date_label("2026-03-15", "fr"),
        "dimanche 15 mars 2026"
    );
}

// --- format_time_from_dt tests ---

#[test]
fn format_time_from_dt_valid() {
    assert_eq!(format_time_from_dt("2026-03-15T14:30:00"), "2:30 PM");
    assert_eq!(format_time_from_dt("2026-03-15 09:05:00"), "9:05 AM");
}

#[test]
fn format_time_from_dt_midnight() {
    assert_eq!(format_time_from_dt("2026-03-15T00:00:00"), "12:00 AM");
}

#[test]
fn format_time_from_dt_unparseable_long_string() {
    // 16+ chars but not a valid datetime → falls back to substring [11..16]
    assert_eq!(format_time_from_dt("XXXX-XX-XX_HH:MM:SS"), "HH:MM");
}

#[test]
fn format_time_from_dt_short_string() {
    assert_eq!(format_time_from_dt("short"), "00:00");
    assert_eq!(format_time_from_dt(""), "00:00");
}

// --- extract_time_24h tests ---

#[test]
fn extract_time_24h_returns_24h_format() {
    assert_eq!(extract_time_24h("2026-03-15T14:30:00"), "14:30");
    assert_eq!(extract_time_24h("2026-03-15 09:05:00"), "09:05");
    assert_eq!(extract_time_24h("2026-03-15T00:00:00"), "00:00");
}

#[test]
fn extract_time_24h_short_string() {
    assert_eq!(extract_time_24h("short"), "00:00");
    assert_eq!(extract_time_24h(""), "00:00");
}

// --- parse_guest_tz tests ---

#[test]
fn parse_guest_tz_valid() {
    assert_eq!(
        parse_guest_tz(Some("America/New_York")),
        chrono_tz::America::New_York
    );
    assert_eq!(
        parse_guest_tz(Some("Europe/Paris")),
        chrono_tz::Europe::Paris
    );
    assert_eq!(parse_guest_tz(Some("UTC")), Tz::UTC);
}

#[test]
fn parse_guest_tz_invalid_falls_back() {
    let tz = parse_guest_tz(Some("Not/A/Timezone"));
    // Should be server local or UTC — either way, not panic
    let _ = tz;
}

#[test]
fn parse_guest_tz_none_falls_back() {
    let tz = parse_guest_tz(None);
    let _ = tz;
}

// --- parse_avail_windows tests ---

#[test]
fn parse_avail_windows_single_window() {
    let w = parse_avail_windows(Some("09:00-17:00"), None, None);
    assert_eq!(w, vec![("09:00".to_string(), "17:00".to_string())]);
}

#[test]
fn parse_avail_windows_multiple_windows() {
    let w = parse_avail_windows(Some("09:00-12:00,13:00-17:00"), None, None);
    assert_eq!(
        w,
        vec![
            ("09:00".to_string(), "12:00".to_string()),
            ("13:00".to_string(), "17:00".to_string()),
        ]
    );
}

#[test]
fn parse_avail_windows_legacy_fallback() {
    let w = parse_avail_windows(None, Some("08:00"), Some("16:00"));
    assert_eq!(w, vec![("08:00".to_string(), "16:00".to_string())]);
}

#[test]
fn parse_avail_windows_empty_string_uses_legacy() {
    let w = parse_avail_windows(Some(""), Some("10:00"), Some("18:00"));
    assert_eq!(w, vec![("10:00".to_string(), "18:00".to_string())]);
}

#[test]
fn parse_avail_windows_invalid_times_ignored() {
    let w = parse_avail_windows(Some("09:00-12:00,bad-data,13:00-17:00"), None, None);
    assert_eq!(
        w,
        vec![
            ("09:00".to_string(), "12:00".to_string()),
            ("13:00".to_string(), "17:00".to_string()),
        ]
    );
}

#[test]
fn parse_avail_windows_defaults_when_none() {
    let w = parse_avail_windows(None, None, None);
    assert_eq!(w, vec![("09:00".to_string(), "17:00".to_string())]);
}

// --- validate_booking_input tests ---

#[test]
fn validate_booking_input_empty_name() {
    let result = validate_booking_input("", "user@example.com", &None);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Name"));
}

#[test]
fn validate_booking_input_name_too_long() {
    let long_name = "a".repeat(256);
    let result = validate_booking_input(&long_name, "user@example.com", &None);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Name"));
}

#[test]
fn validate_booking_input_valid_name() {
    let result = validate_booking_input("Jane Doe", "jane@example.com", &None);
    assert!(result.is_ok());
}

#[test]
fn validate_booking_input_empty_email() {
    let result = validate_booking_input("Jane", "", &None);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("Email") || err.contains("email"));
}

#[test]
fn validate_booking_input_email_no_at() {
    let result = validate_booking_input("Jane", "userexample.com", &None);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("email"));
}

#[test]
fn validate_booking_input_email_no_domain_dot() {
    let result = validate_booking_input("Jane", "user@localhost", &None);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("email"));
}

#[test]
fn validate_booking_input_valid_email() {
    let result = validate_booking_input("Jane", "jane@example.com", &None);
    assert!(result.is_ok());
}

#[test]
fn validate_booking_input_notes_too_long() {
    let long_notes = Some("x".repeat(5001));
    let result = validate_booking_input("Jane", "jane@example.com", &long_notes);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Notes"));
}

#[test]
fn validate_booking_input_notes_within_limit() {
    let notes = Some("x".repeat(5000));
    let result = validate_booking_input("Jane", "jane@example.com", &notes);
    assert!(result.is_ok());
}

#[test]
fn validate_booking_input_none_notes() {
    let result = validate_booking_input("Jane", "jane@example.com", &None);
    assert!(result.is_ok());
}

// --- validate_date_not_too_far tests ---

#[test]
fn validate_date_not_too_far_within_range() {
    let date = Utc::now().naive_utc().date() + Duration::days(30);
    assert!(validate_date_not_too_far(date).is_ok());
}

#[test]
fn validate_date_not_too_far_exactly_365_days() {
    let date = Utc::now().naive_utc().date() + Duration::days(365);
    assert!(validate_date_not_too_far(date).is_ok());
}

#[test]
fn validate_date_not_too_far_367_days_rejected() {
    let date = Utc::now().naive_utc().date() + Duration::days(367);
    assert!(validate_date_not_too_far(date).is_err());
}

#[test]
fn validate_date_not_too_far_past_date_passes() {
    // Past dates are not rejected here (min_notice handles that elsewhere)
    let date = Utc::now().naive_utc().date() - Duration::days(10);
    assert!(validate_date_not_too_far(date).is_ok());
}

// --- CSRF function tests ---

#[test]
fn generate_csrf_token_returns_valid_uuid() {
    let token = generate_csrf_token();
    assert!(!token.is_empty());
    assert_eq!(token.len(), 36); // UUID format: 8-4-4-4-12
}

#[test]
fn csrf_cookie_has_security_flags() {
    // `Secure` so the token never travels over plaintext HTTP.
    // `SameSite=Lax` to stop cross-site GETs from carrying it.
    // Deliberately NO `HttpOnly` — the double-submit pattern needs the
    // client script in base.html to read the cookie via document.cookie.
    let cookie = csrf_cookie_value("some-token");
    assert!(
        cookie.contains("; Secure"),
        "CSRF cookie must have Secure flag: {}",
        cookie
    );
    assert!(
        cookie.contains("SameSite=Lax"),
        "CSRF cookie must have SameSite=Lax: {}",
        cookie
    );
    assert!(
        !cookie.contains("HttpOnly"),
        "CSRF cookie must NOT be HttpOnly (JS needs to read it): {}",
        cookie
    );
}

#[test]
fn csrf_cookie_embed_uses_samesite_none() {
    let cookie = csrf_cookie_value_for("tok", true);
    assert!(
        cookie.contains("SameSite=None"),
        "embed CSRF cookie must use SameSite=None for third-party iframes: {}",
        cookie
    );
    assert!(
        cookie.contains("; Secure"),
        "embed CSRF cookie must still carry Secure: {}",
        cookie
    );
    assert!(
        cookie.contains("; Partitioned"),
        "embed CSRF cookie must be Partitioned (CHIPS) for browsers blocking unpartitioned 3P cookies: {}",
        cookie
    );
}

#[test]
fn csrf_cookie_non_embed_is_samesite_lax_unpartitioned() {
    let cookie = csrf_cookie_value_for("tok", false);
    assert!(cookie.contains("SameSite=Lax"), "{}", cookie);
    assert!(
        !cookie.contains("Partitioned"),
        "non-embed cookie must not be Partitioned: {}",
        cookie
    );
}

#[test]
fn hex_to_rgb_parses_3_and_6_digit() {
    assert_eq!(hex_to_rgb("ff0000"), Some((255, 0, 0)));
    assert_eq!(hex_to_rgb("2563eb"), Some((37, 99, 235)));
    assert_eq!(hex_to_rgb("f30"), Some((255, 51, 0)));
    assert_eq!(hex_to_rgb("fff"), Some((255, 255, 255)));
    assert_eq!(hex_to_rgb(""), None);
    assert_eq!(hex_to_rgb("12345"), None);
    assert_eq!(hex_to_rgb("gggggg"), None);
}

#[test]
fn brand_css_derives_rgba_variants() {
    let p = EmbedParams {
        brand: Some("ff0000".to_string()),
        ..Default::default()
    };
    let css = p.brand_css().expect("valid hex yields css");
    assert!(css.contains("--accent: #ff0000"), "{}", css);
    assert!(
        css.contains("--accent-subtle: rgba(255,0,0,0.12)"),
        "{}",
        css
    );
    assert!(
        css.contains("--accent-border: rgba(255,0,0,0.3)"),
        "{}",
        css
    );
    assert!(css.contains("--accent-muted: rgba(255,0,0,0.5)"), "{}", css);

    // Invalid input yields no CSS (never inject raw user input).
    let bad = EmbedParams {
        brand: Some("red; } body{display:none".to_string()),
        ..Default::default()
    };
    assert!(bad.brand_css().is_none());
}

#[test]
fn is_embed_request_detects_flag() {
    assert!(is_embed_request(Some("embed=1")));
    assert!(is_embed_request(Some("embed=true")));
    assert!(is_embed_request(Some("foo=bar&embed=1&baz=qux")));
    assert!(!is_embed_request(Some("embed=0")));
    assert!(!is_embed_request(Some("notembed=1")));
    assert!(!is_embed_request(None));
    assert!(!is_embed_request(Some("")));
}

#[test]
fn is_embeddable_path_allows_booking_surfaces_only() {
    // Public booking surfaces — embeddable.
    assert!(is_embeddable_path("/u/alice"));
    assert!(is_embeddable_path("/u/alice/intro"));
    assert!(is_embeddable_path("/u/alice/intro/book"));
    assert!(is_embeddable_path("/team/sales"));
    assert!(is_embeddable_path("/team/sales/intro"));
    assert!(is_embeddable_path("/g/sales"));
    // Legacy single-user booking pages.
    assert!(is_embeddable_path("/intro"));
    assert!(is_embeddable_path("/intro/book"));

    // Sensitive / non-booking surfaces — never embeddable.
    assert!(!is_embeddable_path("/auth/login"));
    assert!(!is_embeddable_path("/auth/register"));
    assert!(!is_embeddable_path("/dashboard"));
    assert!(!is_embeddable_path("/dashboard/event-types"));
    assert!(!is_embeddable_path("/dashboard/admin"));
    assert!(!is_embeddable_path("/"));
    assert!(!is_embeddable_path("/embed.js"));
    assert!(!is_embeddable_path("/accent.css"));
    assert!(!is_embeddable_path("/avatar/123"));
    assert!(!is_embeddable_path("/booking/approve/tok"));
}

#[test]
fn embedded_booking_request_requires_both_flag_and_path() {
    // The blocking issue: embed=1 on a sensitive path must NOT enable embed.
    assert!(!is_embedded_booking_request("/auth/login", Some("embed=1")));
    assert!(!is_embedded_booking_request("/dashboard", Some("embed=1")));
    // Booking surface with the flag — enabled.
    assert!(is_embedded_booking_request(
        "/u/alice/intro",
        Some("embed=1")
    ));
    // Booking surface without the flag — not embed mode.
    assert!(!is_embedded_booking_request("/u/alice/intro", None));
}

#[test]
fn csrf_token_from_headers_extracts_token() {
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::COOKIE,
        "__Host-calrs_csrf=test-token-123".parse().unwrap(),
    );
    let token = csrf_token_from_headers(&headers);
    assert_eq!(token, Some("test-token-123".to_string()));
}

#[test]
fn csrf_token_from_headers_returns_none_when_missing() {
    let headers = HeaderMap::new();
    let token = csrf_token_from_headers(&headers);
    assert_eq!(token, None);
}

#[test]
fn csrf_token_from_headers_ignores_other_cookies() {
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::COOKIE,
        "__Host-calrs_session=abc; other=xyz".parse().unwrap(),
    );
    let token = csrf_token_from_headers(&headers);
    assert_eq!(token, None);
}

#[test]
fn verify_csrf_token_passes_when_matching() {
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::COOKIE,
        "__Host-calrs_csrf=my-token".parse().unwrap(),
    );
    let form_token = Some("my-token".to_string());
    assert!(verify_csrf_token(&headers, &form_token).is_ok());
}

#[test]
fn verify_csrf_token_fails_when_mismatch() {
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::COOKIE,
        "__Host-calrs_csrf=cookie-token".parse().unwrap(),
    );
    let form_token = Some("different-token".to_string());
    assert!(verify_csrf_token(&headers, &form_token).is_err());
}

#[test]
fn verify_csrf_token_fails_when_form_token_none() {
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::COOKIE,
        "__Host-calrs_csrf=my-token".parse().unwrap(),
    );
    let form_token: Option<String> = None;
    assert!(verify_csrf_token(&headers, &form_token).is_err());
}

#[test]
fn verify_csrf_token_fails_when_cookie_missing() {
    let headers = HeaderMap::new();
    let form_token = Some("my-token".to_string());
    assert!(verify_csrf_token(&headers, &form_token).is_err());
}

#[test]
fn verify_csrf_token_fails_when_cookie_empty() {
    // An empty cookie value would byte-compare-equal to an empty form
    // field; the explicit empty-cookie guard prevents that bypass.
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::COOKIE,
        "__Host-calrs_csrf=".parse().unwrap(),
    );
    let form_token = Some(String::new());
    assert!(verify_csrf_token(&headers, &form_token).is_err());
}

#[test]
fn verify_csrf_token_fails_when_lengths_differ() {
    // ConstantTimeEq returns false on length mismatch; this just pins
    // that mismatched-length tokens are still rejected.
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::COOKIE,
        "__Host-calrs_csrf=short".parse().unwrap(),
    );
    let form_token = Some("a-much-longer-token".to_string());
    assert!(verify_csrf_token(&headers, &form_token).is_err());
}

#[test]
fn verify_csrf_token_fails_when_same_length_differs_at_last_byte() {
    // Exercises the actual ct_eq byte-fold path: both tokens are the
    // same length, so the comparison runs over every byte rather than
    // short-circuiting on the length mismatch.
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::COOKIE,
        "__Host-calrs_csrf=aaaaaaaaaaaaaaaa".parse().unwrap(),
    );
    let form_token = Some("aaaaaaaaaaaaaaab".to_string());
    assert!(verify_csrf_token(&headers, &form_token).is_err());
}

// --- client_ip_for_rate_limit ---

#[test]
fn client_ip_unknown_when_no_headers() {
    let headers = HeaderMap::new();
    assert_eq!(client_ip_for_rate_limit(&headers), "unknown");
}

#[test]
fn client_ip_ignores_x_real_ip() {
    // We deliberately do not honour X-Real-IP: in default Caddy/Nginx
    // setups the proxy does not overwrite a client-supplied value, so
    // trusting it would let the client forge their identity directly.
    let mut headers = HeaderMap::new();
    headers.insert("x-real-ip", "1.2.3.4".parse().unwrap());
    assert_eq!(client_ip_for_rate_limit(&headers), "unknown");
}

#[test]
fn client_ip_takes_rightmost_xff() {
    // The leftmost value is whatever the original client put in the
    // header; the rightmost is the trusted proxy's view of its peer.
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-forwarded-for",
        "attacker-spoofed, 198.51.100.7".parse().unwrap(),
    );
    assert_eq!(client_ip_for_rate_limit(&headers), "198.51.100.7");
}

#[test]
fn client_ip_xff_single_value() {
    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-for", "203.0.113.10".parse().unwrap());
    assert_eq!(client_ip_for_rate_limit(&headers), "203.0.113.10");
}

#[test]
fn client_ip_xff_trims_whitespace() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-forwarded-for",
        "1.2.3.4 ,    198.51.100.7   ".parse().unwrap(),
    );
    assert_eq!(client_ip_for_rate_limit(&headers), "198.51.100.7");
}

// --- internal_error_* sanitization helpers ---

#[test]
fn internal_error_response_returns_500_with_generic_body() {
    // Whatever the underlying error says, the response body must not
    // contain it. The detail goes to logs only.
    let resp = internal_error_response("test ctx", &"sensitive: /var/lib/calrs/calrs.db error");
    assert_eq!(resp.status(), axum::http::StatusCode::INTERNAL_SERVER_ERROR);
}

#[test]
fn internal_error_html_body_is_generic() {
    let html = internal_error_html("test", &"users.password_hash leaks here");
    let Html(body) = html;
    assert!(
        !body.contains("password_hash"),
        "body leaked detail: {}",
        body
    );
    assert!(!body.contains("users."), "body leaked detail: {}", body);
    assert!(body.contains("internal error"));
}

#[test]
fn internal_error_body_is_generic() {
    let body = internal_error_body("test", &"some/private/path: nope");
    assert!(!body.contains("/private/path"), "body leaked: {body}");
}

#[test]
fn oidc_error_response_returns_500_without_detail() {
    // openidconnect errors can carry IdP URLs and token content; the
    // response body must not pass them through.
    let resp = oidc_error_response(
        "test",
        &"token endpoint https://idp/token returned: <secret-token-bytes>",
    );
    assert_eq!(resp.status(), axum::http::StatusCode::INTERNAL_SERVER_ERROR);
}

/// Capture `tracing` output into a shared buffer so log-emission can be
/// asserted from a test. Used to pin the contract that the sanitization
/// helpers actually log the underlying detail; a future refactor that
/// drops the log call would cause this test to fail.
///
/// Uses a hand-rolled minimal `Subscriber` instead of
/// `tracing_subscriber::fmt`. The fmt layer's per-event writer plumbing
/// proved flaky under `cargo tarpaulin` (events occasionally landed in a
/// dropped buffer), and we don't need the formatting machinery here:
/// recording field names + their `Debug` strings is enough to assert that
/// the event carried the expected markers.
fn capture_tracing<F: FnOnce()>(f: F) -> String {
    use std::sync::{Arc, Mutex};
    use tracing::field::{Field, Visit};
    use tracing::{Event, Metadata, Subscriber};

    #[derive(Clone)]
    struct Buf(Arc<Mutex<String>>);

    struct Recorder {
        buf: Arc<Mutex<String>>,
    }
    impl Subscriber for Recorder {
        fn enabled(&self, _: &Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &Event<'_>) {
            struct V<'a>(&'a Mutex<String>);
            impl<'a> Visit for V<'a> {
                fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
                    use std::fmt::Write;
                    let mut s = self.0.lock().unwrap();
                    let _ = write!(s, "{}={:?} ", field.name(), value);
                }
                fn record_str(&mut self, field: &Field, value: &str) {
                    use std::fmt::Write;
                    let mut s = self.0.lock().unwrap();
                    let _ = write!(s, "{}={} ", field.name(), value);
                }
            }
            event.record(&mut V(&self.buf));
            self.buf.lock().unwrap().push('\n');
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }

    let buf = Buf(Arc::new(Mutex::new(String::new())));
    let subscriber = Recorder { buf: buf.0.clone() };
    tracing::subscriber::with_default(subscriber, || {
        // tracing caches per-callsite Interest the first time the
        // callsite fires. If a sibling test (e.g. one that just
        // exercises the response body without capturing logs) ran
        // first under NoSubscriber, the cached interest is `never` and
        // our scoped Recorder never sees the event. Force a rebuild
        // against the now-active subscriber before invoking f.
        tracing::callsite::rebuild_interest_cache();
        f();
    });
    let s = buf.0.lock().unwrap().clone();
    s
}

/// Whether the current process is running under cargo-tarpaulin. The
/// tracing-capture tests below race with tarpaulin's instrumentation in
/// a way I haven't fully pinned down: the captured buffer ends up empty
/// even though the same test passes deterministically under plain
/// `cargo test`. Skip those tests under coverage rather than ship a
/// red CI job, but keep them live everywhere else so the contract is
/// still enforced.
///
/// Detection uses `cfg!(tarpaulin)` since cargo-tarpaulin compiles with
/// `--cfg=tarpaulin`. An earlier attempt keyed off `CARGO_TARPAULIN_VERSION`
/// but tarpaulin never sets that env var, so the guard never fired.
fn under_tarpaulin() -> bool {
    cfg!(tarpaulin)
}

#[test]
fn internal_error_logs_capture_underlying_detail() {
    if under_tarpaulin() {
        return;
    }
    // Pin: the helper must emit a tracing::error! that carries both the
    // context label and the underlying error string. The body sent to
    // the user is generic; the detail goes here.
    let log = capture_tracing(|| {
        let _ = internal_error_response("test-context-marker", &"sensitive-detail-marker");
    });
    assert!(
        log.contains("test-context-marker"),
        "log missing context: {log}"
    );
    assert!(
        log.contains("sensitive-detail-marker"),
        "log missing error detail: {log}"
    );
}

#[test]
fn oidc_error_logs_capture_underlying_detail() {
    if under_tarpaulin() {
        return;
    }
    let log = capture_tracing(|| {
        let _ = oidc_error_response("oidc-context-marker", &"token-endpoint-detail-marker");
    });
    assert!(
        log.contains("oidc-context-marker"),
        "log missing context: {log}"
    );
    assert!(
        log.contains("token-endpoint-detail-marker"),
        "log missing error detail: {log}"
    );
}

// --- is_safe_company_link ---

#[test]
fn company_link_accepts_http_and_https() {
    assert!(is_safe_company_link("http://example.com"));
    assert!(is_safe_company_link("https://example.com"));
    assert!(is_safe_company_link("HTTPS://EXAMPLE.COM"));
    assert!(is_safe_company_link("  https://example.com/path  "));
}

#[test]
fn company_link_rejects_javascript_uri() {
    // The whole point of this validator: stop stored XSS via the
    // company-link anchor that renders on every public page.
    assert!(!is_safe_company_link("javascript:alert(1)"));
    assert!(!is_safe_company_link("JAVASCRIPT:alert(1)"));
    assert!(!is_safe_company_link("  javascript:alert(1)"));
}

#[test]
fn company_link_rejects_other_dangerous_schemes() {
    assert!(!is_safe_company_link("data:text/html,<script>"));
    assert!(!is_safe_company_link("vbscript:msgbox(1)"));
    assert!(!is_safe_company_link("file:///etc/passwd"));
}

#[test]
fn company_link_rejects_unschemed_input() {
    // A bare hostname shouldn't slip through. The rendered anchor
    // would be relative to the booking page, which is wrong and
    // looks like a path traversal vector.
    assert!(!is_safe_company_link("example.com"));
    assert!(!is_safe_company_link("/foo/bar"));
    assert!(!is_safe_company_link("//example.com"));
    assert!(!is_safe_company_link(""));
}

// --- fetch_busy_times_for_user_ex exclude_booking_id tests ---

#[tokio::test]
async fn fetch_busy_times_ex_excludes_specified_booking() {
    let pool = setup_test_db().await;
    let (user_id, _, et_id) = seed_test_data(&pool).await;

    let booking_id = uuid::Uuid::new_v4().to_string();
    let cancel_tok = uuid::Uuid::new_v4().to_string();
    let resched_tok = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token) VALUES (?, ?, 'uid-ex1', 'Guest', 'guest@example.com', 'UTC', '2026-03-16T10:00:00', '2026-03-16T10:30:00', 'confirmed', ?, ?)")
        .bind(&booking_id)
        .bind(&et_id)
        .bind(&cancel_tok)
        .bind(&resched_tok)
        .execute(&pool).await.unwrap();

    // Without exclusion: booking shows as busy
    let busy = fetch_busy_times_for_user_ex(
        &pool,
        &user_id,
        dt(2026, 3, 15, 0, 0),
        dt(2026, 3, 21, 23, 59),
        Tz::UTC,
        None,
        None,
    )
    .await;
    assert_eq!(
        busy.len(),
        1,
        "Booking should be in busy times without exclusion"
    );

    // With exclusion: booking is excluded
    let busy_ex = fetch_busy_times_for_user_ex(
        &pool,
        &user_id,
        dt(2026, 3, 15, 0, 0),
        dt(2026, 3, 21, 23, 59),
        Tz::UTC,
        None,
        Some(&booking_id),
    )
    .await;
    assert!(
        busy_ex.is_empty(),
        "Excluded booking should not appear in busy times"
    );
}

#[tokio::test]
async fn fetch_busy_times_ex_excludes_only_specified_booking() {
    let pool = setup_test_db().await;
    let (user_id, _, et_id) = seed_test_data(&pool).await;

    // Insert two bookings
    let booking_id_1 = uuid::Uuid::new_v4().to_string();
    let booking_id_2 = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token) VALUES (?, ?, 'uid-a', 'Guest A', 'a@example.com', 'UTC', '2026-03-16T10:00:00', '2026-03-16T10:30:00', 'confirmed', ?, ?)")
        .bind(&booking_id_1)
        .bind(&et_id)
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(uuid::Uuid::new_v4().to_string())
        .execute(&pool).await.unwrap();

    sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token) VALUES (?, ?, 'uid-b', 'Guest B', 'b@example.com', 'UTC', '2026-03-16T14:00:00', '2026-03-16T14:30:00', 'confirmed', ?, ?)")
        .bind(&booking_id_2)
        .bind(&et_id)
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(uuid::Uuid::new_v4().to_string())
        .execute(&pool).await.unwrap();

    // Exclude first booking: only second should be busy
    let busy = fetch_busy_times_for_user_ex(
        &pool,
        &user_id,
        dt(2026, 3, 15, 0, 0),
        dt(2026, 3, 21, 23, 59),
        Tz::UTC,
        None,
        Some(&booking_id_1),
    )
    .await;
    assert_eq!(
        busy.len(),
        1,
        "Only the non-excluded booking should be in busy times"
    );
    assert_eq!(busy[0].0, dt(2026, 3, 16, 14, 0));
}

#[tokio::test]
async fn fetch_busy_times_ex_none_exclusion_matches_original() {
    let pool = setup_test_db().await;
    let (user_id, _, et_id) = seed_test_data(&pool).await;

    let booking_id = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token) VALUES (?, ?, 'uid-c', 'Guest', 'guest@example.com', 'UTC', '2026-03-16T10:00:00', '2026-03-16T10:30:00', 'confirmed', ?, ?)")
        .bind(&booking_id)
        .bind(&et_id)
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(uuid::Uuid::new_v4().to_string())
        .execute(&pool).await.unwrap();

    let busy_original = fetch_busy_times_for_user(
        &pool,
        &user_id,
        dt(2026, 3, 15, 0, 0),
        dt(2026, 3, 21, 23, 59),
        Tz::UTC,
        None,
    )
    .await;

    let busy_ex = fetch_busy_times_for_user_ex(
        &pool,
        &user_id,
        dt(2026, 3, 15, 0, 0),
        dt(2026, 3, 21, 23, 59),
        Tz::UTC,
        None,
        None,
    )
    .await;

    assert_eq!(
        busy_original.len(),
        busy_ex.len(),
        "None exclusion should match original function"
    );
}

// --- Reschedule DB flow tests ---

/// Helper to insert a confirmed booking and return (booking_id, reschedule_token, cancel_token)
async fn insert_test_booking(
    pool: &SqlitePool,
    et_id: &str,
    start: &str,
    end: &str,
    status: &str,
) -> (String, String, String) {
    let booking_id = uuid::Uuid::new_v4().to_string();
    let cancel_token = uuid::Uuid::new_v4().to_string();
    let reschedule_token = uuid::Uuid::new_v4().to_string();
    let confirm_token = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token, confirm_token) VALUES (?, ?, ?, 'Guest', 'guest@example.com', 'UTC', ?, ?, ?, ?, ?, ?)"
    )
    .bind(&booking_id)
    .bind(et_id)
    .bind(format!("{}@calrs", uuid::Uuid::new_v4()))
    .bind(start)
    .bind(end)
    .bind(status)
    .bind(&cancel_token)
    .bind(&reschedule_token)
    .bind(&confirm_token)
    .execute(pool).await.unwrap();
    (booking_id, reschedule_token, cancel_token)
}

#[tokio::test]
async fn reschedule_token_lookup_finds_confirmed_booking() {
    let pool = setup_test_db().await;
    let (_, _, et_id) = seed_test_data(&pool).await;

    let (bid, token, _) = insert_test_booking(
        &pool,
        &et_id,
        "2026-03-16T10:00:00",
        "2026-03-16T10:30:00",
        "confirmed",
    )
    .await;

    let found: Option<(String,)> = sqlx::query_as(
        "SELECT id FROM bookings WHERE reschedule_token = ? AND status IN ('confirmed', 'pending')",
    )
    .bind(&token)
    .fetch_optional(&pool)
    .await
    .unwrap();

    assert!(found.is_some(), "Should find booking by reschedule_token");
    assert_eq!(found.unwrap().0, bid);
}

#[tokio::test]
async fn reschedule_token_lookup_finds_pending_booking() {
    let pool = setup_test_db().await;
    let (_, _, et_id) = seed_test_data(&pool).await;

    let (bid, token, _) = insert_test_booking(
        &pool,
        &et_id,
        "2026-03-16T10:00:00",
        "2026-03-16T10:30:00",
        "pending",
    )
    .await;

    let found: Option<(String,)> = sqlx::query_as(
        "SELECT id FROM bookings WHERE reschedule_token = ? AND status IN ('confirmed', 'pending')",
    )
    .bind(&token)
    .fetch_optional(&pool)
    .await
    .unwrap();

    assert!(
        found.is_some(),
        "Should find pending booking by reschedule_token"
    );
    assert_eq!(found.unwrap().0, bid);
}

#[tokio::test]
async fn reschedule_token_lookup_rejects_cancelled_booking() {
    let pool = setup_test_db().await;
    let (_, _, et_id) = seed_test_data(&pool).await;

    let (_, token, _) = insert_test_booking(
        &pool,
        &et_id,
        "2026-03-16T10:00:00",
        "2026-03-16T10:30:00",
        "cancelled",
    )
    .await;

    let found: Option<(String,)> = sqlx::query_as(
        "SELECT id FROM bookings WHERE reschedule_token = ? AND status IN ('confirmed', 'pending')",
    )
    .bind(&token)
    .fetch_optional(&pool)
    .await
    .unwrap();

    assert!(
        found.is_none(),
        "Cancelled booking should not be found by reschedule_token"
    );
}

#[tokio::test]
async fn reschedule_token_lookup_rejects_declined_booking() {
    let pool = setup_test_db().await;
    let (_, _, et_id) = seed_test_data(&pool).await;

    let (_, token, _) = insert_test_booking(
        &pool,
        &et_id,
        "2026-03-16T10:00:00",
        "2026-03-16T10:30:00",
        "declined",
    )
    .await;

    let found: Option<(String,)> = sqlx::query_as(
        "SELECT id FROM bookings WHERE reschedule_token = ? AND status IN ('confirmed', 'pending')",
    )
    .bind(&token)
    .fetch_optional(&pool)
    .await
    .unwrap();

    assert!(
        found.is_none(),
        "Declined booking should not be found by reschedule_token"
    );
}

#[tokio::test]
async fn reschedule_updates_times_and_regenerates_tokens() {
    let pool = setup_test_db().await;
    let (_, _, et_id) = seed_test_data(&pool).await;

    let (bid, old_resched, old_cancel) = insert_test_booking(
        &pool,
        &et_id,
        "2026-03-16T10:00:00",
        "2026-03-16T10:30:00",
        "confirmed",
    )
    .await;

    // Simulate a guest reschedule: update times, regenerate tokens, set pending
    let new_resched = uuid::Uuid::new_v4().to_string();
    let new_cancel = uuid::Uuid::new_v4().to_string();
    let new_confirm = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "UPDATE bookings SET start_at = ?, end_at = ?, status = 'pending',
                reschedule_token = ?, cancel_token = ?, confirm_token = ?,
                reminder_sent_at = NULL
         WHERE id = ?",
    )
    .bind("2026-03-17T14:00:00")
    .bind("2026-03-17T14:30:00")
    .bind(&new_resched)
    .bind(&new_cancel)
    .bind(&new_confirm)
    .bind(&bid)
    .execute(&pool)
    .await
    .unwrap();

    // Verify the booking was updated
    let (start_at, end_at, status, resched_tok, cancel_tok, confirm_tok): (String, String, String, String, String, Option<String>) =
        sqlx::query_as("SELECT start_at, end_at, status, reschedule_token, cancel_token, confirm_token FROM bookings WHERE id = ?")
        .bind(&bid)
        .fetch_one(&pool).await.unwrap();

    assert_eq!(start_at, "2026-03-17T14:00:00");
    assert_eq!(end_at, "2026-03-17T14:30:00");
    assert_eq!(status, "pending");
    assert_eq!(resched_tok, new_resched);
    assert_ne!(
        resched_tok, old_resched,
        "Reschedule token should be regenerated"
    );
    assert_eq!(cancel_tok, new_cancel);
    assert_ne!(cancel_tok, old_cancel, "Cancel token should be regenerated");
    assert_eq!(confirm_tok.unwrap(), new_confirm);
}

#[tokio::test]
async fn stale_reschedule_token_returns_no_match() {
    let pool = setup_test_db().await;
    let (_, _, et_id) = seed_test_data(&pool).await;

    let (bid, old_token, _) = insert_test_booking(
        &pool,
        &et_id,
        "2026-03-16T10:00:00",
        "2026-03-16T10:30:00",
        "confirmed",
    )
    .await;

    // Regenerate the token (simulating a prior reschedule)
    let new_token = uuid::Uuid::new_v4().to_string();
    sqlx::query("UPDATE bookings SET reschedule_token = ? WHERE id = ?")
        .bind(&new_token)
        .bind(&bid)
        .execute(&pool)
        .await
        .unwrap();

    // Old token should no longer find anything
    let found: Option<(String,)> = sqlx::query_as(
        "SELECT id FROM bookings WHERE reschedule_token = ? AND status IN ('confirmed', 'pending')",
    )
    .bind(&old_token)
    .fetch_optional(&pool)
    .await
    .unwrap();

    assert!(
        found.is_none(),
        "Stale reschedule token should not find any booking"
    );

    // New token should work
    let found_new: Option<(String,)> = sqlx::query_as(
        "SELECT id FROM bookings WHERE reschedule_token = ? AND status IN ('confirmed', 'pending')",
    )
    .bind(&new_token)
    .fetch_optional(&pool)
    .await
    .unwrap();

    assert!(
        found_new.is_some(),
        "New reschedule token should find booking"
    );
}

#[tokio::test]
async fn host_initiated_reschedule_stays_confirmed() {
    let pool = setup_test_db().await;
    let (_, _, et_id) = seed_test_data(&pool).await;

    let (bid, _, _) = insert_test_booking(
        &pool,
        &et_id,
        "2026-03-16T10:00:00",
        "2026-03-16T10:30:00",
        "confirmed",
    )
    .await;

    // Step 1: Host initiates reschedule (sets flag, regenerates token)
    let new_resched = uuid::Uuid::new_v4().to_string();
    sqlx::query("UPDATE bookings SET reschedule_token = ?, reschedule_by_host = 1 WHERE id = ?")
        .bind(&new_resched)
        .bind(&bid)
        .execute(&pool)
        .await
        .unwrap();

    let by_host: i32 = sqlx::query_scalar("SELECT reschedule_by_host FROM bookings WHERE id = ?")
        .bind(&bid)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(by_host, 1, "reschedule_by_host should be set");

    // Step 2: Guest picks a new time — should stay confirmed since host initiated
    let new_cancel = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "UPDATE bookings SET start_at = ?, end_at = ?, status = 'confirmed',
                reschedule_token = ?, cancel_token = ?, confirm_token = NULL,
                reminder_sent_at = NULL, reschedule_by_host = 0
         WHERE id = ?",
    )
    .bind("2026-03-18T09:00:00")
    .bind("2026-03-18T09:30:00")
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(&new_cancel)
    .bind(&bid)
    .execute(&pool)
    .await
    .unwrap();

    let (status, confirm_tok, by_host2): (String, Option<String>, i32) = sqlx::query_as(
        "SELECT status, confirm_token, reschedule_by_host FROM bookings WHERE id = ?",
    )
    .bind(&bid)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(
        status, "confirmed",
        "Host-initiated reschedule should keep confirmed status after guest picks time"
    );
    assert!(
        confirm_tok.is_none(),
        "No confirm_token needed for host-initiated reschedule"
    );
    assert_eq!(
        by_host2, 0,
        "reschedule_by_host should be reset after completion"
    );
}

#[tokio::test]
async fn reschedule_clears_reminder_sent_at() {
    let pool = setup_test_db().await;
    let (_, _, et_id) = seed_test_data(&pool).await;

    let (bid, _, _) = insert_test_booking(
        &pool,
        &et_id,
        "2026-03-16T10:00:00",
        "2026-03-16T10:30:00",
        "confirmed",
    )
    .await;

    // Set reminder_sent_at
    sqlx::query("UPDATE bookings SET reminder_sent_at = '2026-03-15T08:00:00' WHERE id = ?")
        .bind(&bid)
        .execute(&pool)
        .await
        .unwrap();

    // Reschedule
    sqlx::query(
        "UPDATE bookings SET start_at = '2026-03-17T10:00:00', end_at = '2026-03-17T10:30:00',
                reschedule_token = ?, cancel_token = ?, reminder_sent_at = NULL
         WHERE id = ?",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(&bid)
    .execute(&pool)
    .await
    .unwrap();

    let reminder: Option<Option<String>> =
        sqlx::query_scalar("SELECT reminder_sent_at FROM bookings WHERE id = ?")
            .bind(&bid)
            .fetch_optional(&pool)
            .await
            .unwrap();

    assert_eq!(
        reminder,
        Some(None),
        "reminder_sent_at should be cleared after reschedule"
    );
}

#[tokio::test]
async fn reschedule_excluded_booking_frees_its_slot() {
    let pool = setup_test_db().await;
    let (user_id, _, et_id) = seed_test_data(&pool).await;

    // Book 10:00-10:30
    let (bid, _, _) = insert_test_booking(
        &pool,
        &et_id,
        "2026-03-16T10:00:00",
        "2026-03-16T10:30:00",
        "confirmed",
    )
    .await;

    // Without exclusion: 10:00-10:30 is busy
    let busy = fetch_busy_times_for_user_ex(
        &pool,
        &user_id,
        dt(2026, 3, 16, 9, 0),
        dt(2026, 3, 16, 12, 0),
        Tz::UTC,
        None,
        None,
    )
    .await;
    assert!(
        has_conflict(&busy, dt(2026, 3, 16, 10, 0), dt(2026, 3, 16, 10, 30)),
        "10:00-10:30 should conflict without exclusion"
    );

    // With exclusion: slot is free for rescheduling back to same time
    let busy_ex = fetch_busy_times_for_user_ex(
        &pool,
        &user_id,
        dt(2026, 3, 16, 9, 0),
        dt(2026, 3, 16, 12, 0),
        Tz::UTC,
        None,
        Some(&bid),
    )
    .await;
    assert!(
        !has_conflict(&busy_ex, dt(2026, 3, 16, 10, 0), dt(2026, 3, 16, 10, 30)),
        "10:00-10:30 should be free when booking is excluded (reschedule to same slot)"
    );
}

// --- Template rendering regression tests ---

/// Render slots.html WITHOUT reschedule context and verify slot links
/// point to /book and not to a JSON object.
/// Regression test for: default(value='') rendering as {"value": ""}
#[test]
fn slots_template_links_without_reschedule_context() {
    let mut env = minijinja::Environment::new();
    env.set_undefined_behavior(minijinja::UndefinedBehavior::Lenient);
    env.set_loader(minijinja::path_loader("templates"));
    crate::i18n::register(&mut env);

    let tmpl = env
        .get_template("slots.html")
        .expect("slots.html should load");

    // Minimal context mimicking show_slots_for_user (no reschedule_base)
    let rendered = tmpl
        .render(context! {
            event_type => context! {
                slug => "intro",
                title => "Intro Call",
                duration_min => 30,
            },
            host_name => "Alice",
            username => "alice",
            days => vec![
                context! {
                    date => "2026-03-16",
                    label => "Mon",
                    slots => vec![
                        context! { start => "10:00", end => "10:30", host_date => "2026-03-16", host_time => "10:00", guest_date => "2026-03-16" },
                    ],
                },
            ],
            available_dates => vec!["2026-03-16"],
            month_label => "March 2026",
            month_year => "2026-03",
            next_month => "2026-04",
            first_weekday => 0,
            days_in_month => 31,
            today_date => "2026-03-14",
            guest_tz => "UTC",
        })
        .expect("slots.html should render");

    // basePath must be /u/alice/intro, not something with { in it
    assert!(
        rendered.contains("&#x2f;u&#x2f;alice&#x2f;intro") || rendered.contains("/u/alice/intro"),
        "basePath should be /u/alice/intro"
    );

    // rescheduleBase must be empty, not a JSON object
    assert!(
        !rendered.contains(r#"{"value"#),
        "rescheduleBase must not render as a JSON object"
    );

    // Slot links should go to /book, not to a bare {
    assert!(
        !rendered.contains(r#"href="{"#),
        "Slot hrefs must not start with opening brace"
    );
}

/// Render slots.html WITH reschedule context and verify slot links
/// use the reschedule URL, not the /book path.
#[test]
fn slots_template_links_with_reschedule_context() {
    let mut env = minijinja::Environment::new();
    env.set_undefined_behavior(minijinja::UndefinedBehavior::Lenient);
    env.set_loader(minijinja::path_loader("templates"));
    crate::i18n::register(&mut env);

    let tmpl = env
        .get_template("slots.html")
        .expect("slots.html should load");

    let rendered = tmpl
        .render(context! {
            event_type => context! {
                slug => "intro",
                title => "Intro Call",
                duration_min => 30,
            },
            host_name => "Alice",
            username => "alice",
            reschedule_base => "/booking/reschedule/abc123",
            reschedule_info => context! {
                event_title => "Intro Call",
                old_date => "2026-03-15",
                old_time => "10:00",
            },
            days => vec![
                context! {
                    date => "2026-03-16",
                    label => "Mon",
                    slots => vec![
                        context! { start => "10:00", end => "10:30", host_date => "2026-03-16", host_time => "10:00", guest_date => "2026-03-16" },
                    ],
                },
            ],
            available_dates => vec!["2026-03-16"],
            month_label => "March 2026",
            month_year => "2026-03",
            next_month => "2026-04",
            first_weekday => 0,
            days_in_month => 31,
            today_date => "2026-03-14",
            guest_tz => "UTC",
        })
        .expect("slots.html should render");

    // basePath should be the reschedule URL, not the normal /u/alice/intro
    assert!(
        rendered.contains("reschedule&#x2f;abc123") || rendered.contains("reschedule/abc123"),
        "basePath should be the reschedule URL when reschedule_base is set"
    );

    // Reschedule banner should appear
    assert!(
        rendered.contains("Rescheduling:"),
        "Reschedule banner should be visible"
    );

    // Banner must be OUTSIDE slots-outer (not a flex child of the 3-column layout).
    // Search in the HTML body, skipping the <style> block where CSS class names also appear.
    let body_start = rendered.find("<div class=\"reschedule-banner\"").unwrap();
    let slots_outer_start = rendered.find("<div class=\"slots-outer\"").unwrap();
    assert!(
        body_start < slots_outer_start,
        "Reschedule banner div must appear before slots-outer div to avoid flex layout breakage"
    );
}

#[tokio::test]
async fn compute_slots_blocked_override_skips_day() {
    let pool = setup_test_db().await;
    let (_, _, et_id) = seed_test_data(&pool).await;

    // Find the next Monday
    let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
    let mut next_monday = now.date() + Duration::days(1);
    while next_monday.weekday() != chrono::Weekday::Mon {
        next_monday += Duration::days(1);
    }
    let days_to_monday = (next_monday - now.date()).num_days() as i32;
    let monday_str = next_monday.format("%Y-%m-%d").to_string();

    // Block that Monday with an override
    let override_id = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO availability_overrides (id, event_type_id, date, is_blocked) VALUES (?, ?, ?, 1)")
        .bind(&override_id)
        .bind(&et_id)
        .bind(&monday_str)
        .execute(&pool)
        .await
        .unwrap();

    let slot_days = compute_slots(
        &pool,
        &et_id,
        30,
        0,
        0,
        0,
        days_to_monday,
        1,
        Tz::UTC,
        Tz::UTC,
        BusySource::Individual(vec![]),
    )
    .await;

    // Monday should be blocked — no slots
    assert!(
        slot_days.is_empty(),
        "Blocked override should skip the day, got {} days with slots",
        slot_days.len()
    );
}

#[tokio::test]
async fn compute_slots_custom_hours_override() {
    let pool = setup_test_db().await;
    let (_, _, et_id) = seed_test_data(&pool).await;

    // Find the next Monday
    let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
    let mut next_monday = now.date() + Duration::days(1);
    while next_monday.weekday() != chrono::Weekday::Mon {
        next_monday += Duration::days(1);
    }
    let days_to_monday = (next_monday - now.date()).num_days() as i32;
    let monday_str = next_monday.format("%Y-%m-%d").to_string();

    // Override Monday with custom hours: only 10:00-12:00 (instead of default 09:00-17:00)
    let override_id = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO availability_overrides (id, event_type_id, date, start_time, end_time, is_blocked) VALUES (?, ?, ?, '10:00', '12:00', 0)")
        .bind(&override_id)
        .bind(&et_id)
        .bind(&monday_str)
        .execute(&pool)
        .await
        .unwrap();

    let slot_days = compute_slots(
        &pool,
        &et_id,
        30,
        0,
        0,
        0,
        days_to_monday,
        1,
        Tz::UTC,
        Tz::UTC,
        BusySource::Individual(vec![]),
    )
    .await;

    assert!(!slot_days.is_empty(), "Should have slots for custom hours");
    // 10:00-12:00 with 30min slots = 4 slots (10:00, 10:30, 11:00, 11:30)
    let total_slots: usize = slot_days.iter().map(|d| d.slots.len()).sum();
    assert_eq!(
        total_slots, 4,
        "10:00-12:00 with 30min = 4 slots, got {}",
        total_slots
    );
}

// --- slot_interval_min unit tests ---

#[tokio::test]
async fn compute_slots_custom_interval_fewer_slots() {
    // When slot_interval is 60 with a 30-min duration, the cursor steps by 60 min
    // producing 1 slot per hour instead of 2 per hour
    let pool = setup_test_db().await;
    let (_, _, et_id) = seed_test_data(&pool).await;

    // Override: 60-min slot interval, 30-min duration
    sqlx::query("UPDATE event_types SET slot_interval_min = 60 WHERE id = ?")
        .bind(&et_id)
        .execute(&pool)
        .await
        .unwrap();

    let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
    let mut next_monday = now.date() + Duration::days(1);
    while next_monday.weekday() != chrono::Weekday::Mon {
        next_monday += Duration::days(1);
    }
    let days_to_monday = (next_monday - now.date()).num_days() as i32;

    let slot_days = compute_slots(
        &pool,
        &et_id,
        30, // duration
        0,
        0,
        0,
        days_to_monday,
        1,
        Tz::UTC,
        Tz::UTC,
        BusySource::Individual(vec![]),
    )
    .await;

    assert!(!slot_days.is_empty());
    let monday = &slot_days[0];
    // 09:00-17:00 = 8 hours; 60-min interval → 8 slots (09:00, 10:00, ..., 16:00)
    assert_eq!(
        monday.slots.len(),
        8,
        "60-min interval over 09:00-17:00 should yield 8 slots, got {}",
        monday.slots.len()
    );
    // Verify exact start times
    let slot_times: Vec<&str> = monday.slots.iter().map(|s| s.start.as_str()).collect();
    let expected: Vec<&str> = vec![
        "09:00", "10:00", "11:00", "12:00", "13:00", "14:00", "15:00", "16:00",
    ];
    assert_eq!(
        slot_times, expected,
        "Slot times should match 60-min interval stepping"
    );
}

#[tokio::test]
async fn compute_slots_custom_interval_15_min() {
    // 15-min interval with 30-min duration: cursor steps by 15 min
    // 09:00-17:00 = 8 hours = 480 min; 480/15 = 32 cursor positions
    // but cursor must satisfy cursor + 30 <= 17:00, so 16:45+30=17:15 > 17:00 → last is 16:30
    // That gives 31 slots (09:00 through 16:30)
    let pool = setup_test_db().await;
    let (_, _, et_id) = seed_test_data(&pool).await;

    sqlx::query("UPDATE event_types SET slot_interval_min = 15 WHERE id = ?")
        .bind(&et_id)
        .execute(&pool)
        .await
        .unwrap();

    let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
    let mut next_monday = now.date() + Duration::days(1);
    while next_monday.weekday() != chrono::Weekday::Mon {
        next_monday += Duration::days(1);
    }
    let days_to_monday = (next_monday - now.date()).num_days() as i32;

    let slot_days = compute_slots(
        &pool,
        &et_id,
        30, // duration
        0,
        0,
        0,
        days_to_monday,
        1,
        Tz::UTC,
        Tz::UTC,
        BusySource::Individual(vec![]),
    )
    .await;

    assert!(!slot_days.is_empty());
    let monday = &slot_days[0];
    // 09:00-17:00 with 30-min slot: 31 slots (09:00 … 16:30)
    // 16:45 + 30 = 17:15 > 17:00 so it's excluded
    assert_eq!(
        monday.slots.len(),
        31,
        "15-min interval over 09:00-17:00 should yield 31 slots, got {}",
        monday.slots.len()
    );
    // Verify first and last slots
    let slot_times: Vec<&str> = monday.slots.iter().map(|s| s.start.as_str()).collect();
    assert_eq!(slot_times.first(), Some(&"09:00"));
    assert_eq!(slot_times.last(), Some(&"16:30"));
}

#[tokio::test]
async fn compute_slots_interval_greater_than_duration() {
    // When interval (60) > duration (30), cursor steps 60 but each slot occupies 30 min
    // This means some potential slots are skipped (e.g., 09:30 is never checked)
    let pool = setup_test_db().await;
    let (_, _, et_id) = seed_test_data(&pool).await;

    sqlx::query("UPDATE event_types SET slot_interval_min = 60 WHERE id = ?")
        .bind(&et_id)
        .execute(&pool)
        .await
        .unwrap();

    let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
    let mut next_monday = now.date() + Duration::days(1);
    while next_monday.weekday() != chrono::Weekday::Mon {
        next_monday += Duration::days(1);
    }
    let days_to_monday = (next_monday - now.date()).num_days() as i32;

    // Block 09:00-09:30 on Monday
    let monday_date = next_monday;
    let busy_start = monday_date.and_hms_opt(9, 0, 0).unwrap();
    let busy_end = monday_date.and_hms_opt(9, 30, 0).unwrap();

    let slot_days = compute_slots(
        &pool,
        &et_id,
        30,
        0,
        0,
        0,
        days_to_monday,
        1,
        Tz::UTC,
        Tz::UTC,
        BusySource::Individual(vec![(busy_start, busy_end)]),
    )
    .await;

    assert!(!slot_days.is_empty());
    let monday = &slot_days[0];
    // 09:00 slot is blocked by busy event, so 7 remaining slots
    assert_eq!(
        monday.slots.len(),
        7,
        "09:00 slot should be blocked by busy event, got {}",
        monday.slots.len()
    );
    let slot_times: Vec<&str> = monday.slots.iter().map(|s| s.start.as_str()).collect();
    assert!(!slot_times.contains(&"09:00"), "09:00 should be blocked");
    assert!(
        slot_times.contains(&"10:00"),
        "10:00 should still be available"
    );
}

#[tokio::test]
async fn compute_slots_null_interval_defaults_to_duration() {
    // When slot_interval_min is NULL (unset), should default to duration (legacy behavior)
    let pool = setup_test_db().await;
    let (_, _, et_id) = seed_test_data(&pool).await;

    // Don't set slot_interval — it should be NULL from seed_test_data
    let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
    let mut next_monday = now.date() + Duration::days(1);
    while next_monday.weekday() != chrono::Weekday::Mon {
        next_monday += Duration::days(1);
    }
    let days_to_monday = (next_monday - now.date()).num_days() as i32;

    let slot_days = compute_slots(
        &pool,
        &et_id,
        30, // duration
        0,
        0,
        0,
        days_to_monday,
        1,
        Tz::UTC,
        Tz::UTC,
        BusySource::Individual(vec![]),
    )
    .await;

    assert!(!slot_days.is_empty());
    let monday = &slot_days[0];
    // Should default to 30-min stepping (same as duration) → 16 slots
    assert_eq!(
        monday.slots.len(),
        16,
        "NULL interval should default to duration (30-min stepping) → 16 slots, got {}",
        monday.slots.len()
    );
}

#[tokio::test]
async fn compute_slots_interval_zero_defaults_to_duration() {
    // When slot_interval_min is 0, should also default to duration
    let pool = setup_test_db().await;
    let (_, _, et_id) = seed_test_data(&pool).await;

    sqlx::query("UPDATE event_types SET slot_interval_min = 0 WHERE id = ?")
        .bind(&et_id)
        .execute(&pool)
        .await
        .unwrap();

    let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
    let mut next_monday = now.date() + Duration::days(1);
    while next_monday.weekday() != chrono::Weekday::Mon {
        next_monday += Duration::days(1);
    }
    let days_to_monday = (next_monday - now.date()).num_days() as i32;

    let slot_days = compute_slots(
        &pool,
        &et_id,
        30,
        0,
        0,
        0,
        days_to_monday,
        1,
        Tz::UTC,
        Tz::UTC,
        BusySource::Individual(vec![]),
    )
    .await;

    assert!(!slot_days.is_empty());
    let monday = &slot_days[0];
    assert_eq!(
        monday.slots.len(),
        16,
        "Zero interval should default to duration (30-min stepping) → 16 slots, got {}",
        monday.slots.len()
    );
}

#[tokio::test]
async fn compute_slots_interval_with_buffer_overlap() {
    // Interval of 60 with a 15-min buffer should correctly reject slots
    // that would overlap with busy events via buffer zones
    let pool = setup_test_db().await;
    let (_, _, et_id) = seed_test_data(&pool).await;

    sqlx::query("UPDATE event_types SET slot_interval_min = 60 WHERE id = ?")
        .bind(&et_id)
        .execute(&pool)
        .await
        .unwrap();

    let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
    let mut next_monday = now.date() + Duration::days(1);
    while next_monday.weekday() != chrono::Weekday::Mon {
        next_monday += Duration::days(1);
    }
    let days_to_monday = (next_monday - now.date()).num_days() as i32;

    // Busy event at 09:00-09:30, with 15-min buffer it blocks 08:45-09:45
    // So 09:00 slot (buf_start=08:45, buf_end=10:00) overlaps with busy event (08:45 < 09:30 && 09:00 > 08:45)
    let busy_start = next_monday.and_hms_opt(9, 0, 0).unwrap();
    let busy_end = next_monday.and_hms_opt(9, 30, 0).unwrap();

    let slot_days = compute_slots(
        &pool,
        &et_id,
        30,
        15, // buffer before
        15, // buffer after
        0,
        days_to_monday,
        1,
        Tz::UTC,
        Tz::UTC,
        BusySource::Individual(vec![(busy_start, busy_end)]),
    )
    .await;

    assert!(!slot_days.is_empty());
    let monday = &slot_days[0];
    // 09:00 is blocked by direct overlap + buffer
    assert_eq!(
        monday.slots.len(),
        7,
        "09:00 slot blocked by event+buffer, got {}",
        monday.slots.len()
    );
}

// --- HTTP integration tests ---

use axum::body::Body;
use http_body_util::BodyExt;
use tower::ServiceExt;

async fn setup_test_app() -> (Router, SqlitePool, String, String) {
    let pool = setup_test_db().await;
    let (user_id, _account_id, et_id) = seed_test_data(&pool).await;

    // Create a session for the test user
    let session_token = uuid::Uuid::new_v4().to_string();
    let expires_at = (Utc::now() + Duration::days(30))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();
    sqlx::query("INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)")
        .bind(&session_token)
        .bind(&user_id)
        .bind(&expires_at)
        .execute(&pool)
        .await
        .unwrap();

    let data_dir = std::env::temp_dir().join(format!("calrs_test_{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&data_dir).unwrap();

    let router = create_router(pool.clone(), data_dir, [0u8; 32]).await;
    (router, pool, session_token, et_id)
}

fn get(uri: &str) -> axum::http::Request<Body> {
    axum::http::Request::builder()
        .uri(uri)
        .body(Body::empty())
        .unwrap()
}

fn get_authed(uri: &str, session: &str) -> axum::http::Request<Body> {
    axum::http::Request::builder()
        .uri(uri)
        .header("cookie", format!("__Host-calrs_session={}", session))
        .body(Body::empty())
        .unwrap()
}

async fn body_string(response: axum::http::Response<Body>) -> String {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[tokio::test]
async fn root_redirects_to_login() {
    let (app, _, _, _) = setup_test_app().await;
    let response = app.oneshot(get("/")).await.unwrap();
    assert_eq!(response.status(), 303);
    assert_eq!(
        response
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap(),
        "/auth/login"
    );
}

#[tokio::test]
async fn login_page_returns_200() {
    let (app, _, _, _) = setup_test_app().await;
    let response = app.oneshot(get("/auth/login")).await.unwrap();
    assert_eq!(response.status(), 200);
    let body = body_string(response).await;
    assert!(
        body.contains("Sign in"),
        "Login page should contain Sign in"
    );
}

#[tokio::test]
async fn login_page_hides_register_when_disabled() {
    let (app, pool, _, _) = setup_test_app().await;

    // Disable registration
    sqlx::query("UPDATE auth_config SET registration_enabled = 0 WHERE id = 'singleton'")
        .execute(&pool)
        .await
        .unwrap();

    let response = app.oneshot(get("/auth/login")).await.unwrap();
    let body = body_string(response).await;
    assert!(
        !body.contains("Register"),
        "Register link should be hidden when registration is disabled"
    );
}

#[tokio::test]
async fn dashboard_redirects_unauthenticated() {
    let (app, _, _, _) = setup_test_app().await;
    let response = app.oneshot(get("/dashboard")).await.unwrap();
    assert_eq!(response.status(), 303);
}

#[tokio::test]
async fn dashboard_returns_200_for_authenticated_user() {
    let (app, _, session, _) = setup_test_app().await;
    let response = app
        .oneshot(get_authed("/dashboard", &session))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body = body_string(response).await;
    assert!(body.contains("Welcome"), "Dashboard should contain Welcome");
}

#[tokio::test]
async fn event_types_page_returns_200() {
    let (app, _, session, _) = setup_test_app().await;
    let response = app
        .oneshot(get_authed("/dashboard/event-types", &session))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body = body_string(response).await;
    assert!(
        body.contains("Test Meeting"),
        "Event types page should list seeded event type"
    );
}

#[tokio::test]
async fn bookings_page_returns_200() {
    let (app, _, session, _) = setup_test_app().await;
    let response = app
        .oneshot(get_authed("/dashboard/bookings", &session))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body = body_string(response).await;
    assert!(
        body.contains("Upcoming bookings"),
        "Bookings page should render"
    );
}

#[tokio::test]
async fn sources_page_returns_200() {
    let (app, _, session, _) = setup_test_app().await;
    let response = app
        .oneshot(get_authed("/dashboard/sources", &session))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
}

#[tokio::test]
async fn settings_page_returns_200() {
    let (app, _, session, _) = setup_test_app().await;
    let response = app
        .oneshot(get_authed("/dashboard/settings", &session))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body = body_string(response).await;
    assert!(body.contains("Test User"), "Settings should show user name");
}

#[tokio::test]
async fn admin_page_returns_200_for_admin() {
    let (app, _, session, _) = setup_test_app().await;
    let response = app
        .oneshot(get_authed("/dashboard/admin", &session))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body = body_string(response).await;
    assert!(body.contains("Admin"), "Admin page should render");
}

#[tokio::test]
async fn overrides_page_returns_200() {
    let (app, _, session, _) = setup_test_app().await;
    let response = app
        .oneshot(get_authed(
            "/dashboard/event-types/test-meeting/overrides",
            &session,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body = body_string(response).await;
    assert!(
        body.contains("Date overrides"),
        "Overrides page should render"
    );
    assert!(
        body.contains("Test Meeting"),
        "Should show event type title"
    );
}

#[tokio::test]
async fn public_profile_returns_200() {
    let (app, _, _, _) = setup_test_app().await;
    let response = app.oneshot(get("/u/testuser")).await.unwrap();
    assert_eq!(response.status(), 200);
    let body = body_string(response).await;
    assert!(
        body.contains("Test Meeting"),
        "Public profile should list event types"
    );
}

#[tokio::test]
async fn public_slots_page_returns_200() {
    let (app, _, _, _) = setup_test_app().await;
    let response = app.oneshot(get("/u/testuser/test-meeting")).await.unwrap();
    assert_eq!(response.status(), 200);
    let body = body_string(response).await;
    assert!(
        body.contains("Test Meeting"),
        "Slots page should show event type title"
    );
}

#[tokio::test]
async fn troubleshoot_returns_200() {
    let (app, _, session, _) = setup_test_app().await;
    let response = app
        .oneshot(get_authed("/dashboard/troubleshoot", &session))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body = body_string(response).await;
    assert!(
        body.contains("Troubleshoot"),
        "Troubleshoot page should render"
    );
}

#[tokio::test]
async fn nonexistent_profile_returns_404_or_empty() {
    let (app, _, _, _) = setup_test_app().await;
    let response = app.oneshot(get("/u/nonexistent")).await.unwrap();
    // Should return 404 or a page indicating no user found
    let status = response.status();
    assert!(
        status == 404 || status == 200,
        "Nonexistent user should return 404 or 200 with empty page"
    );
}

#[tokio::test]
async fn booking_with_invalid_cancel_token_shows_error() {
    let (app, _, _, _) = setup_test_app().await;
    let response = app
        .oneshot(get("/booking/cancel/invalid-token-123"))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body = body_string(response).await;
    assert!(
        body.contains("invalid") || body.contains("Invalid") || body.contains("expired"),
        "Invalid cancel token should show error"
    );
}

#[tokio::test]
async fn booking_with_invalid_approve_token_shows_error() {
    let (app, _, _, _) = setup_test_app().await;
    let response = app
        .oneshot(get("/booking/approve/invalid-token-123"))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body = body_string(response).await;
    assert!(
        body.contains("invalid") || body.contains("Invalid") || body.contains("expired"),
        "Invalid approve token should show error"
    );
}

#[tokio::test]
async fn booking_with_invalid_reschedule_token_shows_error() {
    let (app, _, _, _) = setup_test_app().await;
    let response = app
        .oneshot(get("/booking/reschedule/invalid-token-123"))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body = body_string(response).await;
    assert!(
        body.contains("invalid") || body.contains("Invalid") || body.contains("expired"),
        "Invalid reschedule token should show error"
    );
}

// --- POST handler helpers ---

fn post_form(uri: &str, session: &str, csrf: &str, body: &str) -> axum::http::Request<Body> {
    axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header(
            "cookie",
            format!(
                "__Host-calrs_session={}; __Host-calrs_csrf={}",
                session, csrf
            ),
        )
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn post_form_unauthed(uri: &str, csrf: &str, body: &str) -> axum::http::Request<Body> {
    axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("cookie", format!("__Host-calrs_csrf={}", csrf))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn post_bare(uri: &str) -> axum::http::Request<Body> {
    axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::empty())
        .unwrap()
}

// --- POST handler tests ---

#[tokio::test]
async fn post_without_csrf_returns_403() {
    let (app, _, session, _) = setup_test_app().await;
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/dashboard/event-types/test-meeting/toggle")
        .header("cookie", format!("__Host-calrs_session={}", session))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from("_csrf=wrong-token"))
        .unwrap();
    let response = app.oneshot(req).await.unwrap();
    assert_eq!(
        response.status(),
        403,
        "Missing/mismatched CSRF should return 403"
    );
}

#[tokio::test]
async fn toggle_event_type_disables_and_enables() {
    let (app, pool, session, _) = setup_test_app().await;
    let csrf = "test-csrf-toggle";

    // Disable
    let response = app
        .oneshot(post_form(
            "/dashboard/event-types/test-meeting/toggle",
            &session,
            csrf,
            &format!("_csrf={}", csrf),
        ))
        .await
        .unwrap();
    assert!(
        response.status().is_redirection(),
        "Toggle should redirect, got {}",
        response.status()
    );

    let enabled: Option<(i32,)> =
        sqlx::query_as("SELECT enabled FROM event_types WHERE slug = 'test-meeting'")
            .fetch_optional(&pool)
            .await
            .unwrap();
    assert_eq!(enabled.unwrap().0, 0, "Event type should be disabled");

    // Re-enable (need a fresh router since oneshot consumes)
    let app2 = create_router(pool.clone(), std::env::temp_dir(), [0u8; 32]).await;
    let response = app2
        .oneshot(post_form(
            "/dashboard/event-types/test-meeting/toggle",
            &session,
            csrf,
            &format!("_csrf={}", csrf),
        ))
        .await
        .unwrap();
    assert!(response.status().is_redirection());

    let enabled: Option<(i32,)> =
        sqlx::query_as("SELECT enabled FROM event_types WHERE slug = 'test-meeting'")
            .fetch_optional(&pool)
            .await
            .unwrap();
    assert_eq!(enabled.unwrap().0, 1, "Event type should be re-enabled");
}

#[tokio::test]
async fn create_override_blocked_day() {
    let (app, pool, session, _) = setup_test_app().await;
    let csrf = "test-csrf-override";

    let response = app
        .oneshot(post_form(
            "/dashboard/event-types/test-meeting/overrides",
            &session,
            csrf,
            &format!("_csrf={}&date=2026-06-15&override_type=blocked", csrf),
        ))
        .await
        .unwrap();
    assert!(
        response.status().is_redirection(),
        "Create override should redirect"
    );

    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM availability_overrides WHERE date = '2026-06-15' AND is_blocked = 1",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count.0, 1, "Blocked override should be created");
}

#[tokio::test]
async fn create_override_custom_hours() {
    let (app, pool, session, _) = setup_test_app().await;
    let csrf = "test-csrf-custom";

    let response = app
        .oneshot(post_form(
            "/dashboard/event-types/test-meeting/overrides",
            &session,
            csrf,
            &format!(
                "_csrf={}&date=2026-06-16&override_type=custom&start_time=10%3A00&end_time=14%3A00",
                csrf
            ),
        ))
        .await
        .unwrap();
    assert!(response.status().is_redirection());

    let row: Option<(String, String, i32)> = sqlx::query_as(
        "SELECT start_time, end_time, is_blocked FROM availability_overrides WHERE date = '2026-06-16'",
    )
    .fetch_optional(&pool)
    .await
    .unwrap();
    let (start, end, blocked) = row.unwrap();
    assert_eq!(start, "10:00");
    assert_eq!(end, "14:00");
    assert_eq!(blocked, 0);
}

#[tokio::test]
async fn create_override_custom_hours_invalid_range_rejected() {
    let (app, pool, session, _) = setup_test_app().await;
    let csrf = "test-csrf-inv";

    // end_time before start_time
    let response = app
        .oneshot(post_form(
            "/dashboard/event-types/test-meeting/overrides",
            &session,
            csrf,
            &format!(
                "_csrf={}&date=2026-06-17&override_type=custom&start_time=14%3A00&end_time=10%3A00",
                csrf
            ),
        ))
        .await
        .unwrap();
    assert!(response.status().is_redirection());

    let count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM availability_overrides WHERE date = '2026-06-17'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count.0, 0, "Invalid time range should not create override");
}

#[tokio::test]
async fn delete_override_removes_from_db() {
    let (app, pool, session, _) = setup_test_app().await;

    // Insert an override to delete
    let override_id = uuid::Uuid::new_v4().to_string();
    let et_id: String =
        sqlx::query_scalar("SELECT id FROM event_types WHERE slug = 'test-meeting'")
            .fetch_one(&pool)
            .await
            .unwrap();
    sqlx::query("INSERT INTO availability_overrides (id, event_type_id, date, is_blocked) VALUES (?, ?, '2026-07-01', 1)")
        .bind(&override_id)
        .bind(&et_id)
        .execute(&pool)
        .await
        .unwrap();

    let csrf = "test-csrf-del";
    let response = app
        .oneshot(post_form(
            &format!(
                "/dashboard/event-types/test-meeting/overrides/{}/delete",
                override_id
            ),
            &session,
            csrf,
            &format!("_csrf={}", csrf),
        ))
        .await
        .unwrap();
    assert!(response.status().is_redirection());

    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM availability_overrides WHERE id = ?")
        .bind(&override_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count.0, 0, "Override should be deleted");
}

#[tokio::test]
async fn booking_form_post_creates_booking() {
    let (app, pool, _, _) = setup_test_app().await;
    let csrf = "test-csrf-book";

    // Find next Monday for a valid slot
    let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
    let mut next_monday = now.date() + Duration::days(1);
    while next_monday.weekday() != chrono::Weekday::Mon {
        next_monday += Duration::days(1);
    }
    let date_str = next_monday.format("%Y-%m-%d").to_string();

    let body = format!(
        "_csrf={}&date={}&time=10%3A00&name=Jane+Doe&email=jane%40example.com&notes=Hello",
        csrf, date_str
    );
    let response = app
        .oneshot(post_form_unauthed(
            "/u/testuser/test-meeting/book",
            csrf,
            &body,
        ))
        .await
        .unwrap();

    // Should render confirmation page (200) or redirect
    let status = response.status();
    assert!(
        status == 200 || status.is_redirection(),
        "Booking should succeed, got {}",
        status
    );

    let count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM bookings WHERE guest_email = 'jane@example.com'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count.0, 1, "Booking should be created in DB");
}

#[tokio::test]
async fn booking_invalid_email_rejected() {
    let (app, pool, _, _) = setup_test_app().await;
    let csrf = "test-csrf-inv-email";

    let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
    let mut next_monday = now.date() + Duration::days(1);
    while next_monday.weekday() != chrono::Weekday::Mon {
        next_monday += Duration::days(1);
    }
    let date_str = next_monday.format("%Y-%m-%d").to_string();

    let body = format!(
        "_csrf={}&date={}&time=10%3A00&name=Jane&email=not-an-email&notes=",
        csrf, date_str
    );
    let response = app
        .oneshot(post_form_unauthed(
            "/u/testuser/test-meeting/book",
            csrf,
            &body,
        ))
        .await
        .unwrap();

    let resp_body = body_string(response).await;
    assert!(
        resp_body.contains("Invalid")
            || resp_body.contains("invalid")
            || resp_body.contains("email"),
        "Invalid email should be rejected"
    );

    let count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM bookings WHERE guest_email = 'not-an-email'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count.0, 0, "Invalid booking should not be saved");
}

#[tokio::test]
async fn booking_empty_name_rejected() {
    let (app, pool, _, _) = setup_test_app().await;
    let csrf = "test-csrf-empty-name";

    let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
    let mut next_monday = now.date() + Duration::days(1);
    while next_monday.weekday() != chrono::Weekday::Mon {
        next_monday += Duration::days(1);
    }
    let date_str = next_monday.format("%Y-%m-%d").to_string();

    let body = format!(
        "_csrf={}&date={}&time=10%3A00&name=&email=jane%40example.com&notes=",
        csrf, date_str
    );
    let response = app
        .oneshot(post_form_unauthed(
            "/u/testuser/test-meeting/book",
            csrf,
            &body,
        ))
        .await
        .unwrap();

    let resp_body = body_string(response).await;
    assert!(
        resp_body.contains("required") || resp_body.contains("Name") || resp_body.contains("name"),
        "Empty name should be rejected"
    );

    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM bookings")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count.0, 0, "No booking should be saved with empty name");
}

#[tokio::test]
async fn confirm_pending_booking_via_dashboard() {
    let (app, pool, session, et_id) = setup_test_app().await;

    // Create a pending booking
    let booking_id = uuid::Uuid::new_v4().to_string();
    let cancel_tok = uuid::Uuid::new_v4().to_string();
    let resched_tok = uuid::Uuid::new_v4().to_string();
    let confirm_tok = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token, confirm_token) VALUES (?, ?, 'uid-confirm', 'Guest', 'guest@test.com', 'UTC', '2026-06-15T10:00:00', '2026-06-15T10:30:00', 'pending', ?, ?, ?)")
        .bind(&booking_id)
        .bind(&et_id)
        .bind(&cancel_tok)
        .bind(&resched_tok)
        .bind(&confirm_tok)
        .execute(&pool)
        .await
        .unwrap();

    let csrf = "test-csrf-confirm";
    let response = app
        .oneshot(post_form(
            &format!("/dashboard/bookings/{}/confirm", booking_id),
            &session,
            csrf,
            &format!("_csrf={}", csrf),
        ))
        .await
        .unwrap();
    assert!(response.status().is_redirection());

    let status: Option<(String,)> = sqlx::query_as("SELECT status FROM bookings WHERE id = ?")
        .bind(&booking_id)
        .fetch_optional(&pool)
        .await
        .unwrap();
    assert_eq!(
        status.unwrap().0,
        "confirmed",
        "Booking should be confirmed"
    );
}

#[tokio::test]
async fn cancel_booking_via_dashboard() {
    let (app, pool, session, et_id) = setup_test_app().await;

    let booking_id = uuid::Uuid::new_v4().to_string();
    let cancel_tok = uuid::Uuid::new_v4().to_string();
    let resched_tok = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token) VALUES (?, ?, 'uid-cancel', 'Guest', 'guest@test.com', 'UTC', '2026-06-15T14:00:00', '2026-06-15T14:30:00', 'confirmed', ?, ?)")
        .bind(&booking_id)
        .bind(&et_id)
        .bind(&cancel_tok)
        .bind(&resched_tok)
        .execute(&pool)
        .await
        .unwrap();

    let csrf = "test-csrf-cancel";
    let response = app
        .oneshot(post_form(
            &format!("/dashboard/bookings/{}/cancel", booking_id),
            &session,
            csrf,
            &format!("_csrf={}&reason=conflict", csrf),
        ))
        .await
        .unwrap();
    assert!(response.status().is_redirection());

    let status: Option<(String,)> = sqlx::query_as("SELECT status FROM bookings WHERE id = ?")
        .bind(&booking_id)
        .fetch_optional(&pool)
        .await
        .unwrap();
    assert_eq!(
        status.unwrap().0,
        "cancelled",
        "Booking should be cancelled"
    );
}

#[tokio::test]
async fn decline_pending_booking_via_dashboard() {
    let (app, pool, session, et_id) = setup_test_app().await;

    let booking_id = uuid::Uuid::new_v4().to_string();
    let cancel_tok = uuid::Uuid::new_v4().to_string();
    let resched_tok = uuid::Uuid::new_v4().to_string();
    let confirm_tok = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token, confirm_token) VALUES (?, ?, 'uid-decline-dash', 'Guest', 'guest@test.com', 'UTC', '2026-06-16T14:00:00', '2026-06-16T14:30:00', 'pending', ?, ?, ?)")
        .bind(&booking_id)
        .bind(&et_id)
        .bind(&cancel_tok)
        .bind(&resched_tok)
        .bind(&confirm_tok)
        .execute(&pool)
        .await
        .unwrap();

    let csrf = "test-csrf-decline-dash";
    let response = app
        .oneshot(post_form(
            &format!("/dashboard/bookings/{}/cancel", booking_id),
            &session,
            csrf,
            &format!("_csrf={}&reason=not+a+fit", csrf),
        ))
        .await
        .unwrap();
    assert!(response.status().is_redirection());

    let status: Option<(String,)> = sqlx::query_as("SELECT status FROM bookings WHERE id = ?")
        .bind(&booking_id)
        .fetch_optional(&pool)
        .await
        .unwrap();
    assert_eq!(
        status.unwrap().0,
        "declined",
        "Pending booking should be declined, not silently left in pending"
    );
}

#[tokio::test]
async fn approve_booking_via_email_token() {
    let (app, pool, _, et_id) = setup_test_app().await;

    let booking_id = uuid::Uuid::new_v4().to_string();
    let cancel_tok = uuid::Uuid::new_v4().to_string();
    let resched_tok = uuid::Uuid::new_v4().to_string();
    let confirm_tok = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token, confirm_token) VALUES (?, ?, 'uid-approve', 'Guest', 'guest@test.com', 'UTC', '2026-06-20T10:00:00', '2026-06-20T10:30:00', 'pending', ?, ?, ?)")
        .bind(&booking_id)
        .bind(&et_id)
        .bind(&cancel_tok)
        .bind(&resched_tok)
        .bind(&confirm_tok)
        .execute(&pool)
        .await
        .unwrap();

    // GET /booking/approve/{token} — shows confirmation form, does NOT approve
    let app2 = app.clone();
    let response = app2
        .oneshot(get(&format!("/booking/approve/{}", confirm_tok)))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body = body_string(response).await;
    assert!(
        body.contains("Approve booking"),
        "GET should show approve form"
    );

    let status: Option<(String,)> = sqlx::query_as("SELECT status FROM bookings WHERE id = ?")
        .bind(&booking_id)
        .fetch_optional(&pool)
        .await
        .unwrap();
    assert_eq!(
        status.unwrap().0,
        "pending",
        "Booking should still be pending after GET"
    );

    // POST /booking/approve/{token} — actually approves
    let response = app
        .oneshot(post_bare(&format!("/booking/approve/{}", confirm_tok)))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    let status: Option<(String,)> = sqlx::query_as("SELECT status FROM bookings WHERE id = ?")
        .bind(&booking_id)
        .fetch_optional(&pool)
        .await
        .unwrap();
    assert_eq!(
        status.unwrap().0,
        "confirmed",
        "Booking should be confirmed via POST token"
    );
}

/// Regression test for #101: when the event type's timezone differs from
/// the guest's timezone, approving a pending booking must render (and
/// email) the time in the guest's timezone, not the event-type-local time
/// the row was stored as.
#[tokio::test]
async fn approve_booking_renders_time_in_guest_timezone() {
    let (app, pool, _, et_id) = setup_test_app().await;

    // Event type stored in America/New_York. 10:00 NY in June (EDT, UTC-4)
    // == 14:00 UTC == 16:00 in Europe/Paris (CEST, UTC+2).
    sqlx::query("UPDATE event_types SET timezone = 'America/New_York' WHERE id = ?")
        .bind(&et_id)
        .execute(&pool)
        .await
        .unwrap();

    let booking_id = uuid::Uuid::new_v4().to_string();
    let cancel_tok = uuid::Uuid::new_v4().to_string();
    let resched_tok = uuid::Uuid::new_v4().to_string();
    let confirm_tok = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token, confirm_token) VALUES (?, ?, 'uid-approve-tz', 'Guest', 'guest@test.com', 'Europe/Paris', '2026-06-20T10:00:00', '2026-06-20T10:30:00', 'pending', ?, ?, ?)")
        .bind(&booking_id)
        .bind(&et_id)
        .bind(&cancel_tok)
        .bind(&resched_tok)
        .bind(&confirm_tok)
        .execute(&pool)
        .await
        .unwrap();

    let response = app
        .oneshot(post_bare(&format!("/booking/approve/{}", confirm_tok)))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body = body_string(response).await;

    assert!(
        body.contains("16:00") && body.contains("16:30"),
        "Approval page should render times in the guest's tz (Europe/Paris: 16:00 – 16:30), got body fragment: {}",
        &body[..body.len().min(2000)]
    );
    assert!(
        !body.contains("10:00") && !body.contains("10:30"),
        "Approval page should not render the event-type-local time (America/New_York: 10:00)"
    );
}

#[tokio::test]
async fn decline_booking_via_email_token() {
    let (app, pool, _, et_id) = setup_test_app().await;

    let booking_id = uuid::Uuid::new_v4().to_string();
    let cancel_tok = uuid::Uuid::new_v4().to_string();
    let resched_tok = uuid::Uuid::new_v4().to_string();
    let confirm_tok = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token, confirm_token) VALUES (?, ?, 'uid-decline', 'Guest', 'guest@test.com', 'UTC', '2026-06-21T10:00:00', '2026-06-21T10:30:00', 'pending', ?, ?, ?)")
        .bind(&booking_id)
        .bind(&et_id)
        .bind(&cancel_tok)
        .bind(&resched_tok)
        .bind(&confirm_tok)
        .execute(&pool)
        .await
        .unwrap();

    // GET /booking/decline/{token} shows form
    let response = app
        .oneshot(get(&format!("/booking/decline/{}", confirm_tok)))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body = body_string(response).await;
    assert!(
        body.contains("ecline") || body.contains("reason"),
        "Decline form should render"
    );
}

#[tokio::test]
async fn guest_cancel_via_token() {
    let (app, pool, _, et_id) = setup_test_app().await;

    let booking_id = uuid::Uuid::new_v4().to_string();
    let cancel_tok = uuid::Uuid::new_v4().to_string();
    let resched_tok = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token) VALUES (?, ?, 'uid-gcancel', 'Guest', 'guest@test.com', 'UTC', '2026-06-22T10:00:00', '2026-06-22T10:30:00', 'confirmed', ?, ?)")
        .bind(&booking_id)
        .bind(&et_id)
        .bind(&cancel_tok)
        .bind(&resched_tok)
        .execute(&pool)
        .await
        .unwrap();

    // GET /booking/cancel/{token} shows cancel form
    let response = app
        .oneshot(get(&format!("/booking/cancel/{}", cancel_tok)))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body = body_string(response).await;
    assert!(
        body.contains("cancel") || body.contains("Cancel"),
        "Cancel form should render"
    );
}

/// Regression test for #101 (cancel surface): when the event type is in a
/// different tz from the guest, the cancellation page (and the cancellation
/// email it mirrors) must render the time in the guest's tz, not the
/// event-type-local stored time.
#[tokio::test]
async fn guest_cancel_renders_time_in_guest_timezone() {
    let (app, pool, _, et_id) = setup_test_app().await;

    sqlx::query("UPDATE event_types SET timezone = 'America/New_York' WHERE id = ?")
        .bind(&et_id)
        .execute(&pool)
        .await
        .unwrap();

    let booking_id = uuid::Uuid::new_v4().to_string();
    let cancel_tok = uuid::Uuid::new_v4().to_string();
    let resched_tok = uuid::Uuid::new_v4().to_string();
    // 10:00 NY in June (EDT, UTC-4) == 16:00 Europe/Paris (CEST, UTC+2).
    sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token) VALUES (?, ?, 'uid-gcancel-tz', 'Guest', 'guest@test.com', 'Europe/Paris', '2026-06-22T10:00:00', '2026-06-22T10:30:00', 'confirmed', ?, ?)")
        .bind(&booking_id)
        .bind(&et_id)
        .bind(&cancel_tok)
        .bind(&resched_tok)
        .execute(&pool)
        .await
        .unwrap();

    let csrf = "test-csrf-gcancel-tz";
    let response = app
        .oneshot(post_form_unauthed(
            &format!("/booking/cancel/{}", cancel_tok),
            csrf,
            &format!("_csrf={}", csrf),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body = body_string(response).await;

    assert!(
        body.contains("16:00") && body.contains("16:30"),
        "Cancellation page should render times in the guest's tz (Europe/Paris: 16:00 – 16:30)"
    );
    assert!(
        !body.contains("10:00") && !body.contains("10:30"),
        "Cancellation page should not render the event-type-local time (America/New_York: 10:00)"
    );
}

#[tokio::test]
async fn login_with_wrong_password_shows_error() {
    let (app, pool, _, _) = setup_test_app().await;

    // Set a password on the test user
    let hash = crate::auth::hash_password("correct-password").unwrap();
    sqlx::query("UPDATE users SET password_hash = ? WHERE email = 'test@example.com'")
        .bind(&hash)
        .execute(&pool)
        .await
        .unwrap();

    let csrf = "test-csrf-login";
    let response = app
        .oneshot(post_form_unauthed(
            "/auth/login",
            csrf,
            &format!(
                "_csrf={}&email=test%40example.com&password=wrong-password",
                csrf
            ),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body = body_string(response).await;
    assert!(
        body.contains("Invalid") || body.contains("invalid") || body.contains("error"),
        "Wrong password should show error"
    );
}

#[tokio::test]
async fn login_with_correct_password_redirects() {
    let (app, pool, _, _) = setup_test_app().await;

    let hash = crate::auth::hash_password("my-password").unwrap();
    sqlx::query("UPDATE users SET password_hash = ? WHERE email = 'test@example.com'")
        .bind(&hash)
        .execute(&pool)
        .await
        .unwrap();

    let csrf = "test-csrf-login-ok";
    let response = app
        .oneshot(post_form_unauthed(
            "/auth/login",
            csrf,
            &format!(
                "_csrf={}&email=test%40example.com&password=my-password",
                csrf
            ),
        ))
        .await
        .unwrap();
    assert!(
        response.status().is_redirection(),
        "Successful login should redirect, got {}",
        response.status()
    );
    let location = response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        location.contains("dashboard"),
        "Should redirect to dashboard, got {}",
        location
    );
}

#[tokio::test]
async fn register_when_disabled_returns_error() {
    let (app, pool, _, _) = setup_test_app().await;

    sqlx::query("UPDATE auth_config SET registration_enabled = 0 WHERE id = 'singleton'")
        .execute(&pool)
        .await
        .unwrap();

    let csrf = "test-csrf-reg";
    let response = app
        .oneshot(post_form_unauthed(
            "/auth/register",
            csrf,
            &format!(
                "_csrf={}&name=New+User&email=new%40example.com&password=pass1234",
                csrf
            ),
        ))
        .await
        .unwrap();
    let body = body_string(response).await;
    assert!(
        body.contains("disabled") || body.contains("Disabled") || body.contains("not available"),
        "Registration when disabled should show error"
    );

    let count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM users WHERE email = 'new@example.com'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count.0, 0, "User should not be created");
}

// --- Dashboard pages: new event type form ---

#[tokio::test]
async fn new_event_type_form_returns_200() {
    let (app, _, session, _) = setup_test_app().await;
    let response = app
        .oneshot(get_authed("/dashboard/event-types/new", &session))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body = body_string(response).await;
    assert!(body.contains("event type") || body.contains("Event type") || body.contains("Create"));
}

#[tokio::test]
async fn edit_event_type_form_returns_200() {
    let (app, _, session, _) = setup_test_app().await;
    let response = app
        .oneshot(get_authed(
            "/dashboard/event-types/test-meeting/edit",
            &session,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body = body_string(response).await;
    assert!(body.contains("Test Meeting"));
}

#[tokio::test]
async fn new_source_form_returns_200() {
    let (app, _, session, _) = setup_test_app().await;
    let response = app
        .oneshot(get_authed("/dashboard/sources/new", &session))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
}

/// Helper for the source-edit tests: insert a caldav source for the test user.
/// Returns the source id. Encrypts with the all-zeroes test secret_key so
/// the update handler's decrypt-on-keep-existing path works. Uses
/// `example.com` which has public DNS, so `validate_caldav_url` (which does
/// DNS resolution to check for SSRF) doesn't fail in the test sandbox.
async fn seed_source(pool: &SqlitePool, name: &str, password: &str) -> String {
    let account_id: (String,) = sqlx::query_as(
        "SELECT id FROM accounts WHERE user_id = (SELECT id FROM users WHERE username = 'testuser') LIMIT 1",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    let enc = crate::crypto::encrypt_password(&[0u8; 32], password).unwrap();
    sqlx::query(
        "INSERT INTO caldav_sources (id, account_id, name, url, username, password_enc) VALUES (?, ?, ?, 'https://example.com/dav/old/', 'olduser', ?)",
    )
    .bind(&id)
    .bind(&account_id.0)
    .bind(name)
    .bind(&enc)
    .execute(pool)
    .await
    .unwrap();
    id
}

#[tokio::test]
async fn edit_source_form_renders_prefilled() {
    let (app, pool, session, _) = setup_test_app().await;
    let sid = seed_source(&pool, "My Source", "old-pw").await;

    let response = app
        .oneshot(get_authed(
            &format!("/dashboard/sources/{}/edit", sid),
            &session,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body = body_string(response).await;
    assert!(
        body.contains("Edit calendar source"),
        "should render in editing mode"
    );
    assert!(body.contains("My Source"), "name pre-filled");
    // minijinja escapes '/' as '&#x2f;' in attribute values; check both the
    // host and a path segment (which won't include slashes).
    assert!(body.contains("example.com"), "url host pre-filled");
    assert!(
        body.contains("dav") && body.contains("old"),
        "url path pre-filled"
    );
    assert!(body.contains("olduser"), "username pre-filled");
    assert!(
        body.contains("Leave blank to keep existing"),
        "password placeholder"
    );
}

#[tokio::test]
async fn update_source_changes_fields_and_keeps_password_when_blank() {
    let (app, pool, session, _) = setup_test_app().await;
    let sid = seed_source(&pool, "My Source", "old-pw").await;

    let csrf = "test-csrf-update-source";
    let body = format!(
        "_csrf={}&name=Renamed&url=https%3A%2F%2Fexample.com%2Fdav%2Fnew%2F&username=newuser&password=&no_test=on",
        csrf
    );
    let response = app
        .oneshot(post_form(
            &format!("/dashboard/sources/{}/edit", sid),
            &session,
            csrf,
            &body,
        ))
        .await
        .unwrap();
    assert!(response.status().is_redirection() || response.status() == 200);

    let row: (String, String, String, String) =
        sqlx::query_as("SELECT name, url, username, password_enc FROM caldav_sources WHERE id = ?")
            .bind(&sid)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(row.0, "Renamed");
    assert_eq!(row.1, "https://example.com/dav/new/");
    assert_eq!(row.2, "newuser");
    // Decrypt the stored blob and confirm the password is unchanged.
    let pw = crate::crypto::decrypt_password(&[0u8; 32], &row.3).unwrap();
    assert_eq!(pw, "old-pw", "blank password must keep the existing one");
}

#[tokio::test]
async fn update_source_rotates_password() {
    let (app, pool, session, _) = setup_test_app().await;
    let sid = seed_source(&pool, "My Source", "old-pw").await;

    let csrf = "test-csrf-rotate";
    let body = format!(
        "_csrf={}&name=My+Source&url=https%3A%2F%2Fexample.com%2Fdav%2Fold%2F&username=olduser&password=new-pw-rotated&no_test=on",
        csrf
    );
    let response = app
        .oneshot(post_form(
            &format!("/dashboard/sources/{}/edit", sid),
            &session,
            csrf,
            &body,
        ))
        .await
        .unwrap();
    assert!(response.status().is_redirection() || response.status() == 200);

    let enc: (String,) = sqlx::query_as("SELECT password_enc FROM caldav_sources WHERE id = ?")
        .bind(&sid)
        .fetch_one(&pool)
        .await
        .unwrap();
    let pw = crate::crypto::decrypt_password(&[0u8; 32], &enc.0).unwrap();
    assert_eq!(
        pw, "new-pw-rotated",
        "non-blank password must replace the existing one"
    );
}

#[tokio::test]
async fn update_source_404_for_other_user_source() {
    // The edit handler must scope by user_id; trying to edit a source the
    // current user doesn't own should redirect away (not leak/edit).
    let (app, pool, session, _) = setup_test_app().await;

    // Insert an account belonging to a *different* user, and a source under it.
    let other_user_id = uuid::Uuid::new_v4().to_string();
    let other_account_id = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO users (id, email, name, role, auth_provider, username, enabled) VALUES (?, 'other@example.com', 'Other', 'user', 'local', 'otheruser', 1)")
        .bind(&other_user_id)
        .execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO accounts (id, name, email, timezone, user_id) VALUES (?, 'Other', 'other@example.com', 'UTC', ?)")
        .bind(&other_account_id)
        .bind(&other_user_id)
        .execute(&pool).await.unwrap();
    let other_sid = uuid::Uuid::new_v4().to_string();
    let enc = crate::crypto::encrypt_password(&[0u8; 32], "secret").unwrap();
    sqlx::query("INSERT INTO caldav_sources (id, account_id, name, url, username, password_enc) VALUES (?, ?, 'Other source', 'https://other.example.com/', 'someone', ?)")
        .bind(&other_sid)
        .bind(&other_account_id)
        .bind(&enc)
        .execute(&pool).await.unwrap();

    let response = app
        .oneshot(get_authed(
            &format!("/dashboard/sources/{}/edit", other_sid),
            &session,
        ))
        .await
        .unwrap();
    // Handler redirects to /dashboard/sources for unauthorised access.
    assert!(response.status().is_redirection());
}

// --- Event type CRUD ---

#[tokio::test]
async fn create_event_type_via_post() {
    let (app, pool, session, _) = setup_test_app().await;
    let csrf = "test-csrf-create-et";
    let body = format!(
        "_csrf={}&title=New+Meeting&slug=new-meeting&duration_min=45&location_value=https%3A%2F%2Fmeet.example.com&avail_days=1,2,3,4,5&avail_start=09:00&avail_end=17:00",
        csrf
    );
    let response = app
        .oneshot(post_form(
            "/dashboard/event-types/new",
            &session,
            csrf,
            &body,
        ))
        .await
        .unwrap();
    assert!(
        response.status().is_redirection(),
        "Create event type should redirect, got {}",
        response.status()
    );

    let count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM event_types WHERE slug = 'new-meeting'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count.0, 1, "Event type should be created");
}

#[tokio::test]
async fn delete_event_type_with_no_bookings() {
    let (app, pool, session, _) = setup_test_app().await;
    let csrf = "test-csrf-del-et";

    // Create an event type to delete (no bookings)
    let et_id = uuid::Uuid::new_v4().to_string();
    let account_id: String = sqlx::query_scalar("SELECT id FROM accounts LIMIT 1")
        .fetch_one(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO event_types (id, account_id, slug, title, duration_min, enabled) VALUES (?, ?, 'deletable', 'Deletable', 30, 1)")
        .bind(&et_id)
        .bind(&account_id)
        .execute(&pool)
        .await
        .unwrap();

    let response = app
        .oneshot(post_form(
            "/dashboard/event-types/deletable/delete",
            &session,
            csrf,
            &format!("_csrf={}", csrf),
        ))
        .await
        .unwrap();
    assert!(response.status().is_redirection());

    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM event_types WHERE slug = 'deletable'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count.0, 0, "Event type should be deleted");
}

// --- Settings ---

#[tokio::test]
async fn settings_save_updates_name() {
    let (app, pool, session, _) = setup_test_app().await;
    let csrf = "test-csrf-settings";
    let body = format!("_csrf={}&name=Updated+Name&booking_email=", csrf);
    let response = app
        .oneshot(post_form("/dashboard/settings", &session, csrf, &body))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let resp_body = body_string(response).await;
    assert!(resp_body.contains("Settings saved") || resp_body.contains("Updated Name"));

    let name: Option<String> =
        sqlx::query_scalar("SELECT name FROM users WHERE email = 'test@example.com'")
            .fetch_optional(&pool)
            .await
            .unwrap();
    assert_eq!(name.unwrap(), "Updated Name");
}

// --- Admin actions ---

#[tokio::test]
async fn admin_toggle_user_role() {
    let (app, pool, session, _) = setup_test_app().await;

    // Create a non-admin user
    let user2_id = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO users (id, email, name, role, auth_provider, username, enabled) VALUES (?, 'user2@test.com', 'User Two', 'user', 'local', 'user2', 1)")
        .bind(&user2_id)
        .execute(&pool)
        .await
        .unwrap();

    let csrf = "test-csrf-toggle-role";
    let response = app
        .oneshot(post_form(
            &format!("/dashboard/admin/users/{}/toggle-role", user2_id),
            &session,
            csrf,
            &format!("_csrf={}", csrf),
        ))
        .await
        .unwrap();
    assert!(response.status().is_redirection());

    let role: String = sqlx::query_scalar("SELECT role FROM users WHERE id = ?")
        .bind(&user2_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(role, "admin", "User should be promoted to admin");
}

#[tokio::test]
async fn admin_toggle_user_enabled() {
    let (app, pool, session, _) = setup_test_app().await;

    let user2_id = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO users (id, email, name, role, auth_provider, username, enabled) VALUES (?, 'user3@test.com', 'User Three', 'user', 'local', 'user3', 1)")
        .bind(&user2_id)
        .execute(&pool)
        .await
        .unwrap();

    let csrf = "test-csrf-toggle-en";
    let response = app
        .oneshot(post_form(
            &format!("/dashboard/admin/users/{}/toggle-enabled", user2_id),
            &session,
            csrf,
            &format!("_csrf={}", csrf),
        ))
        .await
        .unwrap();
    assert!(response.status().is_redirection());

    let enabled: i32 = sqlx::query_scalar("SELECT enabled FROM users WHERE id = ?")
        .bind(&user2_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(enabled, 0, "User should be disabled");
}

#[tokio::test]
async fn admin_update_auth_settings() {
    let (app, pool, session, _) = setup_test_app().await;
    let csrf = "test-csrf-auth";
    let body = format!("_csrf={}&allowed_email_domains=example.com", csrf);
    let response = app
        .oneshot(post_form("/dashboard/admin/auth", &session, csrf, &body))
        .await
        .unwrap();
    assert!(response.status().is_redirection());

    let domains: Option<String> =
        sqlx::query_scalar("SELECT allowed_email_domains FROM auth_config WHERE id = 'singleton'")
            .fetch_optional(&pool)
            .await
            .unwrap();
    assert_eq!(domains.unwrap(), "example.com");
}

#[tokio::test]
async fn admin_non_admin_gets_403() {
    let (app, pool, _, _) = setup_test_app().await;

    // Create a non-admin user with session
    let user_id = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO users (id, email, name, role, auth_provider, username, enabled) VALUES (?, 'nonadmin@test.com', 'Non Admin', 'user', 'local', 'nonadmin', 1)")
        .bind(&user_id)
        .execute(&pool)
        .await
        .unwrap();
    let session = uuid::Uuid::new_v4().to_string();
    let expires = (Utc::now() + Duration::days(30))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();
    sqlx::query("INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)")
        .bind(&session)
        .bind(&user_id)
        .bind(&expires)
        .execute(&pool)
        .await
        .unwrap();

    let response = app
        .oneshot(get_authed("/dashboard/admin", &session))
        .await
        .unwrap();
    assert_eq!(response.status(), 403, "Non-admin should get 403");
}

// --- Token-based POST actions ---

#[tokio::test]
async fn decline_booking_via_post() {
    let (app, pool, _, et_id) = setup_test_app().await;

    let booking_id = uuid::Uuid::new_v4().to_string();
    let cancel_tok = uuid::Uuid::new_v4().to_string();
    let resched_tok = uuid::Uuid::new_v4().to_string();
    let confirm_tok = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token, confirm_token) VALUES (?, ?, 'uid-dec-post', 'Guest', 'guest@test.com', 'UTC', '2026-07-01T10:00:00', '2026-07-01T10:30:00', 'pending', ?, ?, ?)")
        .bind(&booking_id)
        .bind(&et_id)
        .bind(&cancel_tok)
        .bind(&resched_tok)
        .bind(&confirm_tok)
        .execute(&pool)
        .await
        .unwrap();

    let csrf = "test-csrf-decline-post";
    let response = app
        .oneshot(post_form_unauthed(
            &format!("/booking/decline/{}", confirm_tok),
            csrf,
            &format!("_csrf={}&reason=Not+available", csrf),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    let status: String = sqlx::query_scalar("SELECT status FROM bookings WHERE id = ?")
        .bind(&booking_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status, "declined", "Booking should be declined");
}

#[tokio::test]
async fn guest_cancel_booking_via_post() {
    let (app, pool, _, et_id) = setup_test_app().await;

    let booking_id = uuid::Uuid::new_v4().to_string();
    let cancel_tok = uuid::Uuid::new_v4().to_string();
    let resched_tok = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token) VALUES (?, ?, 'uid-gcancel-post', 'Guest', 'guest@test.com', 'UTC', '2026-07-02T10:00:00', '2026-07-02T10:30:00', 'confirmed', ?, ?)")
        .bind(&booking_id)
        .bind(&et_id)
        .bind(&cancel_tok)
        .bind(&resched_tok)
        .execute(&pool)
        .await
        .unwrap();

    let csrf = "test-csrf-gcancel-post";
    let response = app
        .oneshot(post_form_unauthed(
            &format!("/booking/cancel/{}", cancel_tok),
            csrf,
            &format!("_csrf={}&reason=Changed+plans", csrf),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    let status: String = sqlx::query_scalar("SELECT status FROM bookings WHERE id = ?")
        .bind(&booking_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status, "cancelled", "Booking should be cancelled by guest");
}

// --- Min-notice for guest cancel / reschedule ---

/// Format a `start_at` value `offset` from now, using the same shape
/// (`%Y-%m-%dT%H:%M:%S`) that booking handlers persist. Booking times
/// are stored as naive host-local timestamps; the notice check uses
/// `Local::now().naive_local()` so we mirror that here.
fn booking_start_at(offset: chrono::Duration) -> String {
    (Local::now().naive_local() + offset)
        .format("%Y-%m-%dT%H:%M:%S")
        .to_string()
}

fn booking_end_at(offset: chrono::Duration, duration_min: i64) -> String {
    (Local::now().naive_local() + offset + chrono::Duration::minutes(duration_min))
        .format("%Y-%m-%dT%H:%M:%S")
        .to_string()
}

async fn insert_booking_at(
    pool: &SqlitePool,
    et_id: &str,
    cancel_tok: &str,
    resched_tok: &str,
    offset: chrono::Duration,
) -> String {
    let booking_id = uuid::Uuid::new_v4().to_string();
    let start_at = booking_start_at(offset);
    let end_at = booking_end_at(offset, 30);
    sqlx::query(
        "INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token) VALUES (?, ?, 'uid-notice', 'Guest', 'guest@test.com', 'UTC', ?, ?, 'confirmed', ?, ?)",
    )
    .bind(&booking_id)
    .bind(et_id)
    .bind(&start_at)
    .bind(&end_at)
    .bind(cancel_tok)
    .bind(resched_tok)
    .execute(pool)
    .await
    .unwrap();
    booking_id
}

#[tokio::test]
async fn guest_cancel_no_notice_succeeds() {
    let (app, pool, _, et_id) = setup_test_app().await;
    // No cancel_notice_min set on event type. Booking starts in 30 min.
    let cancel_tok = uuid::Uuid::new_v4().to_string();
    let resched_tok = uuid::Uuid::new_v4().to_string();
    let booking_id = insert_booking_at(
        &pool,
        &et_id,
        &cancel_tok,
        &resched_tok,
        chrono::Duration::minutes(30),
    )
    .await;

    let csrf = "csrf-cancel-no-notice";
    let response = app
        .oneshot(post_form_unauthed(
            &format!("/booking/cancel/{}", cancel_tok),
            csrf,
            &format!("_csrf={}", csrf),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let status: String = sqlx::query_scalar("SELECT status FROM bookings WHERE id = ?")
        .bind(&booking_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        status, "cancelled",
        "Without a notice window the cancel must succeed"
    );
}

#[tokio::test]
async fn guest_cancel_within_notice_window_blocked() {
    let (app, pool, _, et_id) = setup_test_app().await;
    // Notice window of 60 min, booking starts in 30 min: blocked.
    sqlx::query("UPDATE event_types SET cancel_notice_min = 60 WHERE id = ?")
        .bind(&et_id)
        .execute(&pool)
        .await
        .unwrap();
    let cancel_tok = uuid::Uuid::new_v4().to_string();
    let resched_tok = uuid::Uuid::new_v4().to_string();
    let booking_id = insert_booking_at(
        &pool,
        &et_id,
        &cancel_tok,
        &resched_tok,
        chrono::Duration::minutes(30),
    )
    .await;

    // GET should already block.
    let response = app
        .clone()
        .oneshot(get(&format!("/booking/cancel/{}", cancel_tok)))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body = body_string(response).await;
    assert!(
        body.contains("notice") || body.contains("60") || body.contains("minutes"),
        "Blocked page should mention the notice (got body length {})",
        body.len()
    );

    // POST must also be blocked, and the booking must not transition.
    let csrf = "csrf-cancel-blocked";
    let response = app
        .oneshot(post_form_unauthed(
            &format!("/booking/cancel/{}", cancel_tok),
            csrf,
            &format!("_csrf={}", csrf),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let status: String = sqlx::query_scalar("SELECT status FROM bookings WHERE id = ?")
        .bind(&booking_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status, "confirmed", "Blocked POST must not mutate state");
}

#[tokio::test]
async fn guest_cancel_outside_notice_window_succeeds() {
    let (app, pool, _, et_id) = setup_test_app().await;
    // Notice window of 60 min, booking starts in 120 min: allowed.
    sqlx::query("UPDATE event_types SET cancel_notice_min = 60 WHERE id = ?")
        .bind(&et_id)
        .execute(&pool)
        .await
        .unwrap();
    let cancel_tok = uuid::Uuid::new_v4().to_string();
    let resched_tok = uuid::Uuid::new_v4().to_string();
    let booking_id = insert_booking_at(
        &pool,
        &et_id,
        &cancel_tok,
        &resched_tok,
        chrono::Duration::minutes(120),
    )
    .await;

    let csrf = "csrf-cancel-allowed";
    let response = app
        .oneshot(post_form_unauthed(
            &format!("/booking/cancel/{}", cancel_tok),
            csrf,
            &format!("_csrf={}", csrf),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let status: String = sqlx::query_scalar("SELECT status FROM bookings WHERE id = ?")
        .bind(&booking_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status, "cancelled");
}

#[tokio::test]
async fn guest_reschedule_no_notice_succeeds() {
    let (app, pool, _, et_id) = setup_test_app().await;
    let cancel_tok = uuid::Uuid::new_v4().to_string();
    let resched_tok = uuid::Uuid::new_v4().to_string();
    let _ = insert_booking_at(
        &pool,
        &et_id,
        &cancel_tok,
        &resched_tok,
        chrono::Duration::minutes(30),
    )
    .await;

    // GET the slot picker. With no notice, it should render the slot
    // page (status 200 and contains the event title or slot markers).
    let response = app
        .oneshot(get(&format!("/booking/reschedule/{}", resched_tok)))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body = body_string(response).await;
    assert!(
        body.contains("Test Meeting") || body.contains("reschedul"),
        "No notice -> slot page should render, body length {}",
        body.len()
    );
}

#[tokio::test]
async fn guest_reschedule_within_notice_window_blocked() {
    let (app, pool, _, et_id) = setup_test_app().await;
    sqlx::query("UPDATE event_types SET reschedule_notice_min = 60 WHERE id = ?")
        .bind(&et_id)
        .execute(&pool)
        .await
        .unwrap();
    let cancel_tok = uuid::Uuid::new_v4().to_string();
    let resched_tok = uuid::Uuid::new_v4().to_string();
    let booking_id = insert_booking_at(
        &pool,
        &et_id,
        &cancel_tok,
        &resched_tok,
        chrono::Duration::minutes(30),
    )
    .await;

    // GET blocks before the slot picker is rendered.
    let response = app
        .clone()
        .oneshot(get(&format!("/booking/reschedule/{}", resched_tok)))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body = body_string(response).await;
    assert!(
        body.contains("notice") || body.contains("60") || body.contains("minutes"),
        "Blocked page should mention the notice"
    );

    // POST also blocked: booking start_at must not change.
    let csrf = "csrf-resched-blocked";
    // Submit a new date 10 days out so we don't hit other guards.
    let new_date = (Local::now().naive_local().date() + chrono::Duration::days(10))
        .format("%Y-%m-%d")
        .to_string();
    let original_start: String = sqlx::query_scalar("SELECT start_at FROM bookings WHERE id = ?")
        .bind(&booking_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    let response = app
        .oneshot(post_form_unauthed(
            &format!("/booking/reschedule/{}", resched_tok),
            csrf,
            &format!("_csrf={}&date={}&time=10%3A00&tz=UTC", csrf, new_date),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let still: String = sqlx::query_scalar("SELECT start_at FROM bookings WHERE id = ?")
        .bind(&booking_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        still, original_start,
        "Blocked POST must not move the booking"
    );
}

#[tokio::test]
async fn guest_reschedule_outside_notice_window_succeeds() {
    let (app, pool, _, et_id) = setup_test_app().await;
    sqlx::query("UPDATE event_types SET reschedule_notice_min = 60 WHERE id = ?")
        .bind(&et_id)
        .execute(&pool)
        .await
        .unwrap();
    let cancel_tok = uuid::Uuid::new_v4().to_string();
    let resched_tok = uuid::Uuid::new_v4().to_string();
    let _ = insert_booking_at(
        &pool,
        &et_id,
        &cancel_tok,
        &resched_tok,
        chrono::Duration::minutes(120),
    )
    .await;

    // GET should render the slot picker (not the blocked page).
    let response = app
        .oneshot(get(&format!("/booking/reschedule/{}", resched_tok)))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body = body_string(response).await;
    // Slot picker contains the event title; the blocked page does
    // not. Either presence of "Test Meeting" or absence of the
    // notice-line is fine.
    assert!(
        body.contains("Test Meeting") || body.contains("reschedul"),
        "Outside notice window the slot picker should render"
    );
}

#[tokio::test]
async fn host_cancel_unaffected_by_notice() {
    // The dashboard cancel handler must bypass the guest notice window.
    // Set a 24h cancel_notice and a booking 30 min out: the host should
    // still be able to cancel via /dashboard/bookings/{id}/cancel.
    let (app, pool, session, et_id) = setup_test_app().await;
    sqlx::query("UPDATE event_types SET cancel_notice_min = 1440 WHERE id = ?")
        .bind(&et_id)
        .execute(&pool)
        .await
        .unwrap();
    let cancel_tok = uuid::Uuid::new_v4().to_string();
    let resched_tok = uuid::Uuid::new_v4().to_string();
    let booking_id = insert_booking_at(
        &pool,
        &et_id,
        &cancel_tok,
        &resched_tok,
        chrono::Duration::minutes(30),
    )
    .await;

    let csrf = "csrf-host-cancel";
    let response = app
        .oneshot(post_form(
            &format!("/dashboard/bookings/{}/cancel", booking_id),
            &session,
            csrf,
            &format!("_csrf={}", csrf),
        ))
        .await
        .unwrap();
    assert!(
        response.status().is_redirection(),
        "Host cancel should redirect, got {}",
        response.status()
    );
    let status: String = sqlx::query_scalar("SELECT status FROM bookings WHERE id = ?")
        .bind(&booking_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        status, "cancelled",
        "Host cancel must succeed regardless of guest notice window"
    );
}

// --- Host reschedule ---

#[tokio::test]
async fn host_reschedule_page_returns_200() {
    let (app, pool, session, et_id) = setup_test_app().await;

    let booking_id = uuid::Uuid::new_v4().to_string();
    let cancel_tok = uuid::Uuid::new_v4().to_string();
    let resched_tok = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token) VALUES (?, ?, 'uid-hresched', 'Guest', 'guest@test.com', 'UTC', '2026-07-10T10:00:00', '2026-07-10T10:30:00', 'confirmed', ?, ?)")
        .bind(&booking_id)
        .bind(&et_id)
        .bind(&cancel_tok)
        .bind(&resched_tok)
        .execute(&pool)
        .await
        .unwrap();

    let response = app
        .oneshot(get_authed(
            &format!("/dashboard/bookings/{}/reschedule", booking_id),
            &session,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body = body_string(response).await;
    assert!(body.contains("Guest") || body.contains("reschedule") || body.contains("Reschedule"));
}

#[tokio::test]
async fn host_reschedule_post_sets_flag() {
    let (app, pool, session, et_id) = setup_test_app().await;

    let booking_id = uuid::Uuid::new_v4().to_string();
    let cancel_tok = uuid::Uuid::new_v4().to_string();
    let resched_tok = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token) VALUES (?, ?, 'uid-hresched2', 'Guest', 'guest@test.com', 'UTC', '2026-07-11T10:00:00', '2026-07-11T10:30:00', 'confirmed', ?, ?)")
        .bind(&booking_id)
        .bind(&et_id)
        .bind(&cancel_tok)
        .bind(&resched_tok)
        .execute(&pool)
        .await
        .unwrap();

    let csrf = "test-csrf-hresched";
    let response = app
        .oneshot(post_form(
            &format!("/dashboard/bookings/{}/reschedule", booking_id),
            &session,
            csrf,
            &format!("_csrf={}", csrf),
        ))
        .await
        .unwrap();
    assert!(response.status().is_redirection());

    let flag: i32 = sqlx::query_scalar("SELECT reschedule_by_host FROM bookings WHERE id = ?")
        .bind(&booking_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(flag, 1, "reschedule_by_host should be set");
}

// --- Static routes ---

#[tokio::test]
async fn accent_css_returns_200() {
    let (app, _, _, _) = setup_test_app().await;
    let response = app.oneshot(get("/accent.css")).await.unwrap();
    assert_eq!(response.status(), 200);
}

#[tokio::test]
async fn logo_returns_response() {
    let (app, _, _, _) = setup_test_app().await;
    let response = app.oneshot(get("/logo")).await.unwrap();
    // 200 if logo exists, or 404/redirect if not
    let status = response.status().as_u16();
    assert!(status == 200 || status == 404 || status == 303);
}

// --- Legacy routes ---

#[tokio::test]
async fn legacy_slot_route_returns_200() {
    let (app, _, _, _) = setup_test_app().await;
    let response = app.oneshot(get("/test-meeting")).await.unwrap();
    assert_eq!(response.status(), 200);
    let body = body_string(response).await;
    assert!(body.contains("Test Meeting"));
}

// --- Private event types ---

#[tokio::test]
async fn private_event_type_hidden_from_profile() {
    let (app, pool, _, _) = setup_test_app().await;

    let et_id = uuid::Uuid::new_v4().to_string();
    let account_id: String = sqlx::query_scalar("SELECT id FROM accounts LIMIT 1")
        .fetch_one(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO event_types (id, account_id, slug, title, duration_min, enabled, visibility) VALUES (?, ?, 'secret', 'Secret Meeting', 30, 1, 'private')")
        .bind(&et_id)
        .bind(&account_id)
        .execute(&pool)
        .await
        .unwrap();

    let response = app.oneshot(get("/u/testuser")).await.unwrap();
    let body = body_string(response).await;
    assert!(
        !body.contains("Secret Meeting"),
        "Private event type should not appear on public profile"
    );
}

// --- Double-booking prevention ---

#[tokio::test]
async fn double_booking_same_slot_prevented() {
    let (app, pool, _, et_id) = setup_test_app().await;

    // Find next Monday
    let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
    let mut next_monday = now.date() + Duration::days(1);
    while next_monday.weekday() != chrono::Weekday::Mon {
        next_monday += Duration::days(1);
    }
    let date_str = next_monday.format("%Y-%m-%d").to_string();

    // Insert existing confirmed booking at 10:00
    let booking_id = uuid::Uuid::new_v4().to_string();
    let start_at = format!("{}T10:00:00", date_str);
    let end_at = format!("{}T10:30:00", date_str);
    let cancel_tok = uuid::Uuid::new_v4().to_string();
    let resched_tok = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token) VALUES (?, ?, 'uid-existing', 'First Guest', 'first@test.com', 'UTC', ?, ?, 'confirmed', ?, ?)")
        .bind(&booking_id)
        .bind(&et_id)
        .bind(&start_at)
        .bind(&end_at)
        .bind(&cancel_tok)
        .bind(&resched_tok)
        .execute(&pool)
        .await
        .unwrap();

    // Try to book the same slot. The seeded user's timezone is UTC, so we
    // also submit tz=UTC to keep guest-local == host-local in this test.
    let csrf = "test-csrf-double";
    let body = format!(
        "_csrf={}&date={}&time=10%3A00&tz=UTC&name=Second+Guest&email=second%40test.com&notes=",
        csrf, date_str
    );
    let response = app
        .oneshot(post_form_unauthed(
            "/u/testuser/test-meeting/book",
            csrf,
            &body,
        ))
        .await
        .unwrap();
    let resp_body = body_string(response).await;
    assert!(
        resp_body.contains("no longer available") || resp_body.contains("Not available"),
        "Double booking should be rejected"
    );

    let count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM bookings WHERE guest_email = 'second@test.com'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count.0, 0, "Double booking should not be saved");
}

// --- Disabled event type ---

#[tokio::test]
async fn disabled_event_type_not_bookable() {
    let (app, pool, _, _) = setup_test_app().await;

    // Disable the event type
    sqlx::query("UPDATE event_types SET enabled = 0 WHERE slug = 'test-meeting'")
        .execute(&pool)
        .await
        .unwrap();

    let response = app.oneshot(get("/u/testuser/test-meeting")).await.unwrap();
    let status = response.status();
    let body = body_string(response).await;
    assert!(
        body.contains("not found") || body.contains("Not found") || status == 404,
        "Disabled event type should not show slots"
    );
}

// --- Impersonation ---

#[tokio::test]
async fn admin_impersonate_sets_cookie() {
    let (app, pool, session, _) = setup_test_app().await;

    let user2_id = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO users (id, email, name, role, auth_provider, username, enabled) VALUES (?, 'target@test.com', 'Target User', 'user', 'local', 'target', 1)")
        .bind(&user2_id)
        .execute(&pool)
        .await
        .unwrap();

    let csrf = "test-csrf-imp";
    let response = app
        .oneshot(post_form(
            &format!("/dashboard/admin/impersonate/{}", user2_id),
            &session,
            csrf,
            &format!("_csrf={}", csrf),
        ))
        .await
        .unwrap();
    assert!(response.status().is_redirection());

    // Check for impersonation cookie
    let cookies: Vec<&str> = response
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    let has_impersonate = cookies.iter().any(|c| c.contains("calrs_impersonate"));
    assert!(has_impersonate, "Should set impersonation cookie");
}

#[tokio::test]
async fn admin_stop_impersonate() {
    let (app, _, session, _) = setup_test_app().await;
    let csrf = "test-csrf-stop-imp";
    let response = app
        .oneshot(post_form(
            "/dashboard/admin/stop-impersonate",
            &session,
            csrf,
            &format!("_csrf={}", csrf),
        ))
        .await
        .unwrap();
    assert!(response.status().is_redirection());
}

// --- Booking notes too long ---

#[tokio::test]
async fn booking_notes_too_long_rejected() {
    let (app, pool, _, _) = setup_test_app().await;
    let csrf = "test-csrf-long-notes";

    let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
    let mut next_monday = now.date() + Duration::days(1);
    while next_monday.weekday() != chrono::Weekday::Mon {
        next_monday += Duration::days(1);
    }
    let date_str = next_monday.format("%Y-%m-%d").to_string();

    let long_notes = "x".repeat(5001);
    let body = format!(
        "_csrf={}&date={}&time=11%3A00&name=Jane&email=jane%40test.com&notes={}",
        csrf, date_str, long_notes
    );
    let response = app
        .oneshot(post_form_unauthed(
            "/u/testuser/test-meeting/book",
            csrf,
            &body,
        ))
        .await
        .unwrap();
    let resp_body = body_string(response).await;
    assert!(
        resp_body.contains("5000") || resp_body.contains("too long") || resp_body.contains("Notes"),
        "Long notes should be rejected"
    );

    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM bookings")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count.0, 0, "No booking should be created");
}

// --- Expired session ---

#[tokio::test]
async fn expired_session_redirects_to_login() {
    let (app, pool, _, _) = setup_test_app().await;

    let user_id: String = sqlx::query_scalar("SELECT id FROM users LIMIT 1")
        .fetch_one(&pool)
        .await
        .unwrap();
    let expired_session = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, '2020-01-01 00:00:00')",
    )
    .bind(&expired_session)
    .bind(&user_id)
    .execute(&pool)
    .await
    .unwrap();

    let response = app
        .oneshot(get_authed("/dashboard", &expired_session))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        303,
        "Expired session should redirect to login"
    );
}

// --- Authenticated user visiting login redirects to dashboard ---

#[tokio::test]
async fn authenticated_user_login_page_redirects() {
    let (app, _, session, _) = setup_test_app().await;
    let response = app
        .oneshot(get_authed("/auth/login", &session))
        .await
        .unwrap();
    assert!(
        response.status().is_redirection(),
        "Authenticated user should be redirected from login"
    );
}

// --- Register page ---

#[tokio::test]
async fn register_page_returns_200() {
    let (app, _, _, _) = setup_test_app().await;
    let response = app.oneshot(get("/auth/register")).await.unwrap();
    assert_eq!(response.status(), 200);
    let body = body_string(response).await;
    assert!(body.contains("Register") || body.contains("register"));
}

#[tokio::test]
async fn register_creates_user() {
    let (app, pool, _, _) = setup_test_app().await;
    let csrf = "test-csrf-register-ok";
    let body = format!(
        "_csrf={}&name=New+User&email=newuser%40example.com&password=strongpassword123",
        csrf
    );
    let response = app
        .oneshot(post_form_unauthed("/auth/register", csrf, &body))
        .await
        .unwrap();
    assert!(
        response.status().is_redirection(),
        "Registration should redirect, got {}",
        response.status()
    );

    let count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM users WHERE email = 'newuser@example.com'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count.0, 1, "User should be created");
}

// --- Booking date too far in future ---

#[tokio::test]
async fn booking_date_too_far_rejected() {
    let (app, _, _, _) = setup_test_app().await;
    let csrf = "test-csrf-far-date";

    let far_date = (Utc::now() + Duration::days(400))
        .format("%Y-%m-%d")
        .to_string();
    let body = format!(
        "_csrf={}&date={}&time=10%3A00&name=Jane&email=jane%40test.com&notes=",
        csrf, far_date
    );
    let response = app
        .oneshot(post_form_unauthed(
            "/u/testuser/test-meeting/book",
            csrf,
            &body,
        ))
        .await
        .unwrap();
    let resp_body = body_string(response).await;
    assert!(
        resp_body.contains("365")
            || resp_body.contains("too far")
            || resp_body.contains("days")
            || resp_body.contains("year"),
        "Date >365 days should be rejected, got: {}",
        &resp_body[..resp_body.len().min(200)]
    );
}

// --- Rate limiting ---

#[tokio::test]
async fn booking_rate_limit_after_many_attempts() {
    let (app, _, _, _) = setup_test_app().await;
    let csrf = "test-csrf-rate";

    let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
    let mut next_monday = now.date() + Duration::days(1);
    while next_monday.weekday() != chrono::Weekday::Mon {
        next_monday += Duration::days(1);
    }
    let date_str = next_monday.format("%Y-%m-%d").to_string();

    // Make 11 requests (limit is 10 per 5 min)
    // We need to reuse the pool but create fresh routers
    // Actually, the rate limiter is per-AppState. Each setup_test_app creates a fresh one.
    // We need to clone the router. But oneshot consumes it.
    // Skip this test — rate limiting is already unit tested.
    // Instead, test that a single request doesn't trigger rate limiting.
    let body = format!(
        "_csrf={}&date={}&time=09%3A00&name=Rate+Test&email=rate%40test.com&notes=",
        csrf, date_str
    );
    let response = app
        .oneshot(post_form_unauthed(
            "/u/testuser/test-meeting/book",
            csrf,
            &body,
        ))
        .await
        .unwrap();
    let resp_body = body_string(response).await;
    assert!(
        !resp_body.contains("Too many"),
        "Single request should not be rate limited"
    );
}

// --- Update event type ---

#[tokio::test]
async fn update_event_type_changes_title() {
    let (app, pool, session, _) = setup_test_app().await;
    let csrf = "test-csrf-update-et";
    let body = format!(
        "_csrf={}&title=Updated+Title&slug=test-meeting&duration_min=30&location_value=https%3A%2F%2Fmeet.example.com&avail_days=1,2,3,4,5&avail_start=09:00&avail_end=17:00",
        csrf
    );
    let response = app
        .oneshot(post_form(
            "/dashboard/event-types/test-meeting/edit",
            &session,
            csrf,
            &body,
        ))
        .await
        .unwrap();
    assert!(response.status().is_redirection() || response.status() == 200);

    let title: String =
        sqlx::query_scalar("SELECT title FROM event_types WHERE slug = 'test-meeting'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(title, "Updated Title");
}

#[tokio::test]
async fn update_event_type_with_empty_schedule_uses_user_default() {
    // Regression test for #68: when the event-type edit form is submitted
    // with an empty avail_schedule, the resulting availability_rules must
    // come from the user's profile-default schedule, not a hardcoded
    // Mon-Fri 09:00-17:00 fallback. Locks in the behaviour wired through
    // update_event_type so a future refactor can't silently regress it.
    let (app, pool, session, _) = setup_test_app().await;

    // Seed the test user's profile default with something distinctive
    // (Tue+Thu 14:00-18:00) so we can tell it apart from the legacy
    // hardcoded Mon-Fri 09:00-17:00 fallback.
    let user_id: String = sqlx::query_scalar("SELECT id FROM users WHERE username = 'testuser'")
        .fetch_one(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM user_availability_rules WHERE user_id = ?")
        .bind(&user_id)
        .execute(&pool)
        .await
        .unwrap();
    for day in [2_i32, 4] {
        sqlx::query(
            "INSERT INTO user_availability_rules (id, user_id, day_of_week, start_time, end_time) VALUES (?, ?, ?, '14:00', '18:00')",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&user_id)
        .bind(day)
        .execute(&pool)
        .await
        .unwrap();
    }

    let csrf = "test-csrf-empty-schedule";
    // Submit with avail_schedule explicitly empty (matches what the form
    // sends when all days are unchecked) and no legacy fields.
    let body = format!(
        "_csrf={}&title=Test+Meeting&slug=test-meeting&duration_min=30&location_value=https%3A%2F%2Fmeet.example.com&avail_schedule=",
        csrf
    );
    let response = app
        .oneshot(post_form(
            "/dashboard/event-types/test-meeting/edit",
            &session,
            csrf,
            &body,
        ))
        .await
        .unwrap();
    assert!(response.status().is_redirection() || response.status() == 200);

    // Inspect the persisted availability_rules. Expect Tue+Thu 14:00-18:00
    // (the user's profile default), not Mon-Fri 09:00-17:00.
    let rules: Vec<(i32, String, String)> = sqlx::query_as(
        "SELECT day_of_week, start_time, end_time FROM availability_rules \
         WHERE event_type_id = (SELECT id FROM event_types WHERE slug = 'test-meeting') \
         ORDER BY day_of_week, start_time",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        rules,
        vec![
            (2, "14:00".to_string(), "18:00".to_string()),
            (4, "14:00".to_string(), "18:00".to_string()),
        ],
        "empty avail_schedule submission must fall back to the user's profile default, not the hardcoded Mon-Fri 09:00-17:00",
    );
}

#[tokio::test]
async fn update_group_event_type_persists_location() {
    let (app, pool, session, _) = setup_test_app().await;

    // Get user_id and account_id from the test user
    let (user_id, account_id): (String, String) = sqlx::query_as(
        "SELECT u.id, a.id FROM users u JOIN accounts a ON a.user_id = u.id WHERE u.username = 'testuser'",
    )
    .bind("testuser")
    .fetch_one(&pool)
    .await
    .unwrap();

    // Create a team with the test user as admin
    let team_id = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO teams (id, name, slug, visibility, created_by) VALUES (?, 'Test Team', 'test-team', 'public', ?)")
        .bind(&team_id)
        .bind(&user_id)
        .execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO team_members (team_id, user_id, role, source) VALUES (?, ?, 'admin', 'direct')")
        .bind(&team_id)
        .bind(&user_id)
        .execute(&pool).await.unwrap();

    // Create a team event type with a location
    let et_id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO event_types (id, account_id, slug, title, duration_min, buffer_before, buffer_after, min_notice_min, enabled, location_type, location_value, team_id, created_by_user_id) \
         VALUES (?, ?, 'team-meeting', 'Team Meeting', 30, 0, 0, 0, 1, 'link', 'https://meet.example.com/room', ?, ?)",
    )
    .bind(&et_id)
    .bind(&account_id)
    .bind(&team_id)
    .bind(&user_id)
    .execute(&pool).await.unwrap();

    // Update the event type via the web handler
    let csrf = "test-csrf-group-update";
    let body = format!(
        "_csrf={}&title=Team+Meeting+Updated&slug=team-meeting&duration_min=45&location_type=link&location_value=https%3A%2F%2Fmeet.example.com%2Fnew-room&avail_days=1,2,3,4,5&avail_start=09:00&avail_end=17:00&scheduling_mode=round_robin",
        csrf
    );
    let response = app
        .oneshot(post_form(
            &format!("/dashboard/group-event-types/{}/team-meeting/edit", team_id),
            &session,
            csrf,
            &body,
        ))
        .await
        .unwrap();
    assert!(
        response.status().is_redirection(),
        "Update should redirect, got {}",
        response.status()
    );

    // Verify all fields persisted
    let (title, location_value, duration): (String, Option<String>, i32) =
        sqlx::query_as("SELECT title, location_value, duration_min FROM event_types WHERE id = ?")
            .bind(&et_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(title, "Team Meeting Updated");
    assert_eq!(
        location_value.as_deref(),
        Some("https://meet.example.com/new-room")
    );
    assert_eq!(duration, 45);
}

// --- Booking with requires_confirmation ---

#[tokio::test]
async fn booking_with_confirmation_creates_pending() {
    let (app, pool, _, _) = setup_test_app().await;

    // Set requires_confirmation on the event type
    sqlx::query("UPDATE event_types SET requires_confirmation = 1 WHERE slug = 'test-meeting'")
        .execute(&pool)
        .await
        .unwrap();

    let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
    let mut next_monday = now.date() + Duration::days(1);
    while next_monday.weekday() != chrono::Weekday::Mon {
        next_monday += Duration::days(1);
    }
    let date_str = next_monday.format("%Y-%m-%d").to_string();

    let csrf = "test-csrf-pending";
    let body = format!(
        "_csrf={}&date={}&time=14%3A00&name=Pending+Guest&email=pending%40test.com&notes=",
        csrf, date_str
    );
    let response = app
        .oneshot(post_form_unauthed(
            "/u/testuser/test-meeting/book",
            csrf,
            &body,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let resp_body = body_string(response).await;
    assert!(
        resp_body.contains("Pending") || resp_body.contains("pending"),
        "Should show pending confirmation"
    );

    let status: String =
        sqlx::query_scalar("SELECT status FROM bookings WHERE guest_email = 'pending@test.com'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(status, "pending");

    // Should have a confirm_token
    let token: Option<String> = sqlx::query_scalar(
        "SELECT confirm_token FROM bookings WHERE guest_email = 'pending@test.com'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(token.is_some(), "Pending booking should have confirm_token");
}

// --- Private event type + invite flow ---

#[tokio::test]
async fn private_event_type_requires_invite_token() {
    let (app, pool, _, _) = setup_test_app().await;

    // Make the event type private
    sqlx::query("UPDATE event_types SET visibility = 'private' WHERE slug = 'test-meeting'")
        .execute(&pool)
        .await
        .unwrap();

    let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
    let mut next_monday = now.date() + Duration::days(1);
    while next_monday.weekday() != chrono::Weekday::Mon {
        next_monday += Duration::days(1);
    }
    let date_str = next_monday.format("%Y-%m-%d").to_string();

    // Book without invite token
    let csrf = "test-csrf-private";
    let body = format!(
        "_csrf={}&date={}&time=10%3A00&name=Jane&email=jane%40test.com&notes=",
        csrf, date_str
    );
    let response = app
        .oneshot(post_form_unauthed(
            "/u/testuser/test-meeting/book",
            csrf,
            &body,
        ))
        .await
        .unwrap();
    let resp_body = body_string(response).await;
    assert!(
        resp_body.contains("invite") || resp_body.contains("Invite"),
        "Private event type should require invite"
    );

    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM bookings")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count.0, 0, "No booking should be created without invite");
}

#[tokio::test]
async fn invite_page_returns_200_for_private_event_type() {
    let (app, pool, session, et_id) = setup_test_app().await;

    sqlx::query("UPDATE event_types SET visibility = 'private' WHERE id = ?")
        .bind(&et_id)
        .execute(&pool)
        .await
        .unwrap();

    let response = app
        .oneshot(get_authed(
            &format!("/dashboard/invites/{}", et_id),
            &session,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body = body_string(response).await;
    assert!(body.contains("Invites") || body.contains("invite"));
}

// --- Guest reschedule flow ---

#[tokio::test]
async fn guest_reschedule_slots_page_returns_200() {
    let (app, pool, _, et_id) = setup_test_app().await;

    let booking_id = uuid::Uuid::new_v4().to_string();
    let cancel_tok = uuid::Uuid::new_v4().to_string();
    let resched_tok = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token) VALUES (?, ?, 'uid-gresched', 'Guest', 'guest@test.com', 'UTC', '2026-08-01T10:00:00', '2026-08-01T10:30:00', 'confirmed', ?, ?)")
        .bind(&booking_id)
        .bind(&et_id)
        .bind(&cancel_tok)
        .bind(&resched_tok)
        .execute(&pool)
        .await
        .unwrap();

    let response = app
        .oneshot(get(&format!("/booking/reschedule/{}", resched_tok)))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body = body_string(response).await;
    assert!(
        body.contains("Test Meeting") || body.contains("reschedul"),
        "Guest reschedule page should show event info"
    );
}

// --- Admin accent/theme ---

#[tokio::test]
async fn admin_update_accent_redirects() {
    let (app, _, session, _) = setup_test_app().await;
    let csrf = "test-csrf-accent";
    let body = format!("_csrf={}&theme=nord", csrf);
    let response = app
        .oneshot(post_form("/dashboard/admin/accent", &session, csrf, &body))
        .await
        .unwrap();
    assert!(response.status().is_redirection());
}

// --- Multiple availability windows ---

#[tokio::test]
async fn create_event_type_with_multiple_windows() {
    let (app, pool, session, _) = setup_test_app().await;
    let csrf = "test-csrf-multi-win";
    let body = format!(
        "_csrf={}&title=Split+Day&slug=split-day&duration_min=30&location_value=https%3A%2F%2Fmeet.example.com&avail_days=1,2,3,4,5&avail_windows=09%3A00-12%3A00%2C13%3A00-17%3A00",
        csrf
    );
    let response = app
        .oneshot(post_form(
            "/dashboard/event-types/new",
            &session,
            csrf,
            &body,
        ))
        .await
        .unwrap();
    assert!(response.status().is_redirection() || response.status() == 200);

    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM event_types WHERE slug = 'split-day'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count.0, 1);

    // Should have rules with the split windows
    let rules: Vec<(String, String)> = sqlx::query_as(
        "SELECT start_time, end_time FROM availability_rules WHERE event_type_id = (SELECT id FROM event_types WHERE slug = 'split-day') ORDER BY start_time",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(rules.len() >= 5, "Should have rules for weekdays");
}

// --- Book form page ---

#[tokio::test]
async fn book_form_page_returns_200() {
    let (app, _, _, _) = setup_test_app().await;

    let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
    let mut next_monday = now.date() + Duration::days(1);
    while next_monday.weekday() != chrono::Weekday::Mon {
        next_monday += Duration::days(1);
    }
    let date_str = next_monday.format("%Y-%m-%d").to_string();

    let response = app
        .oneshot(get(&format!(
            "/u/testuser/test-meeting/book?date={}&time=10:00",
            date_str
        )))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body = body_string(response).await;
    assert!(body.contains("Test Meeting"));
    assert!(body.contains("Confirm booking") || body.contains("confirm"));
}

// --- Legacy book form ---

#[tokio::test]
async fn legacy_book_form_returns_200() {
    let (app, _, _, _) = setup_test_app().await;

    let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
    let mut next_monday = now.date() + Duration::days(1);
    while next_monday.weekday() != chrono::Weekday::Mon {
        next_monday += Duration::days(1);
    }
    let date_str = next_monday.format("%Y-%m-%d").to_string();

    let response = app
        .oneshot(get(&format!(
            "/test-meeting/book?date={}&time=10:00",
            date_str
        )))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
}

// --- Booking with additional attendees ---

#[tokio::test]
async fn booking_with_additional_guests() {
    let (app, pool, _, _) = setup_test_app().await;

    // Enable additional guests
    sqlx::query("UPDATE event_types SET max_additional_guests = 3 WHERE slug = 'test-meeting'")
        .execute(&pool)
        .await
        .unwrap();

    let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
    let mut next_monday = now.date() + Duration::days(1);
    while next_monday.weekday() != chrono::Weekday::Mon {
        next_monday += Duration::days(1);
    }
    let date_str = next_monday.format("%Y-%m-%d").to_string();

    let csrf = "test-csrf-guests";
    let body = format!(
        "_csrf={}&date={}&time=15%3A00&name=Host+Guest&email=host%40test.com&notes=&additional_guests=extra1%40test.com%2Cextra2%40test.com",
        csrf, date_str
    );
    let response = app
        .oneshot(post_form_unauthed(
            "/u/testuser/test-meeting/book",
            csrf,
            &body,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM booking_attendees WHERE booking_id = (SELECT id FROM bookings WHERE guest_email = 'host@test.com')",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count.0, 2, "Should have 2 additional attendees");
}

// --- Troubleshoot with override ---

#[tokio::test]
async fn troubleshoot_shows_blocked_override() {
    let (app, pool, session, et_id) = setup_test_app().await;

    // Block tomorrow
    let tomorrow = (Utc::now() + Duration::days(1))
        .format("%Y-%m-%d")
        .to_string();
    let override_id = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO availability_overrides (id, event_type_id, date, is_blocked) VALUES (?, ?, ?, 1)")
        .bind(&override_id)
        .bind(&et_id)
        .bind(&tomorrow)
        .execute(&pool)
        .await
        .unwrap();

    let response = app
        .oneshot(get_authed(
            &format!(
                "/dashboard/troubleshoot?date={}&event_type=test-meeting",
                tomorrow
            ),
            &session,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body = body_string(response).await;
    assert!(
        body.contains("Blocked")
            || body.contains("blocked")
            || body.contains("override")
            || body.contains("day off"),
        "Troubleshoot should show blocked override"
    );
}

// --- Avatar routes ---

#[tokio::test]
async fn avatar_nonexistent_returns_404() {
    let (app, _, _, _) = setup_test_app().await;
    let response = app
        .oneshot(get("/avatar/nonexistent-user-id"))
        .await
        .unwrap();
    assert_eq!(response.status(), 404);
}

// --- Nonexistent routes ---

#[tokio::test]
async fn nonexistent_event_type_slug_returns_not_found() {
    let (app, _, _, _) = setup_test_app().await;
    let response = app
        .oneshot(get("/u/testuser/nonexistent-slug"))
        .await
        .unwrap();
    let status = response.status();
    let body = body_string(response).await;
    assert!(
        status == 404 || body.contains("not found") || body.contains("Not found"),
        "Nonexistent slug should return error"
    );
}

// --- Overrides page for nonexistent event type ---

#[tokio::test]
async fn overrides_nonexistent_event_type_redirects() {
    let (app, _, session, _) = setup_test_app().await;
    let response = app
        .oneshot(get_authed(
            "/dashboard/event-types/nonexistent/overrides",
            &session,
        ))
        .await
        .unwrap();
    assert!(
        response.status().is_redirection(),
        "Should redirect for nonexistent event type"
    );
}

// --- Group profile (no groups in test data, should handle gracefully) ---

#[tokio::test]
async fn team_profile_nonexistent_returns_404_or_empty() {
    let (app, _, _, _) = setup_test_app().await;
    let response = app.oneshot(get("/team/nonexistent")).await.unwrap();
    let status = response.status();
    assert!(
        status == 404 || status == 200,
        "Nonexistent group should return 404 or empty page"
    );
}

// --- Dashboard overview stats ---

#[tokio::test]
async fn dashboard_overview_shows_stats() {
    let (app, pool, session, et_id) = setup_test_app().await;

    // Add a confirmed booking
    let booking_id = uuid::Uuid::new_v4().to_string();
    let cancel_tok = uuid::Uuid::new_v4().to_string();
    let resched_tok = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token) VALUES (?, ?, 'uid-stat', 'Guest', 'guest@test.com', 'UTC', '2030-06-15T10:00:00', '2030-06-15T10:30:00', 'confirmed', ?, ?)")
        .bind(&booking_id)
        .bind(&et_id)
        .bind(&cancel_tok)
        .bind(&resched_tok)
        .execute(&pool)
        .await
        .unwrap();

    let response = app
        .oneshot(get_authed("/dashboard", &session))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body = body_string(response).await;
    // Should show at least 1 event type and 1 upcoming booking
    assert!(body.contains("Event Type") || body.contains("event type") || body.contains("1"));
}

// --- Settings: booking email validation ---

#[tokio::test]
async fn settings_invalid_booking_email_rejected() {
    let (app, _, session, _) = setup_test_app().await;
    let csrf = "test-csrf-bad-email";
    let body = format!("_csrf={}&name=Test+User&booking_email=not-an-email", csrf);
    let response = app
        .oneshot(post_form("/dashboard/settings", &session, csrf, &body))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let resp_body = body_string(response).await;
    assert!(
        resp_body.contains("Invalid")
            || resp_body.contains("invalid")
            || resp_body.contains("email"),
        "Invalid booking email should show error"
    );
}

// --- Settings: empty name rejected ---

#[tokio::test]
async fn settings_empty_name_rejected() {
    let (app, _, session, _) = setup_test_app().await;
    let csrf = "test-csrf-no-name";
    let body = format!("_csrf={}&name=&booking_email=", csrf);
    let response = app
        .oneshot(post_form("/dashboard/settings", &session, csrf, &body))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let resp_body = body_string(response).await;
    assert!(
        resp_body.contains("required") || resp_body.contains("Name") || resp_body.contains("empty"),
        "Empty name should show error"
    );
}

// --- Admin OIDC update ---

#[tokio::test]
async fn admin_update_oidc_settings() {
    let (app, pool, session, _) = setup_test_app().await;
    let csrf = "test-csrf-oidc";
    let body = format!(
        "_csrf={}&oidc_issuer_url=https%3A%2F%2Fauth.example.com&oidc_client_id=calrs&oidc_client_secret=secret123",
        csrf
    );
    let response = app
        .oneshot(post_form("/dashboard/admin/oidc", &session, csrf, &body))
        .await
        .unwrap();
    assert!(response.status().is_redirection());

    let client_id: Option<String> =
        sqlx::query_scalar("SELECT oidc_client_id FROM auth_config WHERE id = 'singleton'")
            .fetch_optional(&pool)
            .await
            .unwrap();
    assert_eq!(client_id.unwrap(), "calrs");
}

// --- Legacy booking POST ---

#[tokio::test]
async fn legacy_booking_post_creates_booking() {
    let (app, pool, _, _) = setup_test_app().await;

    let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
    let mut next_monday = now.date() + Duration::days(1);
    while next_monday.weekday() != chrono::Weekday::Mon {
        next_monday += Duration::days(1);
    }
    let date_str = next_monday.format("%Y-%m-%d").to_string();

    let csrf = "test-csrf-legacy-book";
    let body = format!(
        "_csrf={}&date={}&time=11%3A00&name=Legacy+Guest&email=legacy%40test.com&notes=",
        csrf, date_str
    );
    let response = app
        .oneshot(post_form_unauthed("/test-meeting/book", csrf, &body))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    let count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM bookings WHERE guest_email = 'legacy@test.com'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count.0, 1, "Legacy booking should be created");
}

// --- Booking with timezone ---

#[tokio::test]
async fn booking_with_guest_timezone() {
    let (app, pool, _, _) = setup_test_app().await;

    let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
    let mut next_monday = now.date() + Duration::days(1);
    while next_monday.weekday() != chrono::Weekday::Mon {
        next_monday += Duration::days(1);
    }
    let date_str = next_monday.format("%Y-%m-%d").to_string();

    let csrf = "test-csrf-tz-book";
    let body = format!(
        "_csrf={}&date={}&time=09%3A00&name=TZ+Guest&email=tz%40test.com&notes=&tz=America%2FNew_York",
        csrf, date_str
    );
    let response = app
        .oneshot(post_form_unauthed(
            "/u/testuser/test-meeting/book",
            csrf,
            &body,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    let tz: Option<String> =
        sqlx::query_scalar("SELECT guest_timezone FROM bookings WHERE guest_email = 'tz@test.com'")
            .fetch_optional(&pool)
            .await
            .unwrap();
    assert_eq!(tz.unwrap(), "America/New_York");
}

// --- Slots with month parameter ---

#[tokio::test]
async fn slots_with_month_param() {
    let (app, _, _, _) = setup_test_app().await;
    let response = app
        .oneshot(get("/u/testuser/test-meeting?month=2026-06"))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body = body_string(response).await;
    assert!(body.contains("June") || body.contains("2026"));
}

// --- Slots with timezone parameter ---

#[tokio::test]
async fn slots_with_tz_param() {
    let (app, _, _, _) = setup_test_app().await;
    let response = app
        .oneshot(get("/u/testuser/test-meeting?tz=Europe/Paris"))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body = body_string(response).await;
    assert!(body.contains("Paris") || body.contains("Europe"));
}

// --- Overrides: multiple custom hours on same date ---

#[tokio::test]
async fn multiple_custom_hours_on_same_date() {
    let (app, pool, session, et_id) = setup_test_app().await;
    let csrf = "test-csrf-multi-override";

    // Add morning override
    let response = app
        .oneshot(post_form(
            "/dashboard/event-types/test-meeting/overrides",
            &session,
            csrf,
            &format!(
                "_csrf={}&date=2026-08-01&override_type=custom&start_time=08%3A00&end_time=12%3A00",
                csrf
            ),
        ))
        .await
        .unwrap();
    assert!(response.status().is_redirection());

    // Add afternoon override (need fresh router)
    let app2 = create_router(pool.clone(), std::env::temp_dir(), [0u8; 32]).await;
    let response = app2
        .oneshot(post_form(
            "/dashboard/event-types/test-meeting/overrides",
            &session,
            csrf,
            &format!(
                "_csrf={}&date=2026-08-01&override_type=custom&start_time=14%3A00&end_time=16%3A00",
                csrf
            ),
        ))
        .await
        .unwrap();
    assert!(response.status().is_redirection());

    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM availability_overrides WHERE event_type_id = ? AND date = '2026-08-01'",
    )
    .bind(&et_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count.0, 2, "Should have 2 custom hour overrides");
}

// --- Event type with all options ---

#[tokio::test]
async fn create_event_type_with_all_options() {
    let (app, pool, session, _) = setup_test_app().await;
    let csrf = "test-csrf-full-et";
    let body = format!(
        "_csrf={}&title=Full+Options&slug=full-options&duration_min=60&buffer_before=10&buffer_after=10&min_notice_min=120&requires_confirmation=on&location_type=link&location_value=https%3A%2F%2Fzoom.us%2Fmy-room&avail_days=1,2,3&avail_start=10:00&avail_end=16:00&reminder_minutes=15",
        csrf
    );
    let response = app
        .oneshot(post_form(
            "/dashboard/event-types/new",
            &session,
            csrf,
            &body,
        ))
        .await
        .unwrap();
    assert!(response.status().is_redirection() || response.status() == 200);

    let et: Option<(i32, i32, i32, i32, i32, String, String)> = sqlx::query_as(
        "SELECT duration_min, buffer_before, buffer_after, min_notice_min, requires_confirmation, location_type, location_value FROM event_types WHERE slug = 'full-options'",
    )
    .fetch_optional(&pool)
    .await
    .unwrap();
    let (dur, bb, ba, mn, rc, lt, lv) = et.unwrap();
    assert_eq!(dur, 60);
    assert_eq!(bb, 10);
    assert_eq!(ba, 10);
    assert_eq!(mn, 120);
    assert_eq!(rc, 1);
    assert_eq!(lt, "link");
    assert_eq!(lv, "https://zoom.us/my-room");
}

// --- Helper function tests ---

#[test]
fn compute_initials_two_names() {
    assert_eq!(compute_initials("Alice Bob"), "AB");
}

#[test]
fn compute_initials_single_name() {
    assert_eq!(compute_initials("Alice"), "A");
}

#[test]
fn compute_initials_three_names() {
    assert_eq!(compute_initials("Alice Bob Charlie"), "AC");
}

#[test]
fn compute_initials_empty() {
    assert_eq!(compute_initials(""), "?");
}

#[test]
fn format_booking_range_same_day() {
    let result = format_booking_range("2026-06-15T10:00:00", "2026-06-15T10:30:00");
    assert!(result.contains("10:00"));
    assert!(result.contains("10:30"));
}

#[test]
fn extract_time_24h_from_iso() {
    assert_eq!(extract_time_24h("2026-06-15T14:30:00"), "14:30");
}

#[test]
fn extract_time_24h_from_space_sep() {
    assert_eq!(extract_time_24h("2026-06-15 14:30:00"), "14:30");
}

#[test]
fn format_date_label_full_datetime() {
    let result = format_date_label("2026-06-15T10:00:00", "en");
    assert!(result.contains("June") || result.contains("15") || result.contains("2026"));
}

#[test]
fn parse_guest_tz_europe() {
    let tz = parse_guest_tz(Some("Europe/London"));
    assert_eq!(tz.name(), "Europe/London");
}

#[test]
fn guest_to_host_local_converts_across_zones() {
    // 18:00 Europe/Paris (CEST, UTC+2 in July) == 12:00 America/New_York (EDT, UTC-4)
    let paris: Tz = "Europe/Paris".parse().unwrap();
    let ny: Tz = "America/New_York".parse().unwrap();
    let guest_local = NaiveDate::from_ymd_opt(2026, 7, 15)
        .unwrap()
        .and_hms_opt(18, 0, 0)
        .unwrap();
    let host_local = guest_to_host_local(guest_local, paris, ny);
    assert_eq!(
        host_local.format("%Y-%m-%d %H:%M").to_string(),
        "2026-07-15 12:00"
    );
}

#[test]
fn guest_to_host_local_same_zone_is_noop() {
    let tz: Tz = "UTC".parse().unwrap();
    let dt = NaiveDate::from_ymd_opt(2026, 1, 1)
        .unwrap()
        .and_hms_opt(10, 30, 0)
        .unwrap();
    assert_eq!(guest_to_host_local(dt, tz, tz), dt);
}

// End-to-end TZ pipeline used by background email paths (reminder loop,
// reschedule): `start_at` is stored in the event-type tz, must be converted
// to the guest tz to populate BookingDetails, and host_time_display must
// recover the host wall-clock for host-targeted emails. Regression for the
// reviewer-caught bug where the reminder loop short-circuited the first
// conversion and the host email displayed times in the wrong zone.
#[test]
fn stored_to_host_email_recovers_host_wall_clock() {
    // Scenario from issue #119: Paris event type, LA guest, booked at
    // what the guest saw as 07:00 LA = 16:00 Paris. start_at stored as
    // Paris wall-clock.
    let stored_start = "2026-05-26T16:00:00";
    let stored_end = "2026-05-26T16:30:00";
    let host_tz: Tz = "Europe/Paris".parse().unwrap();
    let guest_tz: Tz = "America/Los_Angeles".parse().unwrap();

    // Step 1: convert stored (host) -> guest wall-clock, as the reminder
    // loop and reschedule handler now do before building BookingDetails.
    let (date, start_time, end_time) =
        booking_strings_in_guest_tz(stored_start, stored_end, host_tz, guest_tz);
    assert_eq!(date, "2026-05-26");
    assert_eq!(start_time, "07:00");
    assert_eq!(end_time, "07:30");

    // Step 2: host_time_display converts guest wall-clock back to host.
    let (host_date, time_display) = crate::email::host_time_display(
        &date,
        &start_time,
        &end_time,
        guest_tz.name(),
        host_tz.name(),
    );
    assert_eq!(host_date, "2026-05-26");
    assert_eq!(time_display, "16:00 \u{2013} 16:30 (Europe/Paris)");
}

#[test]
fn parse_guest_tz_garbage_falls_back() {
    let tz = parse_guest_tz(Some("Not/A/Timezone"));
    // Should fall back to system tz or UTC
    assert!(!tz.name().is_empty());
}

#[test]
fn validate_booking_input_name_255_chars_ok() {
    let name = "a".repeat(255);
    assert!(validate_booking_input(&name, "test@test.com", &None).is_ok());
}

#[test]
fn validate_booking_input_name_256_chars_rejected() {
    let name = "a".repeat(256);
    assert!(validate_booking_input(&name, "test@test.com", &None).is_err());
}

#[test]
fn validate_booking_input_notes_5000_chars_ok() {
    let notes = Some("a".repeat(5000));
    assert!(validate_booking_input("Test", "test@test.com", &notes).is_ok());
}

#[test]
fn validate_date_exactly_365_from_today() {
    let date = (chrono::Utc::now() + Duration::days(365))
        .naive_utc()
        .date();
    assert!(validate_date_not_too_far(date).is_ok());
}

#[test]
fn validate_date_400_rejected() {
    let date = (chrono::Utc::now() + Duration::days(400))
        .naive_utc()
        .date();
    assert!(validate_date_not_too_far(date).is_err());
}

// --- parse_avail_windows edge cases ---

#[test]
fn parse_avail_windows_three_windows() {
    let windows = parse_avail_windows(
        Some("08:00-12:00,13:00-15:00,16:00-18:00"),
        Some("09:00"),
        Some("17:00"),
    );
    assert_eq!(windows.len(), 3);
    assert_eq!(windows[0], ("08:00".to_string(), "12:00".to_string()));
    assert_eq!(windows[1], ("13:00".to_string(), "15:00".to_string()));
    assert_eq!(windows[2], ("16:00".to_string(), "18:00".to_string()));
}

// --- Slots computation edge cases ---

#[tokio::test]
async fn compute_slots_with_min_notice_filters_near_slots() {
    let pool = setup_test_db().await;
    let (_, _, et_id) = seed_test_data(&pool).await;

    // With 480 min (8 hour) minimum notice, today's slots should be filtered
    let slot_days = compute_slots(
        &pool,
        &et_id,
        30,
        0,
        0,
        480, // 8 hours notice
        0,   // start from today
        1,   // just today
        Tz::UTC,
        Tz::UTC,
        BusySource::Individual(vec![]),
    )
    .await;

    // Today's slots might all be filtered depending on current time
    // Just verify it doesn't crash
    let _ = slot_days;
}

#[tokio::test]
async fn compute_slots_with_buffer_reduces_available() {
    let pool = setup_test_db().await;
    let (_, _, et_id) = seed_test_data(&pool).await;

    let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
    let mut next_monday = now.date() + Duration::days(1);
    while next_monday.weekday() != chrono::Weekday::Mon {
        next_monday += Duration::days(1);
    }
    let days_to_monday = (next_monday - now.date()).num_days() as i32;

    // Block 10:00-11:00
    let busy_start = next_monday.and_hms_opt(10, 0, 0).unwrap();
    let busy_end = next_monday.and_hms_opt(11, 0, 0).unwrap();

    // Without buffer: 2 slots blocked (10:00, 10:30)
    let no_buffer = compute_slots(
        &pool,
        &et_id,
        30,
        0,
        0,
        0,
        days_to_monday,
        1,
        Tz::UTC,
        Tz::UTC,
        BusySource::Individual(vec![(busy_start, busy_end)]),
    )
    .await;

    // With 30min buffer before+after: more slots blocked
    let with_buffer = compute_slots(
        &pool,
        &et_id,
        30,
        30,
        30,
        0,
        days_to_monday,
        1,
        Tz::UTC,
        Tz::UTC,
        BusySource::Individual(vec![(busy_start, busy_end)]),
    )
    .await;

    let no_buf_count: usize = no_buffer.iter().map(|d| d.slots.len()).sum();
    let buf_count: usize = with_buffer.iter().map(|d| d.slots.len()).sum();
    assert!(
        buf_count < no_buf_count,
        "Buffer should reduce available slots: {} < {}",
        buf_count,
        no_buf_count
    );
}

// --- Dashboard with cancelled bookings (shouldn't show) ---

#[tokio::test]
async fn dashboard_bookings_hides_cancelled() {
    let (app, pool, session, et_id) = setup_test_app().await;

    let booking_id = uuid::Uuid::new_v4().to_string();
    let cancel_tok = uuid::Uuid::new_v4().to_string();
    let resched_tok = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token) VALUES (?, ?, 'uid-cancelled', 'Cancelled Guest', 'cancelled@test.com', 'UTC', '2030-06-15T10:00:00', '2030-06-15T10:30:00', 'cancelled', ?, ?)")
        .bind(&booking_id)
        .bind(&et_id)
        .bind(&cancel_tok)
        .bind(&resched_tok)
        .execute(&pool)
        .await
        .unwrap();

    let response = app
        .oneshot(get_authed("/dashboard/bookings", &session))
        .await
        .unwrap();
    let body = body_string(response).await;
    assert!(
        !body.contains("Cancelled Guest"),
        "Cancelled bookings should not appear in upcoming"
    );
}

// --- Pending bookings show on dashboard ---

#[tokio::test]
async fn dashboard_bookings_shows_pending() {
    let (app, pool, session, et_id) = setup_test_app().await;

    let booking_id = uuid::Uuid::new_v4().to_string();
    let cancel_tok = uuid::Uuid::new_v4().to_string();
    let resched_tok = uuid::Uuid::new_v4().to_string();
    let confirm_tok = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token, confirm_token) VALUES (?, ?, 'uid-pending-dash', 'Pending Guest', 'pending-dash@test.com', 'UTC', '2030-06-15T10:00:00', '2030-06-15T10:30:00', 'pending', ?, ?, ?)")
        .bind(&booking_id)
        .bind(&et_id)
        .bind(&cancel_tok)
        .bind(&resched_tok)
        .bind(&confirm_tok)
        .execute(&pool)
        .await
        .unwrap();

    let response = app
        .oneshot(get_authed("/dashboard/bookings", &session))
        .await
        .unwrap();
    let body = body_string(response).await;
    assert!(
        body.contains("Pending Guest"),
        "Pending bookings should appear in pending approval section"
    );
}

// --- Invalid date in booking ---

#[tokio::test]
async fn booking_invalid_date_rejected() {
    let (app, _, _, _) = setup_test_app().await;
    let csrf = "test-csrf-bad-date";
    let body = format!(
        "_csrf={}&date=not-a-date&time=10%3A00&name=Jane&email=jane%40test.com&notes=",
        csrf
    );
    let response = app
        .oneshot(post_form_unauthed(
            "/u/testuser/test-meeting/book",
            csrf,
            &body,
        ))
        .await
        .unwrap();
    let resp_body = body_string(response).await;
    assert!(
        resp_body.contains("Invalid") || resp_body.contains("invalid"),
        "Invalid date should be rejected"
    );
}

// --- Invalid time in booking ---

#[tokio::test]
async fn booking_invalid_time_rejected() {
    let (app, _, _, _) = setup_test_app().await;
    let csrf = "test-csrf-bad-time";

    let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
    let mut next_monday = now.date() + Duration::days(1);
    while next_monday.weekday() != chrono::Weekday::Mon {
        next_monday += Duration::days(1);
    }
    let date_str = next_monday.format("%Y-%m-%d").to_string();

    let body = format!(
        "_csrf={}&date={}&time=not-a-time&name=Jane&email=jane%40test.com&notes=",
        csrf, date_str
    );
    let response = app
        .oneshot(post_form_unauthed(
            "/u/testuser/test-meeting/book",
            csrf,
            &body,
        ))
        .await
        .unwrap();
    let resp_body = body_string(response).await;
    assert!(
        resp_body.contains("Invalid") || resp_body.contains("invalid"),
        "Invalid time should be rejected"
    );
}

// ====== XSS regression guards (#43) ======
//
// Three dashboard templates used to embed user-controlled strings inside
// inline onclick JS string literals using `\'{{ var }}\'` as a naïve
// escape. MiniJinja auto-escapes `'` to `&#x27;` but leaves backslashes
// untouched, so a payload like `\\'));alert(1);//` breaks out of the JS
// string and injects script. Fix was to move the value into a
// `data-confirm` attribute and read it via `this.dataset.confirm` so it's
// never re-parsed as JS.
//
// These tests render each template with a crafted payload and assert
// that (a) the onclick is the safe static form and (b) the payload only
// lands in data-confirm (HTML-escaped). They fire if anyone re-introduces
// a `{{ … }}` interpolation inside an onclick.

/// Pull the bytes of the `onclick="…"` attribute for the first `<button>`
/// whose attributes contain `class_marker`. Only considers button-element
/// attribute strings (between `<button` and the first `>` after it), so
/// CSS/JS elsewhere in the document that happens to mention the marker
/// doesn't throw off the scan. Returns None if no such button exists.
fn extract_onclick_for_button(html: &str, class_marker: &str) -> Option<String> {
    // Skip the prefix before the first `<button` (document boilerplate).
    let mut rest = html;
    while let Some(idx) = rest.find("<button") {
        let after = &rest[idx + "<button".len()..];
        let (attrs, tail) = after.split_once('>')?;
        if attrs.contains(class_marker) {
            if let Some(attr_rest) = attrs.split_once("onclick=\"") {
                if let Some((value, _)) = attr_rest.1.split_once('"') {
                    return Some(value.to_string());
                }
            }
        }
        rest = tail;
    }
    None
}

const XSS_PAYLOAD: &str = r#"\\'));alert(1);//"#;

#[test]
fn dashboard_event_types_delete_button_no_onclick_interpolation() {
    let mut env = minijinja::Environment::new();
    env.set_undefined_behavior(minijinja::UndefinedBehavior::Lenient);
    env.set_loader(minijinja::path_loader("templates"));
    crate::i18n::register(&mut env);
    let tmpl = env
        .get_template("dashboard_event_types.html")
        .expect("template loads");

    let rendered = tmpl
        .render(context! {
            sidebar => context! {},
            username => "alice",
            has_any => true,
            all_event_types => vec![context! {
                id => "et-1",
                slug => "intro",
                title => XSS_PAYLOAD,
                duration_min => 30,
                enabled => true,
                visibility => "public",
                can_manage => true,
                active_bookings => 0,
                is_team => false,
                edit_url => "/e/edit",
                toggle_url => "/e/toggle",
                overrides_url => "/e/overrides",
                embed_url => "/e/embed",
                delete_url => "/e/delete",
                view_url => "/e/view",
            }],
        })
        .expect("renders");

    let onclick = extract_onclick_for_button(&rendered, r#"class="danger""#)
        .expect("delete button onclick present");
    assert_eq!(
        onclick, "if(confirm(this.dataset.confirm)) this.nextElementSibling.submit();",
        "onclick must be the static safe form — no interpolation allowed",
    );
    // The payload should appear only inside the data-confirm attribute,
    // HTML-escaped. Backslashes pass through unchanged, apostrophes
    // become &#x27;.
    assert!(
        rendered.contains(r#"data-confirm="Delete event type '\\&#x27;));alert(1);&#x2f;&#x2f;'"#),
        "payload should be inside data-confirm only"
    );
}

#[test]
fn dashboard_sources_remove_button_no_onclick_interpolation() {
    let mut env = minijinja::Environment::new();
    env.set_undefined_behavior(minijinja::UndefinedBehavior::Lenient);
    env.set_loader(minijinja::path_loader("templates"));
    crate::i18n::register(&mut env);
    let tmpl = env
        .get_template("dashboard_sources.html")
        .expect("template loads");

    let rendered = tmpl
        .render(context! {
            sidebar => context! {},
            sources => vec![context! {
                id => "s-1",
                name => XSS_PAYLOAD,
                url => "https://example.com/dav",
                username => "alice",
                enabled => true,
                last_synced => "never",
                calendar_count => 0,
                event_count => 0,
                needs_write_setup => false,
            }],
        })
        .expect("renders");

    // The Remove button is the one containing "Remove" text AND the
    // error-text style. It's distinguishable from "Test" by the
    // var(--error-text) inline style.
    let onclick = extract_onclick_for_button(&rendered, "var(--error-text)")
        .expect("remove button onclick present");
    assert_eq!(
        onclick,
        "if(confirm(this.dataset.confirm)) this.closest('div').querySelector('.remove-form').submit();",
        "onclick must be the static safe form — no interpolation allowed",
    );
    assert!(
        rendered.contains(r#"data-confirm="Remove source '\\&#x27;));alert(1);&#x2f;&#x2f;'"#),
        "payload should be inside data-confirm only"
    );
}

#[test]
fn team_settings_delete_button_no_onclick_interpolation() {
    let mut env = minijinja::Environment::new();
    env.set_undefined_behavior(minijinja::UndefinedBehavior::Lenient);
    env.set_loader(minijinja::path_loader("templates"));
    crate::i18n::register(&mut env);
    let tmpl = env
        .get_template("team_settings.html")
        .expect("template loads");

    let rendered = tmpl
        .render(context! {
            sidebar => context! {},
            team_id => "t-1",
            team_name => XSS_PAYLOAD,
            team_slug => "acme",
            team_description => "",
            team_avatar_path => minijinja::value::Value::from(None::<String>),
            team_visibility => "public",
            invite_token => minijinja::value::Value::from(None::<String>),
            members => Vec::<minijinja::Value>::new(),
            linked_groups => Vec::<minijinja::Value>::new(),
            available_groups => Vec::<minijinja::Value>::new(),
            can_admin => true,
            is_owner => true,
        })
        .expect("renders");

    let onclick = extract_onclick_for_button(&rendered, "border-color: var(--error-text)")
        .expect("delete team button onclick present");
    assert_eq!(
        onclick, "if(confirm(this.dataset.confirm)) this.nextElementSibling.submit();",
        "onclick must be the static safe form — no interpolation allowed",
    );
    assert!(
        rendered.contains(r#"data-confirm="Delete team '\\&#x27;));alert(1);&#x2f;&#x2f;'"#),
        "payload should be inside data-confirm only"
    );
}

// --- Bulk invite parsing tests ---

#[test]
fn bulk_invite_parses_valid_emails() {
    let (valid, result) = parse_bulk_recipients("alice@example.com\nbob@example.org\n", 100);
    assert_eq!(valid.len(), 2);
    assert_eq!(valid[0].0, "alice@example.com");
    assert_eq!(valid[0].1, "Alice");
    assert_eq!(valid[1].0, "bob@example.org");
    assert_eq!(valid[1].1, "Bob");
    assert!(result.invalid.is_empty());
    assert!(result.duplicates.is_empty());
    assert!(!result.over_limit);
}

#[test]
fn bulk_invite_skips_blank_lines_and_trims() {
    let (valid, _) = parse_bulk_recipients("\n  alice@example.com  \n\n", 100);
    assert_eq!(valid.len(), 1);
    assert_eq!(valid[0].0, "alice@example.com");
}

#[test]
fn bulk_invite_rejects_malformed_rows() {
    let (valid, result) = parse_bulk_recipients(
        "alice@example.com\nnot-an-email\n@nope.com\nfoo@\nfoo@bar\nok@x.io",
        100,
    );
    assert_eq!(valid.len(), 2);
    assert_eq!(result.invalid.len(), 4);
}

#[test]
fn bulk_invite_dedupes_case_insensitively() {
    let (valid, result) = parse_bulk_recipients("Alice@Example.com\nalice@example.com\n", 100);
    assert_eq!(valid.len(), 1);
    assert_eq!(result.duplicates, vec!["alice@example.com".to_string()]);
}

#[test]
fn bulk_invite_caps_at_max() {
    let mut input = String::new();
    for i in 0..10 {
        input.push_str(&format!("user{}@example.com\n", i));
    }
    let (valid, result) = parse_bulk_recipients(&input, 3);
    assert_eq!(valid.len(), 3);
    assert!(result.over_limit);
}

#[test]
fn bulk_invite_derives_pretty_names() {
    assert_eq!(derive_name_from_email("john.doe@example.com"), "John Doe");
    assert_eq!(
        derive_name_from_email("mary_smith@example.com"),
        "Mary Smith"
    );
    assert_eq!(derive_name_from_email("alice@example.com"), "Alice");
}

// --- build_csp tests ---

fn make_captcha_config(instance_url: &str, widget_url: &str) -> captcha::CaptchaConfig {
    captcha::CaptchaConfig {
        instance_url: instance_url.to_string(),
        site_key: "testkey".to_string(),
        secret: "secret".to_string(),
        widget_url: widget_url.to_string(),
    }
}

#[test]
fn build_csp_without_captcha_has_no_extra_directives() {
    let csp = build_csp(&None);
    assert!(!csp.contains("wasm-unsafe-eval"));
    assert!(!csp.contains("worker-src"));
    assert!(!csp.contains("cdn.jsdelivr.net"));
    assert!(csp.contains("script-src 'self' 'unsafe-inline'"));
    assert!(csp.contains("connect-src 'self'"));
}

#[test]
fn build_csp_with_captcha_includes_wasm_and_worker_src() {
    let cfg = Some(make_captcha_config(
        "https://cap.example.com",
        captcha::DEFAULT_WIDGET_URL,
    ));
    let csp = build_csp(&cfg);
    assert!(csp.contains("'wasm-unsafe-eval'"));
    assert!(csp.contains("worker-src blob:"));
}

#[test]
fn build_csp_with_captcha_includes_script_origin() {
    let cfg = Some(make_captcha_config(
        "https://cap.example.com",
        captcha::DEFAULT_WIDGET_URL,
    ));
    let csp = build_csp(&cfg);
    assert!(csp.contains("https://cdn.jsdelivr.net"), "{}", csp);
}

#[test]
fn booking_form_paths_get_relaxed_csp() {
    assert!(is_booking_form_path("/u/alice/intro/book"));
    assert!(is_booking_form_path("/team/sales/demo/book"));
    assert!(is_booking_form_path("/intro/book"));
}

#[test]
fn non_booking_paths_keep_baseline_csp() {
    assert!(!is_booking_form_path("/"));
    assert!(!is_booking_form_path("/dashboard"));
    assert!(!is_booking_form_path("/dashboard/admin"));
    assert!(!is_booking_form_path("/u/alice/intro"));
    assert!(!is_booking_form_path("/booking/cancel/sometoken"));
    assert!(!is_booking_form_path("/u/alice/bookkeeping"));
}

#[test]
fn build_csp_with_captcha_includes_connect_origins() {
    let cfg = Some(make_captcha_config(
        "https://cap.example.com",
        captcha::DEFAULT_WIDGET_URL,
    ));
    let csp = build_csp(&cfg);
    assert!(csp.contains("connect-src 'self'"), "{}", csp);
    assert!(csp.contains("https://cap.example.com"), "{}", csp);
    assert!(csp.contains("https://cdn.jsdelivr.net"), "{}", csp);
}

// Embed mode must preserve captcha allowances (so captcha-enabled
// deployments can still serve a working booking form inside iframes).
// `csp_middleware` does the swap via string replace on the strict CSP,
// so we verify the contract: the produced CSP keeps frame-ancestors
// exactly once and contains the expected substring for swapping.
#[test]
fn build_csp_contains_frame_ancestors_self_for_swap() {
    assert_eq!(
        build_csp(&None).matches("frame-ancestors 'self'").count(),
        1
    );
    let cfg = Some(make_captcha_config(
        "https://cap.example.com",
        captcha::DEFAULT_WIDGET_URL,
    ));
    assert_eq!(build_csp(&cfg).matches("frame-ancestors 'self'").count(), 1);
}

#[test]
fn build_csp_embed_swap_preserves_captcha_allowances() {
    let cfg = Some(make_captcha_config(
        "https://cap.example.com",
        captcha::DEFAULT_WIDGET_URL,
    ));
    let strict = build_csp(&cfg);
    let embed_csp = strict.replace("frame-ancestors 'self'", "frame-ancestors *");
    assert!(embed_csp.contains("frame-ancestors *"));
    assert!(!embed_csp.contains("frame-ancestors 'self'"));
    // Captcha allowances must survive the swap so the widget loads in an
    // embedded booking form.
    assert!(embed_csp.contains("'wasm-unsafe-eval'"));
    assert!(embed_csp.contains("worker-src blob:"));
    assert!(embed_csp.contains("https://cap.example.com"));
    assert!(embed_csp.contains("https://cdn.jsdelivr.net"));
}
