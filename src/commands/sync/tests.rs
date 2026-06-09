use super::*;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::str::FromStr;

async fn setup_test_db() -> SqlitePool {
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

/// Seed the minimum fixtures needed to exercise the orphan sweep:
/// one user + account + event type + caldav source. Returns the source id.
async fn seed_fixtures(pool: &SqlitePool) -> (String, String) {
    let user_id = Uuid::new_v4().to_string();
    let account_id = Uuid::new_v4().to_string();
    let et_id = Uuid::new_v4().to_string();
    let source_id = Uuid::new_v4().to_string();

    sqlx::query("INSERT INTO users (id, email, name, role, auth_provider, username, enabled) VALUES (?, 'host@example.com', 'Host', 'admin', 'local', 'host', 1)")
        .bind(&user_id).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO accounts (id, name, email, timezone, user_id) VALUES (?, 'Host', 'host@example.com', 'UTC', ?)")
        .bind(&account_id).bind(&user_id).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO event_types (id, account_id, slug, title, duration_min) VALUES (?, ?, 'intro', 'Intro', 30)")
        .bind(&et_id).bind(&account_id).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO caldav_sources (id, account_id, name, url, username, write_calendar_href) VALUES (?, ?, 'test', 'https://dav.example.com/', 'user', '/calendars/host/default/')")
        .bind(&source_id).bind(&account_id).execute(pool).await.unwrap();

    (source_id, et_id)
}

/// Regression test for issue #44: a pending booking whose CalDAV event was deleted
/// during a guest-initiated reschedule must NOT be cancelled by the orphan sweep.
/// Before the fix, this scenario caused the reschedule request to be cancelled
/// before the host could click approve — only the previous meeting was cancelled
/// and no new one was created.
#[tokio::test]
async fn orphan_sweep_skips_pending_booking_awaiting_approval() {
    let pool = setup_test_db().await;
    let (source_id, et_id) = seed_fixtures(&pool).await;
    let key = [0u8; 32];

    // Booking in the exact state produced by guest_reschedule_booking's pending
    // branch: status='pending', caldav_calendar_href still set from the prior
    // confirmed push (fix A in web/mod.rs clears this — but the sweep must also
    // be safe even if a legacy booking row still has the href set).
    let booking_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone,
            start_at, end_at, status, cancel_token, reschedule_token, caldav_calendar_href)
         VALUES (?, ?, 'orphaned-uid', 'Guest', 'guest@example.com', 'UTC',
            '2030-06-15T10:00:00', '2030-06-15T10:30:00', 'pending', 'ctok', 'rtok',
            '/calendars/host/default/')",
    )
    .bind(&booking_id)
    .bind(&et_id)
    .execute(&pool)
    .await
    .unwrap();
    // Note: no matching row in `events` — the CalDAV event was deleted during reschedule.

    cancel_orphaned_bookings(&pool, &key, None, &source_id).await;

    let status: String = sqlx::query_scalar("SELECT status FROM bookings WHERE id = ?")
        .bind(&booking_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        status, "pending",
        "pending bookings must not be auto-cancelled by the orphan sweep — \
         they're awaiting host approval, not tracking a CalDAV event"
    );
}

/// Regression test for production incident 2026-05-14: a sync-collection delta
/// reported an href as deleted, but the local `events` table had no matching row
/// (the event lived on a different calendar — the booking's write calendar).
/// Before the fix, `delete_events_by_href` still called `cancel_orphaned_booking`,
/// which scans bookings globally by UID and wrongly cancelled a live booking.
/// The fix gates the cancellation on the local DELETE having matched a row.
#[tokio::test]
async fn delete_events_by_href_skips_cancellation_when_no_local_event() {
    let pool = setup_test_db().await;
    let (source_id, et_id) = seed_fixtures(&pool).await;
    let key = [0u8; 32];

    // Seed a calendar on this source (the one that supposedly reported a
    // deletion via sync-collection delta).
    let cal_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO calendars (id, source_id, href, display_name) \
         VALUES (?, ?, '/calendars/host/shared/', 'Shared')",
    )
    .bind(&cal_id)
    .bind(&source_id)
    .execute(&pool)
    .await
    .unwrap();

    // The confirmed booking. Note: NO matching row in `events` for this calendar
    // — the booking's CalDAV event lives elsewhere (or was never synced into
    // this particular calendar).
    let booking_uid = "live-booking-uid@calrs";
    let booking_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone,
            start_at, end_at, status, cancel_token, reschedule_token, caldav_calendar_href)
         VALUES (?, ?, ?, 'Guest', 'guest@example.com', 'UTC',
            '2030-06-15T10:00:00', '2030-06-15T10:30:00', 'confirmed', 'ctok', 'rtok',
            '/calendars/host/default/')",
    )
    .bind(&booking_id)
    .bind(&et_id)
    .bind(booking_uid)
    .execute(&pool)
    .await
    .unwrap();

    // Simulate BlueMind's sync-collection reporting this href as deleted on
    // the Shared calendar (false positive — the event isn't there locally).
    let href = format!("/calendars/host/shared/{}.ics", booking_uid);
    let deleted = delete_events_by_href(&pool, &key, None, &source_id, &cal_id, &[href]).await;
    assert_eq!(deleted, 0, "no local row to delete");

    let status: String = sqlx::query_scalar("SELECT status FROM bookings WHERE id = ?")
        .bind(&booking_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        status, "confirmed",
        "a sync-collection 'deleted' href with no local event MUST NOT cancel the booking"
    );
}

/// Positive case for `delete_events_by_href`: when the server reports a deletion
/// AND we had a matching local event for that calendar, we both remove the event
/// and cancel any booking with that UID. This is the legitimate signal.
#[tokio::test]
async fn delete_events_by_href_cancels_when_local_event_existed() {
    let pool = setup_test_db().await;
    let (source_id, et_id) = seed_fixtures(&pool).await;
    let key = [0u8; 32];

    let cal_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO calendars (id, source_id, href, display_name) \
         VALUES (?, ?, '/calendars/host/default/', 'Default')",
    )
    .bind(&cal_id)
    .bind(&source_id)
    .execute(&pool)
    .await
    .unwrap();

    let booking_uid = "to-be-cancelled@calrs";

    // Seed the local event row (we knew about it before the server signaled deletion).
    sqlx::query(
        "INSERT INTO events (id, calendar_id, uid, summary, start_at, end_at) \
         VALUES (?, ?, ?, 'Demo', '2030-06-15T10:00:00', '2030-06-15T10:30:00')",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&cal_id)
    .bind(booking_uid)
    .execute(&pool)
    .await
    .unwrap();

    let booking_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone,
            start_at, end_at, status, cancel_token, reschedule_token, caldav_calendar_href)
         VALUES (?, ?, ?, 'Guest', 'guest@example.com', 'UTC',
            '2030-06-15T10:00:00', '2030-06-15T10:30:00', 'confirmed', 'ctok', 'rtok',
            '/calendars/host/default/')",
    )
    .bind(&booking_id)
    .bind(&et_id)
    .bind(booking_uid)
    .execute(&pool)
    .await
    .unwrap();

    let href = format!("/calendars/host/default/{}.ics", booking_uid);
    let deleted = delete_events_by_href(&pool, &key, None, &source_id, &cal_id, &[href]).await;
    assert_eq!(deleted, 1, "local row should have been removed");

    let status: String = sqlx::query_scalar("SELECT status FROM bookings WHERE id = ?")
        .bind(&booking_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status, "cancelled");
}

/// Confirm-before-cancel (issue #105): when the verification HTTP call can't
/// reach the server (unreachable host, timeout, 5xx), `cancel_orphaned_booking`
/// must treat the result as inconclusive and SKIP the cancellation. The
/// principle is "never cancel a customer booking unless the server confirms
/// the event is gone." A flaky network minute is no basis for cancelling.
///
/// This test points the CaldavClient at a closed port so the HEAD fails with
/// a connection error; we set up a delta-path scenario where the booking
/// would otherwise be cancelled (local event present, server reports deletion).
#[tokio::test]
async fn delete_events_by_href_skips_cancellation_when_verification_fails() {
    let pool = setup_test_db().await;
    let (source_id, et_id) = seed_fixtures(&pool).await;
    let key = [0u8; 32];

    let cal_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO calendars (id, source_id, href, display_name) \
         VALUES (?, ?, '/calendars/host/default/', 'Default')",
    )
    .bind(&cal_id)
    .bind(&source_id)
    .execute(&pool)
    .await
    .unwrap();

    let booking_uid = "ambiguous-deletion@calrs";

    // Local event row exists — so the DELETE will report rows_affected > 0
    // and the hotfix gate alone wouldn't save us. Only the verification
    // layer should keep this booking confirmed.
    sqlx::query(
        "INSERT INTO events (id, calendar_id, uid, summary, start_at, end_at) \
         VALUES (?, ?, ?, 'Demo', '2030-06-15T10:00:00', '2030-06-15T10:30:00')",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&cal_id)
    .bind(booking_uid)
    .execute(&pool)
    .await
    .unwrap();

    let booking_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone,
            start_at, end_at, status, cancel_token, reschedule_token, caldav_calendar_href)
         VALUES (?, ?, ?, 'Guest', 'guest@example.com', 'UTC',
            '2030-06-15T10:00:00', '2030-06-15T10:30:00', 'confirmed', 'ctok', 'rtok',
            '/calendars/host/default/')",
    )
    .bind(&booking_id)
    .bind(&et_id)
    .bind(booking_uid)
    .execute(&pool)
    .await
    .unwrap();

    // Port 1 is reserved (tcpmux) and ~always closed on a dev box — HEAD will
    // fail with a connection refusal, exercising the Err(_) arm of the
    // verification gate.
    let client = CaldavClient::new("http://127.0.0.1:1", "u", "p");

    let href = format!("/calendars/host/default/{}.ics", booking_uid);
    let _ = delete_events_by_href(&pool, &key, Some(&client), &source_id, &cal_id, &[href]).await;

    let status: String = sqlx::query_scalar("SELECT status FROM bookings WHERE id = ?")
        .bind(&booking_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        status, "confirmed",
        "verification HTTP failure must NOT cancel the booking — \
         inconclusive evidence cannot justify a customer-visible cancellation"
    );
}

/// Positive case: the orphan sweep still cancels a confirmed booking whose CalDAV
/// event has been deleted (host removed it directly in their calendar app). This
/// is the original intent of the feature and must keep working.
#[tokio::test]
async fn orphan_sweep_cancels_confirmed_booking_with_missing_event() {
    let pool = setup_test_db().await;
    let (source_id, et_id) = seed_fixtures(&pool).await;
    let key = [0u8; 32];

    let booking_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone,
            start_at, end_at, status, cancel_token, reschedule_token, caldav_calendar_href)
         VALUES (?, ?, 'deleted-uid', 'Guest', 'guest@example.com', 'UTC',
            '2030-06-15T10:00:00', '2030-06-15T10:30:00', 'confirmed', 'ctok', 'rtok',
            '/calendars/host/default/')",
    )
    .bind(&booking_id)
    .bind(&et_id)
    .execute(&pool)
    .await
    .unwrap();

    cancel_orphaned_bookings(&pool, &key, None, &source_id).await;

    let status: String = sqlx::query_scalar("SELECT status FROM bookings WHERE id = ?")
        .bind(&booking_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status, "cancelled");
}

/// Issue #106 (cross-source isolation defense-in-depth): a sync of source A
/// must NEVER cancel a booking that belongs to source B's account, even if
/// the UIDs collide. UUIDs make natural collisions vanishingly unlikely, but
/// a single-tenant install where an admin imports an iCal feed (or a future
/// codepath that generates UIDs from a non-UUID source) could produce one.
/// The lookup in `cancel_orphaned_booking` is scoped via a join on
/// `caldav_sources.account_id = event_types.account_id`, with the source_id
/// filter pinning the side we're acting on. This test verifies that scoping.
#[tokio::test]
async fn cancel_does_not_cross_source_account_boundary() {
    let pool = setup_test_db().await;
    // Account A: gets seeded by the helper. Source A, event type A.
    // We don't act ON source A in this test — we only verify a sync of
    // source B can't reach across to cancel a booking on account A.
    let (_source_a_id, et_a_id) = seed_fixtures(&pool).await;

    // Account B: separate user, account, event type, source.
    let user_b_id = Uuid::new_v4().to_string();
    let account_b_id = Uuid::new_v4().to_string();
    let et_b_id = Uuid::new_v4().to_string();
    let source_b_id = Uuid::new_v4().to_string();
    let cal_b_id = Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO users (id, email, name, role, auth_provider, username, enabled) VALUES (?, 'host-b@example.com', 'Host B', 'user', 'local', 'hostb', 1)")
        .bind(&user_b_id).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO accounts (id, name, email, timezone, user_id) VALUES (?, 'Host B', 'host-b@example.com', 'UTC', ?)")
        .bind(&account_b_id).bind(&user_b_id).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO event_types (id, account_id, slug, title, duration_min) VALUES (?, ?, 'intro-b', 'Intro B', 30)")
        .bind(&et_b_id).bind(&account_b_id).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO caldav_sources (id, account_id, name, url, username, write_calendar_href) VALUES (?, ?, 'test-b', 'https://dav-b.example.com/', 'user-b', '/calendars/hostb/default/')")
        .bind(&source_b_id).bind(&account_b_id).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO calendars (id, source_id, href, display_name) VALUES (?, ?, '/calendars/hostb/default/', 'Default B')")
        .bind(&cal_b_id).bind(&source_b_id).execute(&pool).await.unwrap();

    let shared_uid = "colliding-uid@calrs";
    let key = [0u8; 32];

    // Confirmed booking on ACCOUNT A — this is what we're protecting.
    let booking_a_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone,
            start_at, end_at, status, cancel_token, reschedule_token, caldav_calendar_href)
         VALUES (?, ?, ?, 'Guest', 'guest@example.com', 'UTC',
            '2030-06-15T10:00:00', '2030-06-15T10:30:00', 'confirmed', 'ctok', 'rtok',
            '/calendars/host/default/')",
    )
    .bind(&booking_a_id)
    .bind(&et_a_id)
    .bind(shared_uid)
    .execute(&pool)
    .await
    .unwrap();

    // Local event on SOURCE B's calendar with the same UID — so the
    // DELETE in `delete_events_by_href` will report rows_affected > 0
    // and the rows_affected gate alone can't save us. Only the
    // source-scoped lookup keeps booking A safe.
    sqlx::query(
        "INSERT INTO events (id, calendar_id, uid, summary, start_at, end_at) \
         VALUES (?, ?, ?, 'Colliding event on B', '2030-06-15T10:00:00', '2030-06-15T10:30:00')",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&cal_b_id)
    .bind(shared_uid)
    .execute(&pool)
    .await
    .unwrap();

    // Source B reports the colliding UID as deleted.
    let href = format!("/calendars/hostb/default/{}.ics", shared_uid);
    let deleted = delete_events_by_href(&pool, &key, None, &source_b_id, &cal_b_id, &[href]).await;
    assert_eq!(
        deleted, 1,
        "the local event row on source B should have been removed"
    );

    // Booking on ACCOUNT A must still be confirmed.
    let status: String = sqlx::query_scalar("SELECT status FROM bookings WHERE id = ?")
        .bind(&booking_a_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        status, "confirmed",
        "a sync of source B must not cancel a booking on account A — \
         source/account scoping is the defense-in-depth boundary"
    );
}

#[tokio::test]
async fn source_lock_identity() {
    // Same id returns the same Arc so concurrent callers contend on one
    // mutex; different ids are independent so unrelated sources can sync
    // in parallel.
    let id_a = format!("lock-test-a-{}", Uuid::new_v4());
    let id_b = format!("lock-test-b-{}", Uuid::new_v4());

    let a1 = source_lock(&id_a).await;
    let a2 = source_lock(&id_a).await;
    let b1 = source_lock(&id_b).await;

    assert!(
        Arc::ptr_eq(&a1, &a2),
        "same id must resolve to the same mutex"
    );
    assert!(
        !Arc::ptr_eq(&a1, &b1),
        "different ids must resolve to different mutexes"
    );
}

#[tokio::test]
async fn sync_if_stale_serializes_on_per_source_lock() {
    // Dedup regression: while one task holds the per-source lock (the
    // "winner" of a race), a second sync_if_stale call for the same
    // source must wait. After the winner bumps last_synced and releases,
    // the waiter re-checks, sees a fresh timestamp, and skips without
    // attempting to hit CalDAV.
    let pool = setup_test_db().await;
    let (source_id, _et_id) = seed_fixtures(&pool).await;

    // Mark stale and give the source a non-null password_enc so the
    // stale_sources SELECT deserializes successfully (the value itself
    // doesn't matter — decrypt would fail but we never reach it).
    sqlx::query(
        "UPDATE caldav_sources SET last_synced = '2000-01-01 00:00:00', password_enc = 'deadbeef' WHERE id = ?",
    )
    .bind(&source_id)
    .execute(&pool)
    .await
    .unwrap();

    let user_id: String = sqlx::query_scalar(
        "SELECT a.user_id FROM caldav_sources cs JOIN accounts a ON a.id = cs.account_id WHERE cs.id = ?",
    )
    .bind(&source_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    // Acquire the per-source lock before spawning the waiter.
    let lock = source_lock(&source_id).await;
    let guard = lock.lock().await;

    let pool_clone = pool.clone();
    let uid_clone = user_id.clone();
    let key = [0u8; 32];
    let waiter = tokio::spawn(async move {
        sync_if_stale(&pool_clone, &key, &uid_clone).await;
    });

    // Give the waiter a chance to reach the lock acquisition.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(
        !waiter.is_finished(),
        "sync_if_stale must block while the per-source mutex is held"
    );

    // Simulate the winner completing its sync: bump last_synced to now.
    sqlx::query("UPDATE caldav_sources SET last_synced = datetime('now') WHERE id = ?")
        .bind(&source_id)
        .execute(&pool)
        .await
        .unwrap();

    // Release the lock. The waiter re-checks, sees fresh state, and
    // returns quickly without doing any network work.
    drop(guard);

    tokio::time::timeout(std::time::Duration::from_secs(2), waiter)
        .await
        .expect("sync_if_stale did not return after the lock was released")
        .expect("sync_if_stale task panicked");
}
