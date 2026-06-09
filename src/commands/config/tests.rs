use super::*;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::str::FromStr;

async fn setup_db() -> SqlitePool {
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

#[tokio::test]
async fn config_show_no_smtp() {
    let pool = setup_db().await;
    let key = [0u8; 32];
    let result = run(&pool, &key, ConfigCommands::Show).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn config_show_with_smtp() {
    let pool = setup_db().await;
    let key = [0u8; 32];

    let smtp_id = Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO smtp_config (id, host, port, username, password_enc, from_email, from_name, enabled) VALUES (?, 'smtp.test.com', 587, 'user', 'enc', 'noreply@test.com', 'Test', 1)")
        .bind(&smtp_id).execute(&pool).await.unwrap();

    let result = run(&pool, &key, ConfigCommands::Show).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn config_auth_show_defaults() {
    let pool = setup_db().await;
    let key = [0u8; 32];
    // No flags — shows current config
    let result = run(
        &pool,
        &key,
        ConfigCommands::Auth {
            registration: None,
            allowed_domains: None,
        },
    )
    .await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn config_auth_disable_registration() {
    let pool = setup_db().await;
    let key = [0u8; 32];
    let result = run(
        &pool,
        &key,
        ConfigCommands::Auth {
            registration: Some(false),
            allowed_domains: None,
        },
    )
    .await;
    assert!(result.is_ok());

    let enabled: bool =
        sqlx::query_scalar("SELECT registration_enabled FROM auth_config WHERE id = 'singleton'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(!enabled);
}

#[tokio::test]
async fn config_auth_set_allowed_domains() {
    let pool = setup_db().await;
    let key = [0u8; 32];
    let result = run(
        &pool,
        &key,
        ConfigCommands::Auth {
            registration: None,
            allowed_domains: Some("example.com,test.org".to_string()),
        },
    )
    .await;
    assert!(result.is_ok());

    let domains: Option<String> =
        sqlx::query_scalar("SELECT allowed_email_domains FROM auth_config WHERE id = 'singleton'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(domains.unwrap(), "example.com,test.org");
}

#[tokio::test]
async fn config_auth_clear_domains_with_any() {
    let pool = setup_db().await;
    let key = [0u8; 32];
    // Set domains first
    let _ = run(
        &pool,
        &key,
        ConfigCommands::Auth {
            registration: None,
            allowed_domains: Some("example.com".to_string()),
        },
    )
    .await;
    // Clear with "any"
    let result = run(
        &pool,
        &key,
        ConfigCommands::Auth {
            registration: None,
            allowed_domains: Some("any".to_string()),
        },
    )
    .await;
    assert!(result.is_ok());

    let domains: Option<String> =
        sqlx::query_scalar("SELECT allowed_email_domains FROM auth_config WHERE id = 'singleton'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(domains.is_none());
}

#[tokio::test]
async fn config_oidc_set_fields() {
    let pool = setup_db().await;
    let key = [0u8; 32];
    let result = run(
        &pool,
        &key,
        ConfigCommands::Oidc {
            issuer_url: Some("https://auth.example.com/realms/test".to_string()),
            client_id: Some("calrs-app".to_string()),
            client_secret: Some("super-secret".to_string()),
            enabled: Some(true),
            auto_register: Some(true),
        },
    )
    .await;
    assert!(result.is_ok());

    let (issuer, cid, enabled, auto_reg): (Option<String>, Option<String>, bool, bool) =
        sqlx::query_as(
            "SELECT oidc_issuer_url, oidc_client_id, oidc_enabled, oidc_auto_register FROM auth_config WHERE id = 'singleton'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(issuer.unwrap(), "https://auth.example.com/realms/test");
    assert_eq!(cid.unwrap(), "calrs-app");
    assert!(enabled);
    assert!(auto_reg);
}

#[tokio::test]
async fn config_oidc_disable() {
    let pool = setup_db().await;
    let key = [0u8; 32];
    // Enable first
    let _ = run(
        &pool,
        &key,
        ConfigCommands::Oidc {
            issuer_url: None,
            client_id: None,
            client_secret: None,
            enabled: Some(true),
            auto_register: None,
        },
    )
    .await;
    // Then disable
    let result = run(
        &pool,
        &key,
        ConfigCommands::Oidc {
            issuer_url: None,
            client_id: None,
            client_secret: None,
            enabled: Some(false),
            auto_register: None,
        },
    )
    .await;
    assert!(result.is_ok());

    let enabled: bool =
        sqlx::query_scalar("SELECT oidc_enabled FROM auth_config WHERE id = 'singleton'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(!enabled);
}

#[tokio::test]
async fn config_smtp_test_no_smtp() {
    let pool = setup_db().await;
    let key = [0u8; 32];
    // No SMTP configured — should print error, not crash
    let result = run(
        &pool,
        &key,
        ConfigCommands::SmtpTest {
            to: "test@example.com".to_string(),
        },
    )
    .await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn config_dump_default() {
    let pool = setup_db().await;
    let output = build_dump_output(&pool).await.unwrap();
    assert_eq!(output["schema_version"], 1);
    assert!(output["auth"]["registration_enabled"].as_bool().unwrap());
    // Secrets must never appear in the auth section
    let auth = output["auth"].as_object().unwrap();
    for secret in [
        "oidc_client_secret",
        "captcha_secret",
        "google_oauth2_client_secret",
        "meeting_webhook_secret",
    ] {
        assert!(
            !auth.contains_key(secret),
            "auth section must not contain '{}'",
            secret
        );
    }
    assert!(output["smtp"].is_null());
    for section in [
        "accounts",
        "users",
        "user_availability_rules",
        "user_groups",
        "caldav_sources",
        "event_types",
        "availability_rules",
        "availability_overrides",
        "event_type_calendars",
        "event_type_member_weights",
        "event_type_watchers",
        "booking_frequency_limits",
        "teams",
        "team_members",
        "team_groups",
        "groups",
    ] {
        assert!(
            output[section].as_array().unwrap().is_empty(),
            "section '{}' should be an empty array",
            section
        );
    }
}

#[tokio::test]
async fn config_dump_pretty() {
    let pool = setup_db().await;
    let key = [0u8; 32];
    let result = run(&pool, &key, ConfigCommands::Dump { pretty: true }).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn config_dump_with_smtp() {
    let pool = setup_db().await;

    let smtp_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO smtp_config (id, host, port, username, password_enc, from_email, from_name, enabled) \
         VALUES (?, 'smtp.test.com', 587, 'user', 'enc', 'noreply@test.com', 'Test', 1)",
    )
    .bind(&smtp_id)
    .execute(&pool)
    .await
    .unwrap();

    let output = build_dump_output(&pool).await.unwrap();
    let smtp = output["smtp"].as_object().unwrap();
    assert_eq!(smtp["host"], "smtp.test.com");
    assert_eq!(smtp["port"], 587);
    assert_eq!(smtp["username"], "user");
    assert_eq!(smtp["from_email"], "noreply@test.com");
    assert_eq!(smtp["from_name"], "Test");
    assert!(smtp["enabled"].as_bool().unwrap());
    // Verify secret is NOT in output
    assert!(!smtp.contains_key("password_enc"));
}

#[tokio::test]
async fn config_dump_with_users_and_event_types() {
    let pool = setup_db().await;

    // Insert a user
    let user_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO users (id, email, name, password_hash, role, auth_provider) \
         VALUES (?, 'alice@test.com', 'Alice', 'hash', 'admin', 'local')",
    )
    .bind(&user_id)
    .execute(&pool)
    .await
    .unwrap();

    // Insert an account (required by event_types FK)
    let account_id = Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO accounts (id, name, email) VALUES (?, 'Alice', 'alice@test.com')")
        .bind(&account_id)
        .execute(&pool)
        .await
        .unwrap();

    // Insert an event type
    let et_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO event_types (id, account_id, slug, title, duration_min, visibility) \
         VALUES (?, ?, 'intro', 'Intro Call', 30, 'public')",
    )
    .bind(&et_id)
    .bind(&account_id)
    .execute(&pool)
    .await
    .unwrap();

    // Insert a team
    let team_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO teams (id, name, slug, visibility) VALUES (?, 'My Team', 'my-team', 'public')",
    )
    .bind(&team_id)
    .execute(&pool)
    .await
    .unwrap();

    // Insert a group
    let group_id = Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO groups (id, name, source) VALUES (?, 'Engineering', 'local')")
        .bind(&group_id)
        .execute(&pool)
        .await
        .unwrap();

    let output = build_dump_output(&pool).await.unwrap();
    assert_eq!(output["users"].as_array().unwrap().len(), 1);
    assert_eq!(output["users"][0]["email"], "alice@test.com");
    assert!(!output["users"][0]
        .as_object()
        .unwrap()
        .contains_key("password_hash"));
    assert_eq!(output["event_types"].as_array().unwrap().len(), 1);
    assert_eq!(output["event_types"][0]["title"], "Intro Call");
    assert_eq!(output["teams"].as_array().unwrap().len(), 1);
    assert_eq!(output["groups"].as_array().unwrap().len(), 1);

    // A disabled user is still configuration — it should appear, flagged disabled
    let disabled_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO users (id, email, name, password_hash, role, auth_provider, enabled) \
         VALUES (?, 'bob@test.com', 'Bob', 'hash', 'user', 'local', 0)",
    )
    .bind(&disabled_id)
    .execute(&pool)
    .await
    .unwrap();

    let output = build_dump_output(&pool).await.unwrap();
    let users = output["users"].as_array().unwrap();
    assert_eq!(users.len(), 2, "disabled user should appear in the dump");
    let bob = users
        .iter()
        .find(|u| u["email"] == "bob@test.com")
        .expect("bob should be in the dump");
    assert!(!bob["enabled"].as_bool().unwrap());
}

#[tokio::test]
async fn config_dump_caldav_no_secrets() {
    let pool = setup_db().await;

    let user_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO users (id, email, name, role, auth_provider, enabled) \
         VALUES (?, 'test@test.com', 'Test', 'user', 'local', 1)",
    )
    .bind(&user_id)
    .execute(&pool)
    .await
    .unwrap();
    let account_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO accounts (id, name, email, user_id) VALUES (?, 'Test', 'test@test.com', ?)",
    )
    .bind(&account_id)
    .bind(&user_id)
    .execute(&pool)
    .await
    .unwrap();
    let source_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO caldav_sources (id, account_id, name, url, username, password_enc) \
         VALUES (?, ?, 'Test', 'https://caldav.test', 'user', 'secret-encrypted')",
    )
    .bind(&source_id)
    .bind(&account_id)
    .execute(&pool)
    .await
    .unwrap();

    let output = build_dump_output(&pool).await.unwrap();
    let sources = output["caldav_sources"].as_array().unwrap();
    assert_eq!(sources.len(), 1);
    let source = sources[0].as_object().unwrap();
    assert!(!source.contains_key("password_enc"));
    // Operational sync state is excluded too
    assert!(!source.contains_key("last_synced"));
    assert!(!source.contains_key("sync_token"));
}

#[tokio::test]
async fn config_dump_relational_sections() {
    let pool = setup_db().await;

    let user_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO users (id, email, name, role, auth_provider) \
         VALUES (?, 'host@test.com', 'Host', 'user', 'local')",
    )
    .bind(&user_id)
    .execute(&pool)
    .await
    .unwrap();
    let account_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO accounts (id, name, email, user_id) VALUES (?, 'Host', 'host@test.com', ?)",
    )
    .bind(&account_id)
    .bind(&user_id)
    .execute(&pool)
    .await
    .unwrap();
    let et_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO event_types (id, account_id, slug, title, duration_min) \
         VALUES (?, ?, 'demo', 'Demo', 45)",
    )
    .bind(&et_id)
    .bind(&account_id)
    .execute(&pool)
    .await
    .unwrap();

    // Weekly rule, date override, per-user hours, frequency limit
    sqlx::query(
        "INSERT INTO availability_rules (id, event_type_id, day_of_week, start_time, end_time) \
         VALUES (?, ?, 1, '09:00', '17:00')",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&et_id)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO availability_overrides (id, event_type_id, date, is_blocked) \
         VALUES (?, ?, '2026-12-25', 1)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&et_id)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO user_availability_rules (id, user_id, day_of_week, start_time, end_time) \
         VALUES (?, ?, 2, '10:00', '16:00')",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&user_id)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO booking_frequency_limits (id, event_type_id, max_bookings, period) \
         VALUES (?, ?, 3, 'day')",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&et_id)
    .execute(&pool)
    .await
    .unwrap();

    let output = build_dump_output(&pool).await.unwrap();
    assert_eq!(output["accounts"].as_array().unwrap().len(), 1);
    assert_eq!(output["availability_rules"].as_array().unwrap().len(), 1);
    assert_eq!(output["availability_rules"][0]["day_of_week"], 1);
    assert_eq!(
        output["availability_overrides"].as_array().unwrap().len(),
        1
    );
    assert!(output["availability_overrides"][0]["is_blocked"]
        .as_bool()
        .unwrap());
    assert_eq!(
        output["user_availability_rules"].as_array().unwrap().len(),
        1
    );
    assert_eq!(
        output["booking_frequency_limits"].as_array().unwrap().len(),
        1
    );
    assert_eq!(output["booking_frequency_limits"][0]["period"], "day");
}
