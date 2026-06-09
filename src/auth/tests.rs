use super::*;

// --- is_email_allowed ---

#[test]
fn email_allowed_no_restriction() {
    assert!(is_email_allowed("alice@anything.com", &None));
    assert!(is_email_allowed(
        "alice@anything.com",
        &Some("".to_string())
    ));
    assert!(is_email_allowed(
        "alice@anything.com",
        &Some("  ".to_string())
    ));
}

#[test]
fn email_allowed_single_domain() {
    let domains = Some("example.com".to_string());
    assert!(is_email_allowed("alice@example.com", &domains));
    assert!(!is_email_allowed("alice@other.com", &domains));
}

#[test]
fn email_allowed_multiple_domains() {
    let domains = Some("example.com, company.org".to_string());
    assert!(is_email_allowed("alice@example.com", &domains));
    assert!(is_email_allowed("bob@company.org", &domains));
    assert!(!is_email_allowed("eve@evil.com", &domains));
}

#[test]
fn email_allowed_case_insensitive() {
    let domains = Some("Example.COM".to_string());
    assert!(is_email_allowed("alice@example.com", &domains));
    assert!(is_email_allowed("alice@EXAMPLE.COM", &domains));
}

#[test]
fn email_allowed_no_at_sign() {
    let domains = Some("example.com".to_string());
    assert!(!is_email_allowed("invalid-email", &domains));
}

#[test]
fn email_allowed_subdomain_not_matched() {
    let domains = Some("example.com".to_string());
    assert!(!is_email_allowed("alice@sub.example.com", &domains));
}

// --- generate_group_slug ---

#[test]
fn slug_basic() {
    assert_eq!(generate_group_slug("Demo Team"), "demo-team");
}

#[test]
fn slug_with_slashes() {
    assert_eq!(
        generate_group_slug("engineering/backend"),
        "engineering-backend"
    );
}

#[test]
fn slug_collapses_dashes() {
    assert_eq!(generate_group_slug("a - - b"), "a-b");
}

#[test]
fn slug_trims_leading_trailing() {
    assert_eq!(generate_group_slug(" -hello- "), "hello");
}

#[test]
fn slug_special_chars() {
    // Unicode alphanumeric chars are kept, non-alphanumeric become dashes
    assert_eq!(generate_group_slug("café & más"), "café-más");
    assert_eq!(generate_group_slug("test!@#$%"), "test");
}

#[test]
fn slug_empty_returns_group() {
    assert_eq!(generate_group_slug(""), "group");
    assert_eq!(generate_group_slug("---"), "group");
    assert_eq!(generate_group_slug("///"), "group");
}

#[test]
fn slug_numeric() {
    assert_eq!(generate_group_slug("team42"), "team42");
}

// --- extract_groups_from_id_token ---

#[test]
fn extract_groups_valid_token() {
    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256"}"#);
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(r#"{"sub":"user1","groups":["engineering","/admins","devops"]}"#);
    let token = format!("{}.{}.fake-sig", header, payload);

    let groups = extract_groups_from_id_token(&token);
    assert_eq!(
        groups,
        Some(vec![
            "engineering".to_string(),
            "admins".to_string(),
            "devops".to_string(),
        ])
    );
}

#[test]
fn extract_groups_no_groups_claim() {
    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256"}"#);
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(r#"{"sub":"user1","email":"alice@test.com"}"#);
    let token = format!("{}.{}.fake-sig", header, payload);

    assert_eq!(extract_groups_from_id_token(&token), None);
}

#[test]
fn extract_groups_empty_groups() {
    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256"}"#);
    let payload =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"sub":"user1","groups":[]}"#);
    let token = format!("{}.{}.fake-sig", header, payload);

    assert_eq!(extract_groups_from_id_token(&token), None);
}

#[test]
fn extract_groups_invalid_token() {
    assert_eq!(extract_groups_from_id_token("not-a-jwt"), None);
    assert_eq!(extract_groups_from_id_token("a.b"), None);
    assert_eq!(extract_groups_from_id_token(""), None);
}

// --- hash_password / verify_password ---

#[test]
fn password_hash_roundtrip() {
    let password = "SecureP@ss123";
    let hash = hash_password(password).unwrap();
    assert!(verify_password(password, &hash));
    assert!(!verify_password("wrong-password", &hash));
}

#[test]
fn verify_password_invalid_hash() {
    assert!(!verify_password("anything", "not-a-valid-hash"));
    assert!(!verify_password("anything", ""));
}

#[test]
fn password_hashes_are_unique() {
    let h1 = hash_password("same-password").unwrap();
    let h2 = hash_password("same-password").unwrap();
    assert_ne!(h1, h2); // different salts
    assert!(verify_password("same-password", &h1));
    assert!(verify_password("same-password", &h2));
}

#[test]
fn hash_password_empty_string() {
    let hash = hash_password("").unwrap();
    assert!(verify_password("", &hash));
    assert!(!verify_password(" ", &hash));
}

#[test]
fn hash_password_unicode() {
    let password = "pässwörd-日本語-🔑";
    let hash = hash_password(password).unwrap();
    assert!(verify_password(password, &hash));
    assert!(!verify_password("pässwörd-日本語", &hash));
}

#[test]
fn hash_password_long_input() {
    let password = "a".repeat(1000);
    let hash = hash_password(&password).unwrap();
    assert!(verify_password(&password, &hash));
}

// --- generate_session_token ---

#[test]
fn session_tokens_are_64_hex_chars_and_unique() {
    let a = generate_session_token();
    let b = generate_session_token();
    assert_eq!(a.len(), 64, "32 bytes hex-encoded should be 64 chars");
    assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    assert_ne!(a, b, "two consecutive tokens must not collide");
}

// --- extract_claims_from_id_token (title) ---

#[test]
fn extract_claims_with_title() {
    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256"}"#);
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(r#"{"sub":"user1","title":"Senior Engineer","groups":["team-a"]}"#);
    let token = format!("{}.{}.fake-sig", header, payload);

    let claims = extract_claims_from_id_token(&token);
    assert_eq!(claims.title, Some("Senior Engineer".to_string()));
    assert_eq!(claims.groups, Some(vec!["team-a".to_string()]));
}

#[test]
fn extract_claims_no_title() {
    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256"}"#);
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(r#"{"sub":"user1","groups":["eng"]}"#);
    let token = format!("{}.{}.fake-sig", header, payload);

    let claims = extract_claims_from_id_token(&token);
    assert_eq!(claims.title, None);
    assert!(claims.groups.is_some());
}

#[test]
fn extract_claims_title_only() {
    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256"}"#);
    let payload =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"sub":"user1","title":"CTO"}"#);
    let token = format!("{}.{}.fake-sig", header, payload);

    let claims = extract_claims_from_id_token(&token);
    assert_eq!(claims.title, Some("CTO".to_string()));
    assert_eq!(claims.groups, None);
}

// ===== DB-backed integration tests =====

async fn setup_db() -> SqlitePool {
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

/// Helper: insert a user directly and return their id.
async fn insert_user(pool: &SqlitePool, email: &str, name: &str, role: &str) -> String {
    let id = uuid::Uuid::new_v4().to_string();
    let hash = hash_password("testpass123").unwrap();
    let username = generate_username(pool, email).await.unwrap();
    sqlx::query(
        "INSERT INTO users (id, email, name, timezone, password_hash, role, auth_provider, username)
         VALUES (?, ?, ?, 'UTC', ?, ?, 'local', ?)",
    )
    .bind(&id)
    .bind(email)
    .bind(name)
    .bind(&hash)
    .bind(role)
    .bind(&username)
    .execute(pool)
    .await
    .unwrap();
    id
}

// --- generate_username ---

#[tokio::test]
async fn generate_username_from_email() {
    let pool = setup_db().await;
    let username = generate_username(&pool, "alice@example.com").await.unwrap();
    assert_eq!(username, "alice");
}

#[tokio::test]
async fn generate_username_dots_become_dashes() {
    let pool = setup_db().await;
    let username = generate_username(&pool, "alice.smith@example.com")
        .await
        .unwrap();
    assert_eq!(username, "alice-smith");
}

#[tokio::test]
async fn generate_username_strips_special_chars() {
    let pool = setup_db().await;
    let username = generate_username(&pool, "al!ce+tag@example.com")
        .await
        .unwrap();
    assert_eq!(username, "alcetag");
}

#[tokio::test]
async fn generate_username_uppercase_lowered() {
    let pool = setup_db().await;
    let username = generate_username(&pool, "Alice.BOB@example.com")
        .await
        .unwrap();
    assert_eq!(username, "alice-bob");
}

#[tokio::test]
async fn generate_username_empty_local_part_fallback() {
    let pool = setup_db().await;
    let username = generate_username(&pool, "@example.com").await.unwrap();
    assert_eq!(username, "user");
}

#[tokio::test]
async fn generate_username_no_at_sign() {
    let pool = setup_db().await;
    let username = generate_username(&pool, "justname").await.unwrap();
    assert_eq!(username, "justname");
}

#[tokio::test]
async fn generate_username_collision_appends_suffix() {
    let pool = setup_db().await;
    // First user takes "alice"
    insert_user(&pool, "alice@one.com", "Alice One", "user").await;
    // Second user with same local part should get "alice-1"
    let username = generate_username(&pool, "alice@two.com").await.unwrap();
    assert_eq!(username, "alice-1");
}

#[tokio::test]
async fn generate_username_multiple_collisions() {
    let pool = setup_db().await;
    // Take "bob", "bob-1", "bob-2"
    insert_user(&pool, "bob@one.com", "Bob One", "user").await;
    // Manually insert bob-1 and bob-2
    let id2 = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO users (id, email, name, timezone, role, auth_provider, username)
         VALUES (?, 'bob2@x.com', 'Bob2', 'UTC', 'user', 'local', 'bob-1')",
    )
    .bind(&id2)
    .execute(&pool)
    .await
    .unwrap();
    let id3 = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO users (id, email, name, timezone, role, auth_provider, username)
         VALUES (?, 'bob3@x.com', 'Bob3', 'UTC', 'user', 'local', 'bob-2')",
    )
    .bind(&id3)
    .execute(&pool)
    .await
    .unwrap();

    let username = generate_username(&pool, "bob@new.com").await.unwrap();
    assert_eq!(username, "bob-3");
}

// --- create_session / validate_session ---

#[tokio::test]
async fn create_and_validate_session() {
    let pool = setup_db().await;
    let user_id = insert_user(&pool, "sess@test.com", "Session User", "user").await;

    let session = create_session(&pool, &user_id).await.unwrap();
    assert!(!session.id.is_empty());
    assert_eq!(session.user_id, user_id);

    // Validate returns the user
    let user = validate_session(&pool, &session.id).await;
    assert!(user.is_some());
    let user = user.unwrap();
    assert_eq!(user.id, user_id);
    assert_eq!(user.email, "sess@test.com");
}

#[tokio::test]
async fn validate_session_invalid_token() {
    let pool = setup_db().await;
    let user = validate_session(&pool, "nonexistent-token").await;
    assert!(user.is_none());
}

#[tokio::test]
async fn validate_session_expired() {
    let pool = setup_db().await;
    let user_id = insert_user(&pool, "expired@test.com", "Expired User", "user").await;

    // Manually insert an expired session
    let token = "expired-session-token";
    sqlx::query("INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)")
        .bind(token)
        .bind(&user_id)
        .bind("2020-01-01T00:00:00") // far in the past
        .execute(&pool)
        .await
        .unwrap();

    let user = validate_session(&pool, token).await;
    assert!(user.is_none());
}

#[tokio::test]
async fn validate_session_disabled_user() {
    let pool = setup_db().await;
    let user_id = insert_user(&pool, "disabled@test.com", "Disabled User", "user").await;

    let session = create_session(&pool, &user_id).await.unwrap();

    // Disable the user
    sqlx::query("UPDATE users SET enabled = 0 WHERE id = ?")
        .bind(&user_id)
        .execute(&pool)
        .await
        .unwrap();

    let user = validate_session(&pool, &session.id).await;
    assert!(user.is_none());
}

#[tokio::test]
async fn create_multiple_sessions_same_user() {
    let pool = setup_db().await;
    let user_id = insert_user(&pool, "multi@test.com", "Multi User", "user").await;

    let s1 = create_session(&pool, &user_id).await.unwrap();
    let s2 = create_session(&pool, &user_id).await.unwrap();
    assert_ne!(s1.id, s2.id);

    // Both sessions are valid
    assert!(validate_session(&pool, &s1.id).await.is_some());
    assert!(validate_session(&pool, &s2.id).await.is_some());
}

// --- delete_session ---

#[tokio::test]
async fn delete_session_invalidates_it() {
    let pool = setup_db().await;
    let user_id = insert_user(&pool, "del@test.com", "Del User", "user").await;

    let session = create_session(&pool, &user_id).await.unwrap();
    assert!(validate_session(&pool, &session.id).await.is_some());

    delete_session(&pool, &session.id).await.unwrap();
    assert!(validate_session(&pool, &session.id).await.is_none());
}

#[tokio::test]
async fn delete_session_nonexistent_is_ok() {
    let pool = setup_db().await;
    // Should not error
    delete_session(&pool, "does-not-exist").await.unwrap();
}

// --- cleanup_expired_sessions ---

#[tokio::test]
async fn cleanup_expired_sessions_removes_old() {
    let pool = setup_db().await;
    let user_id = insert_user(&pool, "cleanup@test.com", "Cleanup User", "user").await;

    // Insert one expired and one valid session
    sqlx::query("INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)")
        .bind("expired-1")
        .bind(&user_id)
        .bind("2020-01-01T00:00:00")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)")
        .bind("expired-2")
        .bind(&user_id)
        .bind("2021-06-15T12:00:00")
        .execute(&pool)
        .await
        .unwrap();

    let valid_session = create_session(&pool, &user_id).await.unwrap();

    let removed = cleanup_expired_sessions(&pool).await.unwrap();
    assert_eq!(removed, 2);

    // Valid session still works
    assert!(validate_session(&pool, &valid_session.id).await.is_some());
    // Expired ones are gone
    assert!(validate_session(&pool, "expired-1").await.is_none());
    assert!(validate_session(&pool, "expired-2").await.is_none());
}

#[tokio::test]
async fn cleanup_expired_sessions_none_expired() {
    let pool = setup_db().await;
    let user_id = insert_user(&pool, "fresh@test.com", "Fresh User", "user").await;
    let _session = create_session(&pool, &user_id).await.unwrap();

    let removed = cleanup_expired_sessions(&pool).await.unwrap();
    assert_eq!(removed, 0);
}

#[tokio::test]
async fn cleanup_expired_sessions_empty_table() {
    let pool = setup_db().await;
    let removed = cleanup_expired_sessions(&pool).await.unwrap();
    assert_eq!(removed, 0);
}

// --- get_user_by_id ---

#[tokio::test]
async fn get_user_by_id_found() {
    let pool = setup_db().await;
    let user_id = insert_user(&pool, "lookup@test.com", "Lookup User", "user").await;

    let user = get_user_by_id(&pool, &user_id).await;
    assert!(user.is_some());
    let user = user.unwrap();
    assert_eq!(user.email, "lookup@test.com");
    assert_eq!(user.name, "Lookup User");
    assert_eq!(user.role, "user");
}

#[tokio::test]
async fn get_user_by_id_not_found() {
    let pool = setup_db().await;
    let user = get_user_by_id(&pool, "nonexistent-id").await;
    assert!(user.is_none());
}

#[tokio::test]
async fn get_user_by_id_disabled_returns_none() {
    let pool = setup_db().await;
    let user_id = insert_user(&pool, "dis@test.com", "Dis User", "user").await;

    // Disable the user
    sqlx::query("UPDATE users SET enabled = 0 WHERE id = ?")
        .bind(&user_id)
        .execute(&pool)
        .await
        .unwrap();

    let user = get_user_by_id(&pool, &user_id).await;
    assert!(user.is_none());
}

// --- get_auth_config ---

#[tokio::test]
async fn get_auth_config_returns_singleton() {
    let pool = setup_db().await;
    let config = get_auth_config(&pool).await.unwrap();
    assert_eq!(config.id, "singleton");
    // Default values from migration
    assert!(config.registration_enabled);
    assert!(!config.oidc_enabled);
    assert!(config.allowed_email_domains.is_none());
}

#[tokio::test]
async fn get_auth_config_after_update() {
    let pool = setup_db().await;

    sqlx::query(
        "UPDATE auth_config SET registration_enabled = 0, allowed_email_domains = 'test.com' WHERE id = 'singleton'",
    )
    .execute(&pool)
    .await
    .unwrap();

    let config = get_auth_config(&pool).await.unwrap();
    assert!(!config.registration_enabled);
    assert_eq!(config.allowed_email_domains, Some("test.com".to_string()));
}

// --- sync_user_groups ---

#[tokio::test]
async fn sync_user_groups_creates_groups() {
    let pool = setup_db().await;
    let user_id = insert_user(&pool, "grp@test.com", "Group User", "user").await;

    sync_user_groups(
        &pool,
        &user_id,
        &["Engineering".to_string(), "DevOps".to_string()],
    )
    .await
    .unwrap();

    // Verify groups were created
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM groups WHERE source = 'oidc'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count.0, 2);

    // Verify memberships
    let memberships: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM user_groups WHERE user_id = ?")
        .bind(&user_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(memberships.0, 2);
}

#[tokio::test]
async fn sync_user_groups_replaces_memberships() {
    let pool = setup_db().await;
    let user_id = insert_user(&pool, "grp2@test.com", "Group User 2", "user").await;

    // Initial sync with two groups
    sync_user_groups(&pool, &user_id, &["TeamA".to_string(), "TeamB".to_string()])
        .await
        .unwrap();

    // Re-sync with different groups
    sync_user_groups(&pool, &user_id, &["TeamC".to_string()])
        .await
        .unwrap();

    // Should have only one membership now
    let memberships: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM user_groups WHERE user_id = ?")
        .bind(&user_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(memberships.0, 1);

    // All three groups should still exist (groups are not deleted)
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM groups WHERE source = 'oidc'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count.0, 3);
}

#[tokio::test]
async fn sync_user_groups_empty_clears_memberships() {
    let pool = setup_db().await;
    let user_id = insert_user(&pool, "grp3@test.com", "Group User 3", "user").await;

    sync_user_groups(&pool, &user_id, &["TeamX".to_string()])
        .await
        .unwrap();

    // Sync with empty groups
    sync_user_groups(&pool, &user_id, &[]).await.unwrap();

    let memberships: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM user_groups WHERE user_id = ?")
        .bind(&user_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(memberships.0, 0);
}

// --- find_or_create_oidc_user: email_verified gate (OIDC takeover defense) ---

async fn auth_config_with_oidc(pool: &SqlitePool, auto_register: bool) -> AuthConfig {
    let mut c = get_auth_config(pool).await.unwrap();
    c.oidc_enabled = true;
    c.oidc_auto_register = auto_register;
    c
}

#[tokio::test]
async fn oidc_link_requires_email_verified() {
    // Takeover scenario: a local user "admin@company.com" exists. An
    // attacker registers at the IdP with the same email but the IdP
    // doesn't assert email_verified. Before the fix, calrs would link the
    // attacker's oidc_subject to the admin account. With the fix, the
    // link is refused.
    let pool = setup_db().await;
    let victim_id = insert_user(&pool, "admin@company.com", "Admin", "admin").await;
    let cfg = auth_config_with_oidc(&pool, false).await;

    let err = find_or_create_oidc_user(
        &pool,
        "attacker-sub-123",
        "admin@company.com",
        false, // email_verified=false — the attack vector
        "Attacker",
        &cfg,
    )
    .await
    .expect_err("must refuse to link when email is unverified");
    assert!(
        err.to_string().contains("verified"),
        "error should mention verification, got: {}",
        err
    );

    // The victim's user row must be unchanged: no oidc_subject written,
    // auth_provider still 'local'.
    let (provider, oidc_subject): (String, Option<String>) =
        sqlx::query_as("SELECT auth_provider, oidc_subject FROM users WHERE id = ?")
            .bind(&victim_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(provider, "local", "auth_provider must not change");
    assert!(oidc_subject.is_none(), "oidc_subject must remain NULL");
}

#[tokio::test]
async fn oidc_link_succeeds_when_email_verified() {
    // Legitimate flow: same email match, but the IdP asserts
    // email_verified=true, so we trust it and link.
    let pool = setup_db().await;
    let user_id = insert_user(&pool, "alice@company.com", "Alice", "user").await;
    let cfg = auth_config_with_oidc(&pool, false).await;

    let result = find_or_create_oidc_user(
        &pool,
        "alice-sub-123",
        "alice@company.com",
        true,
        "Alice",
        &cfg,
    )
    .await
    .expect("verified email must link");
    assert_eq!(result, user_id);

    let (provider, oidc_subject): (String, Option<String>) =
        sqlx::query_as("SELECT auth_provider, oidc_subject FROM users WHERE id = ?")
            .bind(&user_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(provider, "oidc");
    assert_eq!(oidc_subject.as_deref(), Some("alice-sub-123"));
}

#[tokio::test]
async fn oidc_auto_register_requires_email_verified() {
    // Squatting scenario: auto-register is on. Attacker signs in with a
    // fresh subject and an email they don't own. Before the fix, calrs
    // would create a new local account keyed on that email, polluting the
    // directory and potentially letting the attacker intercept anything
    // addressed to that email inside calrs. With the fix, refused.
    let pool = setup_db().await;
    let cfg = auth_config_with_oidc(&pool, true).await;

    let err = find_or_create_oidc_user(
        &pool,
        "attacker-sub",
        "victim@company.com",
        false,
        "Attacker",
        &cfg,
    )
    .await
    .expect_err("auto-register must refuse unverified email");
    assert!(err.to_string().to_lowercase().contains("verified"));

    // No user row created.
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
async fn oidc_auto_register_creates_user_when_email_verified() {
    let pool = setup_db().await;
    let cfg = auth_config_with_oidc(&pool, true).await;

    let user_id = find_or_create_oidc_user(
        &pool,
        "fresh-sub-001",
        "newuser@company.com",
        true,
        "New User",
        &cfg,
    )
    .await
    .expect("verified + auto_register must create");

    let (provider, oidc_subject, email): (String, Option<String>, String) =
        sqlx::query_as("SELECT auth_provider, oidc_subject, email FROM users WHERE id = ?")
            .bind(&user_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(provider, "oidc");
    assert_eq!(oidc_subject.as_deref(), Some("fresh-sub-001"));
    assert_eq!(email, "newuser@company.com");
}

#[tokio::test]
async fn oidc_returning_user_bypasses_email_verified_gate() {
    // Once a user is linked (identified by oidc_subject), subsequent
    // logins always work — the subject claim is the IdP's stable
    // identifier. Whether the IdP re-asserts email_verified on each
    // login is not our concern at that point; we've already trusted
    // the subject.
    let pool = setup_db().await;
    // Seed: verified first login, auto_register=true so the account exists.
    let cfg = auth_config_with_oidc(&pool, true).await;
    let id_first = find_or_create_oidc_user(
        &pool,
        "stable-sub-001",
        "user@company.com",
        true,
        "User",
        &cfg,
    )
    .await
    .expect("initial verified sign-in succeeds");

    // Second login: same subject, but IdP has stopped asserting
    // email_verified. Must still succeed via step 1 (oidc_subject match).
    let id_second = find_or_create_oidc_user(
        &pool,
        "stable-sub-001",
        "user@company.com",
        false,
        "User",
        &cfg,
    )
    .await
    .expect("returning user with existing oidc_subject must always work");
    assert_eq!(id_first, id_second);
}

#[tokio::test]
async fn oidc_no_auto_register_without_match_fails() {
    // Baseline: no existing user, auto_register=false. Unrelated to
    // verification — the pre-fix message path. Confirming we didn't
    // accidentally change this.
    let pool = setup_db().await;
    let cfg = auth_config_with_oidc(&pool, false).await;

    let err = find_or_create_oidc_user(&pool, "sub", "nope@company.com", true, "Nobody", &cfg)
        .await
        .expect_err("no user + auto_register=false must error");
    assert!(
        err.to_string().to_lowercase().contains("no account"),
        "expected 'no account' in: {}",
        err
    );
}

#[tokio::test]
async fn oidc_first_auto_registered_user_gets_admin_role() {
    // Pins the inline-CASE behavior: when auto-register creates the very
    // first user via OIDC, that user gets the admin role atomically.
    let pool = setup_db().await;
    let cfg = auth_config_with_oidc(&pool, true).await;

    let user_id =
        find_or_create_oidc_user(&pool, "sub-1", "first@company.com", true, "First", &cfg)
            .await
            .unwrap();

    let role: String = sqlx::query_scalar("SELECT role FROM users WHERE id = ?")
        .bind(&user_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(role, "admin");
}

#[tokio::test]
async fn oidc_subsequent_auto_registered_user_gets_user_role() {
    // With users already in the DB, OIDC auto-register must produce a
    // plain 'user' (the admin slot is already taken).
    let pool = setup_db().await;
    insert_user(&pool, "existing@company.com", "Existing", "admin").await;
    let cfg = auth_config_with_oidc(&pool, true).await;

    let user_id =
        find_or_create_oidc_user(&pool, "sub-2", "second@company.com", true, "Second", &cfg)
            .await
            .unwrap();

    let role: String = sqlx::query_scalar("SELECT role FROM users WHERE id = ?")
        .bind(&user_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(role, "user");
}

// --- delete_user ---

/// Insert a user + linked account and return (user_id, account_id).
async fn insert_user_with_account(
    pool: &SqlitePool,
    email: &str,
    name: &str,
    role: &str,
) -> (String, String) {
    let user_id = insert_user(pool, email, name, role).await;
    let account_id = uuid::Uuid::new_v4().to_string();
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
    (user_id, account_id)
}

#[tokio::test]
async fn delete_user_not_found() {
    let pool = setup_db().await;
    let result = delete_user(&pool, "nonexistent-id", None, None).await;
    assert!(matches!(result, Err(DeleteUserError::NotFound)));
}

#[tokio::test]
async fn delete_user_blocks_self_delete() {
    let pool = setup_db().await;
    let (uid, _) = insert_user_with_account(&pool, "alice@x.com", "Alice", "admin").await;
    // Add a second admin so the LastAdmin check doesn't trigger first.
    insert_user_with_account(&pool, "bob@x.com", "Bob", "admin").await;

    let result = delete_user(&pool, &uid, Some(&uid), None).await;
    assert!(matches!(result, Err(DeleteUserError::SelfDelete)));
}

#[tokio::test]
async fn delete_user_blocks_last_admin() {
    let pool = setup_db().await;
    let (uid, _) = insert_user_with_account(&pool, "alice@x.com", "Alice", "admin").await;
    // No other admin. Calling without a requester so SelfDelete doesn't
    // mask the LastAdmin check.
    let result = delete_user(&pool, &uid, None, None).await;
    assert!(matches!(result, Err(DeleteUserError::LastAdmin)));
}

#[tokio::test]
async fn delete_user_allows_demoted_last_admin_path() {
    // If you have two admins, deleting one is allowed.
    let pool = setup_db().await;
    let (alice_id, _) = insert_user_with_account(&pool, "alice@x.com", "Alice", "admin").await;
    let (bob_id, _) = insert_user_with_account(&pool, "bob@x.com", "Bob", "admin").await;

    delete_user(&pool, &bob_id, Some(&alice_id), None)
        .await
        .expect("two admins, delete one should succeed");

    let remaining: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(remaining.0, 1);
}

#[tokio::test]
async fn delete_user_blocks_with_future_bookings_as_host() {
    let pool = setup_db().await;
    let (alice_id, alice_account) =
        insert_user_with_account(&pool, "alice@x.com", "Alice", "admin").await;
    let (bob_id, bob_account) = insert_user_with_account(&pool, "bob@x.com", "Bob", "user").await;

    // Bob owns an event type with a confirmed future booking.
    let et_id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO event_types (id, account_id, slug, title, duration_min, buffer_before, buffer_after, min_notice_min, enabled, location_type)
         VALUES (?, ?, 'meet', 'Meet', 30, 0, 0, 0, 1, 'link')",
    )
    .bind(&et_id)
    .bind(&bob_account)
    .execute(&pool).await.unwrap();
    let booking_id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, cancel_token, reschedule_token, start_at, end_at, status)
         VALUES (?, ?, 'uid-future@x', 'Guest', 'g@x.com', 'UTC', ?, ?, datetime('now', '+7 days'), datetime('now', '+7 days', '+30 minutes'), 'confirmed')",
    )
    .bind(&booking_id)
    .bind(&et_id)
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(uuid::Uuid::new_v4().to_string())
    .execute(&pool).await.unwrap();

    let result = delete_user(&pool, &bob_id, Some(&alice_id), None).await;
    match result {
        Err(DeleteUserError::HasFutureBookings { count }) => assert_eq!(count, 1),
        other => panic!("expected HasFutureBookings(1), got {:?}", other),
    }

    // alice's untouched account
    let _ = alice_account;
}

#[tokio::test]
async fn delete_user_blocks_with_future_bookings_as_assignee() {
    // Bob is the round-robin assignee on a future booking under a team
    // event type that *alice* owns. The host_future query won't match
    // because alice owns the account; the assigned_future query is what
    // catches it. Locks in the second branch of the count.
    let pool = setup_db().await;
    let (alice_id, alice_account) =
        insert_user_with_account(&pool, "alice@x.com", "Alice", "admin").await;
    let (bob_id, _) = insert_user_with_account(&pool, "bob@x.com", "Bob", "user").await;

    // Alice owns the team event type.
    let et_id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO event_types (id, account_id, slug, title, duration_min, buffer_before, buffer_after, min_notice_min, enabled, location_type)
         VALUES (?, ?, 'team-meet', 'Team Meet', 30, 0, 0, 0, 1, 'link')",
    )
    .bind(&et_id)
    .bind(&alice_account)
    .execute(&pool).await.unwrap();
    // Future booking with bob as the assigned member.
    let booking_id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, cancel_token, reschedule_token, start_at, end_at, status, assigned_user_id)
         VALUES (?, ?, 'uid-assigned@x', 'Guest', 'g@x.com', 'UTC', ?, ?, datetime('now', '+7 days'), datetime('now', '+7 days', '+30 minutes'), 'confirmed', ?)",
    )
    .bind(&booking_id)
    .bind(&et_id)
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(&bob_id)
    .execute(&pool).await.unwrap();

    let result = delete_user(&pool, &bob_id, Some(&alice_id), None).await;
    match result {
        Err(DeleteUserError::HasFutureBookings { count }) => assert_eq!(count, 1),
        other => panic!("expected HasFutureBookings(1), got {:?}", other),
    }
}

#[tokio::test]
async fn delete_user_ignores_past_bookings() {
    let pool = setup_db().await;
    let (alice_id, _) = insert_user_with_account(&pool, "alice@x.com", "Alice", "admin").await;
    let (bob_id, bob_account) = insert_user_with_account(&pool, "bob@x.com", "Bob", "user").await;

    // Bob's event type has only a *past* booking; that should not block.
    let et_id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO event_types (id, account_id, slug, title, duration_min, buffer_before, buffer_after, min_notice_min, enabled, location_type)
         VALUES (?, ?, 'meet', 'Meet', 30, 0, 0, 0, 1, 'link')",
    )
    .bind(&et_id)
    .bind(&bob_account)
    .execute(&pool).await.unwrap();
    let booking_id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, cancel_token, reschedule_token, start_at, end_at, status)
         VALUES (?, ?, 'uid-past@x', 'Guest', 'g@x.com', 'UTC', ?, ?, datetime('now', '-7 days'), datetime('now', '-7 days', '+30 minutes'), 'confirmed')",
    )
    .bind(&booking_id)
    .bind(&et_id)
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(uuid::Uuid::new_v4().to_string())
    .execute(&pool).await.unwrap();

    delete_user(&pool, &bob_id, Some(&alice_id), None)
        .await
        .expect("past bookings must not block deletion");
}

#[tokio::test]
async fn delete_user_cascades_account_subtree_and_invites() {
    // The full happy path: a user with an account, an event type, a past
    // booking, an availability rule, AND an invite they authored on
    // *another* user's event type. After deletion: the user, their
    // account subtree, and their cross-owned invite are all gone, while
    // the other user's account and event type are untouched.
    let pool = setup_db().await;
    let (alice_id, alice_account) =
        insert_user_with_account(&pool, "alice@x.com", "Alice", "admin").await;
    let (bob_id, bob_account) = insert_user_with_account(&pool, "bob@x.com", "Bob", "user").await;

    // Bob's own event type with a past booking + an availability rule.
    let bob_et = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO event_types (id, account_id, slug, title, duration_min, buffer_before, buffer_after, min_notice_min, enabled, location_type)
         VALUES (?, ?, 'bob-meet', 'Bob Meet', 30, 0, 0, 0, 1, 'link')",
    )
    .bind(&bob_et)
    .bind(&bob_account)
    .execute(&pool).await.unwrap();
    sqlx::query(
        "INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, cancel_token, reschedule_token, start_at, end_at, status)
         VALUES (?, ?, 'uid-past@x', 'Guest', 'g@x.com', 'UTC', ?, ?, datetime('now', '-7 days'), datetime('now', '-7 days', '+30 minutes'), 'confirmed')",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(&bob_et)
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(uuid::Uuid::new_v4().to_string())
    .execute(&pool).await.unwrap();
    sqlx::query(
        "INSERT INTO availability_rules (id, event_type_id, day_of_week, start_time, end_time) VALUES (?, ?, 1, '09:00', '17:00')",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(&bob_et)
    .execute(&pool).await.unwrap();

    // Alice owns an internal event type that Bob created an invite on.
    let alice_et = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO event_types (id, account_id, slug, title, duration_min, buffer_before, buffer_after, min_notice_min, enabled, location_type, visibility)
         VALUES (?, ?, 'alice-meet', 'Alice Meet', 30, 0, 0, 0, 1, 'link', 'internal')",
    )
    .bind(&alice_et)
    .bind(&alice_account)
    .execute(&pool).await.unwrap();
    sqlx::query(
        "INSERT INTO booking_invites (id, event_type_id, token, guest_name, guest_email, max_uses, used_count, created_by_user_id)
         VALUES (?, ?, 'tok-xyz', '', '', 1, 0, ?)",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(&alice_et)
    .bind(&bob_id)
    .execute(&pool).await.unwrap();

    delete_user(&pool, &bob_id, Some(&alice_id), None)
        .await
        .expect("delete must succeed");

    // Bob and his account/event_types/bookings are gone.
    let bob_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE id = ?")
        .bind(&bob_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(bob_count.0, 0, "user row should be deleted");
    let bob_account_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM accounts WHERE user_id IS ?")
            .bind(&bob_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(bob_account_count.0, 0, "account should be deleted");
    let bob_et_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM event_types WHERE id = ?")
        .bind(&bob_et)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(bob_et_count.0, 0, "bob's event type should cascade-delete");

    // Bob's invite on alice's event type is gone, but alice's event type stays.
    let invite_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM booking_invites WHERE token = 'tok-xyz'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(invite_count.0, 0, "bob-authored invite should be deleted");
    let alice_et_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM event_types WHERE id = ?")
        .bind(&alice_et)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(alice_et_count.0, 1, "alice's event type must be untouched");

    // Alice still exists.
    let alice_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE id = ?")
        .bind(&alice_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(alice_count.0, 1);
}
