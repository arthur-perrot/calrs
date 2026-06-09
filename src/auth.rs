use anyhow::{Context, Result};
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use axum::extract::{Form, FromRequestParts, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum_extra::extract::CookieJar;
use base64::Engine;
use chrono::{Duration, Utc};
use rand::rngs::OsRng;
use rand::RngCore;
use sqlx::SqlitePool;
use std::sync::Arc;

use crate::models::{AuthConfig, Session, User};
use crate::web::{csrf_cookie_value, generate_csrf_token, verify_csrf_token, AppState};

// `__Host-` prefix forces browsers to enforce: Secure flag, Path=/, no Domain
// attribute. This prevents cookies from being overwritten by a sibling
// subdomain or downgraded over plaintext HTTP.
const SESSION_COOKIE: &str = "__Host-calrs_session";
const IMPERSONATE_COOKIE: &str = "__Host-calrs_impersonate";
const SESSION_DURATION_DAYS: i64 = 30;

// --- Password hashing ---

pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("Failed to hash password: {}", e))?;
    Ok(hash.to_string())
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    let parsed = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

// Pre-computed Argon2id hash used as a timing dummy when no user is found,
// preventing user enumeration via response-time differences.
const DUMMY_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

// --- Session management ---

fn generate_session_token() -> String {
    // Use OsRng (kernel CSPRNG) directly rather than thread_rng (userspace
    // ChaCha12). 30-day session tokens warrant the strongest entropy source.
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

pub async fn create_session(pool: &SqlitePool, user_id: &str) -> Result<Session> {
    let id = generate_session_token();
    let expires_at = (Utc::now() + Duration::days(SESSION_DURATION_DAYS))
        .format("%Y-%m-%dT%H:%M:%S")
        .to_string();

    sqlx::query("INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)")
        .bind(&id)
        .bind(user_id)
        .bind(&expires_at)
        .execute(pool)
        .await
        .context("Failed to create session")?;

    Ok(Session {
        id,
        user_id: user_id.to_string(),
        expires_at,
        created_at: Utc::now().format("%Y-%m-%dT%H:%M:%S").to_string(),
    })
}

pub async fn validate_session(pool: &SqlitePool, token: &str) -> Option<User> {
    let now = Utc::now().format("%Y-%m-%dT%H:%M:%S").to_string();
    sqlx::query_as::<_, User>(
        "SELECT u.* FROM users u
         JOIN sessions s ON s.user_id = u.id
         WHERE s.id = ? AND s.expires_at > ? AND u.enabled = 1",
    )
    .bind(token)
    .bind(&now)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
}

pub async fn get_user_by_id(pool: &SqlitePool, user_id: &str) -> Option<User> {
    sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = ? AND enabled = 1")
        .bind(user_id)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
}

pub async fn delete_session(pool: &SqlitePool, token: &str) -> Result<()> {
    sqlx::query("DELETE FROM sessions WHERE id = ?")
        .bind(token)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn cleanup_expired_sessions(pool: &SqlitePool) -> Result<u64> {
    let now = Utc::now().format("%Y-%m-%dT%H:%M:%S").to_string();
    let result = sqlx::query("DELETE FROM sessions WHERE expires_at <= ?")
        .bind(&now)
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

// --- User deletion ---

/// Reasons `delete_user` can refuse or fail. The web layer and CLI both
/// match on this to render a user-facing message.
#[derive(Debug)]
pub enum DeleteUserError {
    NotFound,
    LastAdmin,
    SelfDelete,
    HasFutureBookings { count: i64 },
    Db(sqlx::Error),
}

impl std::fmt::Display for DeleteUserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "user not found"),
            Self::LastAdmin => write!(
                f,
                "cannot delete the last admin (promote another user first)"
            ),
            Self::SelfDelete => {
                write!(f, "admins cannot delete themselves; ask another admin")
            }
            Self::HasFutureBookings { count } => write!(
                f,
                "user has {} upcoming booking(s) (as host or assigned member); cancel them before deletion",
                count
            ),
            Self::Db(e) => write!(f, "database error: {}", e),
        }
    }
}

impl std::error::Error for DeleteUserError {}

impl From<sqlx::Error> for DeleteUserError {
    fn from(e: sqlx::Error) -> Self {
        Self::Db(e)
    }
}

/// Delete a user and all data uniquely owned by them.
///
/// Refuses if: target is the last admin, target is the requester,
/// or the target has upcoming confirmed/pending bookings (as the
/// owning host or as an assigned member of a team event).
///
/// Walks the cascade chain explicitly because `accounts.user_id` is
/// `ON DELETE SET NULL`, not CASCADE — a naive `DELETE FROM users`
/// would orphan the user's accounts (and everything under them) and
/// would also fail the `booking_invites.created_by_user_id` foreign
/// key for any invites this user authored on other users' event types.
///
/// `requester_user_id` should be the id of the admin performing the
/// deletion (used for the self-delete check). Pass `None` to skip
/// that check (e.g. for emergency CLI cleanup or test setup).
///
/// `avatars_dir` is the directory holding avatar files. The user's
/// avatar (if any) is removed best-effort after the DB transaction
/// commits. Pass `None` to skip the filesystem cleanup.
pub async fn delete_user(
    pool: &SqlitePool,
    target_user_id: &str,
    requester_user_id: Option<&str>,
    avatars_dir: Option<&std::path::Path>,
) -> std::result::Result<(), DeleteUserError> {
    let target: Option<(String, Option<String>)> =
        sqlx::query_as("SELECT role, avatar_path FROM users WHERE id = ?")
            .bind(target_user_id)
            .fetch_optional(pool)
            .await?;
    let (target_role, avatar_filename) = match target {
        Some(t) => t,
        None => return Err(DeleteUserError::NotFound),
    };

    if let Some(req) = requester_user_id {
        if req == target_user_id {
            return Err(DeleteUserError::SelfDelete);
        }
    }

    if target_role == "admin" {
        let admin_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE role = 'admin'")
            .fetch_one(pool)
            .await?;
        if admin_count.0 <= 1 {
            return Err(DeleteUserError::LastAdmin);
        }
    }

    // Future bookings as host (own event_types) or as a round-robin assignee
    // on a team event. Both block deletion to keep guests from showing up to
    // a meeting whose host no longer exists.
    //
    // These counts run outside the deletion transaction, so a booking landing
    // between the count and the commit would be silently destroyed. Acceptable
    // for a manual admin action: the window is sub-second and the action is
    // intentional. If this is ever called from automation, switch to
    // `pool.begin()` with `BEGIN IMMEDIATE` and move the counts inside the
    // transaction so the SELECTs serialize against concurrent booking inserts.
    let host_future: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM bookings b
         JOIN event_types et ON et.id = b.event_type_id
         JOIN accounts a ON a.id = et.account_id
         WHERE a.user_id = ?
           AND b.status IN ('confirmed', 'pending')
           AND b.start_at > datetime('now')",
    )
    .bind(target_user_id)
    .fetch_one(pool)
    .await?;
    let assigned_future: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM bookings
         WHERE assigned_user_id = ?
           AND status IN ('confirmed', 'pending')
           AND start_at > datetime('now')",
    )
    .bind(target_user_id)
    .fetch_one(pool)
    .await?;
    let total_future = host_future.0 + assigned_future.0;
    if total_future > 0 {
        return Err(DeleteUserError::HasFutureBookings {
            count: total_future,
        });
    }

    let mut tx = pool.begin().await?;

    // Bookings for event types under this user's accounts must go first:
    // `bookings.event_type_id` has no ON DELETE action (a pre-existing schema
    // quirk in migration 001), so the cascade from accounts → event_types
    // would otherwise be blocked. Deleting bookings cascades booking_attendees
    // and booking_claim_tokens.
    sqlx::query(
        "DELETE FROM bookings WHERE event_type_id IN (
            SELECT et.id FROM event_types et
            JOIN accounts a ON a.id = et.account_id
            WHERE a.user_id = ?)",
    )
    .bind(target_user_id)
    .execute(&mut *tx)
    .await?;

    // Invites this user authored on event types owned by *other* users. The
    // `booking_invites.created_by_user_id` FK has no ON DELETE action either,
    // so the user delete would fail without this. Invites on the user's *own*
    // event types are mopped up by the cascade from `event_types`.
    sqlx::query("DELETE FROM booking_invites WHERE created_by_user_id = ?")
        .bind(target_user_id)
        .execute(&mut *tx)
        .await?;

    // Accounts cascade-delete their event_types, caldav_sources, calendars,
    // events, smtp_config, and (transitively) any availability rules,
    // overrides, attendees, claim tokens, member weights, frequency limits,
    // and watcher rows attached to those event types.
    sqlx::query("DELETE FROM accounts WHERE user_id = ?")
        .bind(target_user_id)
        .execute(&mut *tx)
        .await?;

    // The user delete cascades sessions, team_members, user_availability_rules,
    // event_type_member_weights, and booking_claim_tokens. teams.created_by
    // and the bookings.assigned/claimed_by_user_id columns are SET NULL.
    sqlx::query("DELETE FROM users WHERE id = ?")
        .bind(target_user_id)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    if let (Some(dir), Some(filename)) = (avatars_dir, avatar_filename) {
        let path = dir.join(&filename);
        let _ = tokio::fs::remove_file(&path).await;
    }

    Ok(())
}

// --- Auth config helpers ---

// Uses SELECT * intentionally: oidc_client_secret is encrypted at rest (AES-256-GCM)
// and encrypted in memory. Accidental serialization is prevented by #[serde(skip)]
// on the AuthConfig.oidc_client_secret field.
pub async fn get_auth_config(pool: &SqlitePool) -> Result<AuthConfig> {
    let config =
        sqlx::query_as::<_, AuthConfig>("SELECT * FROM auth_config WHERE id = 'singleton'")
            .fetch_one(pool)
            .await
            .context("Failed to load auth config")?;
    Ok(config)
}

pub fn is_email_allowed(email: &str, allowed_domains: &Option<String>) -> bool {
    let domains = match allowed_domains {
        Some(d) if !d.trim().is_empty() => d,
        _ => return true, // No restriction
    };

    let email_domain = match email.rsplit_once('@') {
        Some((_, domain)) => domain.to_lowercase(),
        None => return false,
    };

    domains
        .split(',')
        .map(|d| d.trim().to_lowercase())
        .any(|d| d == email_domain)
}

/// Generate a unique username from an email address.
pub async fn generate_username(pool: &SqlitePool, email: &str) -> Result<String> {
    let local_part = email.split('@').next().unwrap_or("user");
    let base: String = local_part
        .to_lowercase()
        .replace('.', "-")
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-')
        .collect();
    let base = if base.is_empty() {
        "user".to_string()
    } else {
        base
    };

    let mut candidate = base.clone();
    let mut suffix = 1u32;
    loop {
        let taken: Option<(String,)> = sqlx::query_as("SELECT id FROM users WHERE username = ?")
            .bind(&candidate)
            .fetch_optional(pool)
            .await?;
        if taken.is_none() {
            break;
        }
        candidate = format!("{}-{}", base, suffix);
        suffix += 1;
    }
    Ok(candidate)
}

/// Insert a local-auth user, computing the admin/user role atomically inside
/// the INSERT to avoid the read-then-write race where two concurrent
/// registrations on a fresh DB both observe an empty users table and both
/// claim admin. When `force_admin` is true the user is admin regardless
/// (used by `calrs user create --admin`); otherwise the user is admin only
/// if no other users exist. Returns the role the database assigned.
pub(crate) async fn create_local_user(
    pool: &SqlitePool,
    user_id: &str,
    email: &str,
    name: &str,
    password_hash: &str,
    username: &str,
    force_admin: bool,
) -> Result<String> {
    sqlx::query_scalar(
        "INSERT INTO users (id, email, name, timezone, password_hash, role, auth_provider, username)
         VALUES (?, ?, ?, 'UTC', ?,
                 CASE WHEN ? OR NOT EXISTS (SELECT 1 FROM users) THEN 'admin' ELSE 'user' END,
                 'local', ?)
         RETURNING role",
    )
    .bind(user_id)
    .bind(email)
    .bind(name)
    .bind(password_hash)
    .bind(force_admin)
    .bind(username)
    .fetch_one(pool)
    .await
    .context("failed to insert user")
}

include!("auth/extractors.rs");
include!("auth/handlers.rs");
include!("auth/oidc.rs");
// --- Helpers ---

fn render_login_error(state: &AppState, error: &str) -> Response {
    // Best-effort: try to show OIDC button even on error page
    let oidc_enabled = false; // Can't async here easily; login errors are local-auth only anyway
    let csrf_token = generate_csrf_token();
    let tmpl = match state.templates.get_template("auth/login.html") {
        Ok(t) => t,
        Err(_) => return Html(error.to_string()).into_response(),
    };
    let body = Html(
        tmpl.render(minijinja::context! { error => error, oidc_enabled => oidc_enabled, csrf_token => csrf_token })
            .unwrap_or_else(|_| error.to_string()),
    );
    ([("Set-Cookie", csrf_cookie_value(&csrf_token))], body).into_response()
}

fn render_register_error(state: &AppState, error: &str, auth_config: &AuthConfig) -> Response {
    let csrf_token = generate_csrf_token();
    let tmpl = match state.templates.get_template("auth/register.html") {
        Ok(t) => t,
        Err(_) => return Html(error.to_string()).into_response(),
    };
    let body = Html(
        tmpl.render(minijinja::context! {
            error => error,
            allowed_domains => auth_config.allowed_email_domains,
            csrf_token => csrf_token,
        })
        .unwrap_or_else(|_| error.to_string()),
    );
    ([("Set-Cookie", csrf_cookie_value(&csrf_token))], body).into_response()
}

include!("auth/group_sync.rs");

#[cfg(test)]
mod tests;
