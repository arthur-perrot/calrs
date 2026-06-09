pub mod captcha;
pub mod meeting;

use crate::utils::{convert_event_to_tz, parse_ical_datetime};
use axum::extract::{Form, Multipart, Path, Query, State};
use axum::http::HeaderMap;
use axum::response::Redirect;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use chrono::{
    Datelike, Duration, Local, NaiveDate, NaiveDateTime, NaiveTime, Offset, TimeZone, Timelike, Utc,
};
use chrono_tz::{OffsetName, Tz};
use minijinja::{context, Environment};
use serde::Deserialize;
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tokio::sync::Mutex;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;

/// Simple per-IP rate limiter for login attempts.
/// Tracks (attempt_count, window_start) per IP.
pub struct RateLimiter {
    state: Mutex<RateLimiterState>,
    max_attempts: u32,
    window: std::time::Duration,
}

struct RateLimiterState {
    attempts: HashMap<String, (u32, std::time::Instant)>,
    last_sweep: std::time::Instant,
}

impl RateLimiter {
    pub fn new(max_attempts: u32, window_secs: u64) -> Self {
        Self {
            state: Mutex::new(RateLimiterState {
                attempts: HashMap::new(),
                last_sweep: std::time::Instant::now(),
            }),
            max_attempts,
            window: std::time::Duration::from_secs(window_secs),
        }
    }

    /// Returns true if the request should be rejected (rate limited).
    pub async fn check_limited(&self, key: &str) -> bool {
        let mut state = self.state.lock().await;
        let now = std::time::Instant::now();

        // Evict entries whose window has elapsed. Bounded by "at most once per
        // window" so the work is amortized; without this the HashMap would
        // grow without bound under traffic from many distinct IPs.
        if now.duration_since(state.last_sweep) >= self.window {
            let window = self.window;
            state
                .attempts
                .retain(|_, (_, start)| now.duration_since(*start) <= window);
            state.last_sweep = now;
        }

        if let Some((count, start)) = state.attempts.get_mut(key) {
            if now.duration_since(*start) > self.window {
                // Window expired, reset
                *count = 1;
                *start = now;
                false
            } else if *count >= self.max_attempts {
                true
            } else {
                *count += 1;
                false
            }
        } else {
            state.attempts.insert(key.to_string(), (1, now));
            false
        }
    }
}

pub struct AppState {
    pub pool: SqlitePool,
    pub templates: Environment<'static>,
    pub login_limiter: RateLimiter,
    pub booking_limiter: RateLimiter,
    pub data_dir: PathBuf,
    pub secret_key: [u8; 32],
    pub theme_css: tokio::sync::RwLock<String>,
    pub company_link: tokio::sync::RwLock<Option<String>>,
    pub captcha_config: tokio::sync::RwLock<Option<captcha::CaptchaConfig>>,
    /// Org-wide meeting provider config (Jitsi + webhook). Cached so guest
    /// slot/booking pages don't hit `auth_config` on every render. Rebuilt
    /// when the admin saves changes.
    pub meeting_config: tokio::sync::RwLock<meeting::MeetingConfig>,
    /// CSP for booking form pages: relaxed with captcha origins when captcha
    /// is enabled, identical to `csp_baseline` otherwise. Rebuilt on admin save.
    pub csp: tokio::sync::RwLock<String>,
    /// Strict baseline CSP served on every non-booking page regardless of
    /// captcha configuration.
    pub csp_baseline: String,
}

// --- CSRF protection (double-submit cookie pattern) ---

/// Generate a random CSRF token using UUID v4.
pub fn generate_csrf_token() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Cookie name for the CSRF token. The `__Host-` prefix forces the browser to
/// enforce Secure, Path=/, and no Domain, so the token cannot be overwritten
/// by a sibling subdomain.
pub const CSRF_COOKIE_NAME: &str = "__Host-calrs_csrf";

/// Build the Set-Cookie header value for a CSRF token.
///
/// `HttpOnly` is intentionally omitted, the double-submit pattern needs the
/// client JS in `base.html` to read the cookie and inject it into the form.
/// `Secure` is set so the token never leaks over plaintext HTTP; modern
/// browsers still honour `Secure` cookies on localhost for dev over HTTP.
///
/// `cross_site=true` switches the cookie to `SameSite=None` so the booking
/// page can read it from inside a third-party iframe (the embed flow). The
/// double-submit token-vs-cookie comparison still defends against CSRF — we
/// never relied on SameSite for that. Browsers blocking all third-party
/// cookies (Safari ITP, Chrome with 3P cookies disabled) still won't deliver
/// it; that's an upstream-platform limitation outside our control.
pub fn csrf_cookie_value(token: &str) -> String {
    csrf_cookie_value_for(token, false)
}

pub fn csrf_cookie_value_for(token: &str, cross_site: bool) -> String {
    let same_site = if cross_site { "None" } else { "Lax" };
    // In the cross-site (embed) case also mark the cookie `Partitioned` (CHIPS).
    // Browsers that block unpartitioned third-party cookies (Safari 18.4+,
    // Firefox 131+, Chrome with 3P cookies disabled) will then still deliver it
    // inside the embed iframe, so the double-submit CSRF check keeps working.
    // `Partitioned` requires `Secure` + `Path=/`, both already set, and is
    // compatible with the `__Host-` prefix.
    let partitioned = if cross_site { "; Partitioned" } else { "" };
    format!(
        "{}={}; Path=/; Secure; SameSite={}; Max-Age=86400{}",
        CSRF_COOKIE_NAME, token, same_site, partitioned
    )
}

/// Extract the CSRF cookie value from request headers.
pub fn csrf_token_from_headers(headers: &HeaderMap) -> Option<String> {
    let prefix = format!("{}=", CSRF_COOKIE_NAME);
    headers
        .get_all(axum::http::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(';'))
        .find_map(|part| {
            let part = part.trim();
            part.strip_prefix(&prefix).map(|v| v.to_string())
        })
}

/// Verify that the CSRF form field matches the cookie value.
///
/// The two tokens are compared with `subtle::ConstantTimeEq` to avoid leaking
/// any partial-match timing information that could otherwise be used to
/// recover a valid token byte by byte.
#[allow(clippy::result_large_err)]
pub fn verify_csrf_token(
    headers: &HeaderMap,
    form_token: &Option<String>,
) -> Result<(), axum::response::Response> {
    let cookie_token = csrf_token_from_headers(headers);
    let valid = match (cookie_token.as_deref(), form_token.as_deref()) {
        (Some(cookie), Some(form)) if !cookie.is_empty() => {
            bool::from(cookie.as_bytes().ct_eq(form.as_bytes()))
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err((
            axum::http::StatusCode::FORBIDDEN,
            Html("403 Forbidden: CSRF token mismatch".to_string()),
        )
            .into_response())
    }
}

// --- Error sanitization helpers ---
//
// Internal errors (template render failures, DB errors, OIDC token-exchange
// errors) used to be `format!`'d straight into the HTTP response body. The
// detail leaks internal layout (template paths, schema hints, IdP URLs and
// occasionally token contents) to anyone who can trigger the path. These
// helpers funnel the detail to the structured log instead and return a
// generic message to the user.

/// Internal-error response (500). Use for any server-side failure on a path
/// where the user cannot fix the cause themselves.
pub(crate) fn internal_error_response<E: std::fmt::Display + ?Sized>(
    context: &str,
    error: &E,
) -> Response {
    tracing::error!(error = %error, context = %context, "internal error");
    (
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        Html("An internal error occurred. Please try again.".to_string()),
    )
        .into_response()
}

/// Same as `internal_error_response` but yields `Html<String>` so it can be
/// returned from helper functions whose signature is `Html<String>` (these
/// are then themselves wrapped via `.into_response()` at the call site).
pub(crate) fn internal_error_html<E: std::fmt::Display + ?Sized>(
    context: &str,
    error: &E,
) -> Html<String> {
    tracing::error!(error = %error, context = %context, "internal error");
    Html("An internal error occurred. Please try again.".to_string())
}

/// Same as `internal_error_response` but yields a plain `String` for sites
/// that compose the response inline, e.g. as a fallback template body via
/// `unwrap_or_else`.
pub(crate) fn internal_error_body<E: std::fmt::Display + ?Sized>(
    context: &str,
    error: &E,
) -> String {
    tracing::error!(error = %error, context = %context, "internal error");
    "An internal error occurred. Please try again.".to_string()
}

/// OIDC-flow failure response. Rendered to the user when the auth handshake
/// breaks down (token exchange, ID token verification, configuration). The
/// underlying error from `openidconnect` can include the IdP's response
/// body, token endpoint URL, or token contents, so it never reaches the
/// client.
pub(crate) fn oidc_error_response<E: std::fmt::Display + ?Sized>(
    context: &str,
    error: &E,
) -> Response {
    tracing::error!(error = %error, context = %context, "oidc auth failure");
    (
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        Html("Authentication failed. Please try again or contact your administrator.".to_string()),
    )
        .into_response()
}

/// Extract the client IP for rate-limiting from request headers.
///
/// Trust model: assumes calrs runs behind a single reverse proxy (the
/// documented Caddy/Nginx setup) that appends the observed peer address
/// to `X-Forwarded-For`. Each proxy in the chain appends, so the
/// rightmost value is the most-recent trusted hop's view of its peer,
/// and everything to its left is attacker-controlled. Taking the
/// rightmost value defeats the "set X-Forwarded-For: random.ip on every
/// request" rate-limit bypass.
///
/// `X-Real-IP` is intentionally not honoured: neither documented proxy
/// sets it by default, so a client-supplied `X-Real-IP` would pass
/// straight through and be trusted (worse than the bug this fixes).
///
/// Falls back to `"unknown"` if `X-Forwarded-For` is missing, which
/// collapses such requests into a single shared rate-limit bucket. That
/// is intentional: it throttles abuse rather than letting it through.
pub fn client_ip_for_rate_limit(headers: &HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.rsplit(',').next())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Form struct for POST endpoints that only need CSRF validation.
#[derive(Deserialize)]
struct CsrfForm {
    _csrf: Option<String>,
}

/// Query struct for CSRF validation on multipart endpoints.
#[derive(Deserialize)]
struct CsrfQuery {
    _csrf: Option<String>,
}

#[derive(Deserialize)]
struct CompanyLinkForm {
    company_link: String,
    _csrf: Option<String>,
}

/// Whether a `company_link` URL is safe to render as a clickable anchor.
/// Only `http://` and `https://` schemes are accepted; this rejects
/// `javascript:`, `data:`, `vbscript:`, `file:` etc., any of which would
/// turn the admin-controlled link on every public page into a stored XSS
/// or local-file vector.
pub(crate) fn is_safe_company_link(url: &str) -> bool {
    let lower = url.trim().to_ascii_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://")
}

async fn get_company_link(pool: &SqlitePool) -> Option<String> {
    sqlx::query_scalar::<_, Option<String>>(
        "SELECT company_link FROM auth_config WHERE id = 'singleton'",
    )
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
    .flatten()
    .filter(|s| !s.is_empty())
    // Defense in depth: even if a bad value reached the DB (legacy data,
    // manual edit), refuse to render anything but http(s). The admin
    // update handler is the primary gate; this is the backstop.
    .filter(|s| is_safe_company_link(s))
}

/// Read the org-wide display labels for the Jitsi / webhook providers from
/// the cached `MeetingConfig`. Returns empty strings when no display name is
/// configured — slot/book templates fall back to the generic "Video call"
/// label in that case.
async fn meeting_provider_labels(state: &AppState) -> (String, String) {
    let cfg = state.meeting_config.read().await;
    let jitsi = cfg
        .jitsi
        .as_ref()
        .and_then(|j| j.display_name.clone())
        .unwrap_or_default();
    let webhook = cfg
        .webhook
        .as_ref()
        .and_then(|w| w.display_name.clone())
        .unwrap_or_default();
    (jitsi, webhook)
}

/// Pick the location URL to expose on a freshly-created booking.
///
/// When the event type uses an auto provider (`jitsi_auto`, `webhook_auto`)
/// **and** the booking is going straight to confirmed, we generate a fresh
/// URL via `meeting::generate_and_persist` and store it on the booking row.
/// Otherwise we fall back to the event type's static `location_value`. The
/// returned value is what gets piped into the email + ICS + CalDAV write.
///
/// For pending bookings, generation is deferred to the approval moment
/// (`approve_booking_by_token`) so a host who declines never invokes a
/// configured webhook.
async fn resolve_booking_location(
    state: &AppState,
    booking_id: &str,
    event_type_id: &str,
    host_user_id: Option<&str>,
    static_location_value: Option<&str>,
    guest_name: &str,
    guest_email: &str,
    confirmed: bool,
) -> Option<String> {
    if confirmed {
        if let Some(generated) = meeting::generate_and_persist(
            &state.pool,
            &state.secret_key,
            booking_id,
            event_type_id,
            host_user_id,
            guest_name,
            guest_email,
        )
        .await
        {
            return Some(generated);
        }
    }
    static_location_value
        .map(str::to_string)
        .filter(|s| !s.is_empty())
}

/// Background task that sends booking reminders on a 60-second tick. Also
/// piggybacks an hourly sweep of expired sessions so the `sessions` table
/// doesn't accumulate dead rows indefinitely.
pub async fn run_reminder_loop(pool: SqlitePool, secret_key: [u8; 32]) {
    let mut last_session_cleanup = std::time::Instant::now();
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;

        // Hourly: prune sessions whose `expires_at` has passed.
        if last_session_cleanup.elapsed() >= std::time::Duration::from_secs(3600) {
            match crate::auth::cleanup_expired_sessions(&pool).await {
                Ok(removed) if removed > 0 => {
                    tracing::info!(removed, "expired sessions pruned");
                }
                Ok(_) => {}
                Err(e) => tracing::warn!(error = %e, "session cleanup failed"),
            }
            last_session_cleanup = std::time::Instant::now();
        }

        // Find bookings that need a reminder:
        // - status is confirmed
        // - reminder not yet sent
        // - event type has reminder_minutes set (> 0)
        // - start_at minus reminder_minutes <= now
        // - start_at > now (don't remind for past bookings)
        // `host_timezone` resolves like `get_host_tz`: prefer the explicit
        // event-type tz, fall back to the host user's tz. NULL falls through
        // to UTC at parse time.
        let due: Vec<(String, String, String, String, String, String, String, String, String, Option<String>, Option<String>, String, Option<String>, Option<String>, Option<String>)> = sqlx::query_as(
            "SELECT b.id, b.guest_name, b.guest_email, b.guest_timezone, b.start_at, b.end_at, et.title, u.name, COALESCE(u.booking_email, u.email), COALESCE(NULLIF(b.meeting_url, ''), et.location_value), b.cancel_token, b.uid, b.language, u.language, COALESCE(NULLIF(et.timezone, ''), u.timezone)
             FROM bookings b
             JOIN event_types et ON et.id = b.event_type_id
             JOIN accounts a ON a.id = et.account_id
             JOIN users u ON u.id = a.user_id
             WHERE b.status = 'confirmed'
               AND b.reminder_sent_at IS NULL
               AND et.reminder_minutes IS NOT NULL
               AND et.reminder_minutes > 0
               AND datetime(b.start_at, '-' || et.reminder_minutes || ' minutes') <= datetime('now')
               AND datetime(b.start_at) > datetime('now')",
        )
        .fetch_all(&pool)
        .await
        .unwrap_or_default();

        let base_url = std::env::var("CALRS_BASE_URL").ok();

        if due.is_empty() {
            continue;
        }

        let smtp_config = match crate::email::load_smtp_config(&pool, &secret_key).await {
            Ok(Some(cfg)) => cfg,
            _ => continue,
        };

        for (
            bid,
            guest_name,
            guest_email,
            guest_timezone,
            start_at,
            end_at,
            event_title,
            host_name,
            host_email,
            location_value,
            cancel_token,
            uid,
            guest_language,
            host_language,
            host_timezone,
        ) in &due
        {
            // start_at/end_at are stored in the event-type tz (see #101). Convert
            // to the guest's tz so `BookingDetails` carries guest-local wall-clock —
            // matches the contract used by cancel/confirm handlers, and lets
            // `host_time_display` convert back into the host's tz correctly for
            // the host reminder.
            let stored_tz_str = host_timezone.as_deref().unwrap_or("UTC");
            let stored_tz = stored_tz_str.parse::<Tz>().unwrap_or(Tz::UTC);
            let guest_tz_parsed = guest_timezone.parse::<Tz>().unwrap_or(Tz::UTC);
            let (date, start_time, end_time) =
                booking_strings_in_guest_tz(start_at, end_at, stored_tz, guest_tz_parsed);

            let location = location_value.as_ref().filter(|v| !v.is_empty()).cloned();

            let details = crate::email::BookingDetails {
                event_title: event_title.clone(),
                date,
                start_time,
                end_time,
                guest_name: guest_name.clone(),
                guest_email: guest_email.clone(),
                guest_timezone: guest_timezone.clone(),
                host_name: host_name.clone(),
                host_email: host_email.clone(),
                uid: uid.clone(),
                notes: None,
                location,
                reminder_minutes: None,
                additional_attendees: vec![],
                guest_language: guest_language.clone(),
                host_language: host_language.clone(),
                host_timezone: stored_tz_str.to_string(),
            };

            let guest_cancel_url = cancel_token.as_ref().and_then(|t| {
                base_url
                    .as_ref()
                    .map(|base| format!("{}/booking/cancel/{}", base.trim_end_matches('/'), t))
            });

            let _ = crate::email::send_guest_reminder(
                &smtp_config,
                &details,
                guest_cancel_url.as_deref(),
            )
            .await;
            let _ = crate::email::send_host_reminder(&smtp_config, &details).await;

            // Mark reminder as sent
            let _ =
                sqlx::query("UPDATE bookings SET reminder_sent_at = datetime('now') WHERE id = ?")
                    .bind(bid)
                    .execute(&pool)
                    .await;

            tracing::info!(booking_id = %bid, "reminder sent");
        }

        // Background sync: pick the stalest enabled source and sync it.
        // With ctag + sync-token this is very cheap for unchanged calendars.
        let stalest: Option<(String,)> = sqlx::query_as(
            "SELECT cs.id
             FROM caldav_sources cs
             WHERE cs.enabled = 1
             ORDER BY COALESCE(cs.last_synced, '2000-01-01') ASC
             LIMIT 1",
        )
        .fetch_optional(&pool)
        .await
        .unwrap_or(None);

        if let Some((source_id,)) = stalest {
            crate::commands::sync::sync_source_by_id(&pool, &secret_key, &source_id).await;
            tracing::debug!(source_id = %source_id, "background sync completed");
        }
    }
}

/// Parse a datetime string from the database, handling both space and T separators.
/// Supports: "2025-03-15 14:30:00", "2025-03-15T14:30:00", "2025-03-15T14:30:00Z"
fn parse_booking_datetime(dt_str: &str) -> Option<NaiveDateTime> {
    let s = dt_str.trim_end_matches('Z');
    NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S")
        .or_else(|_| NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S"))
        .ok()
}

/// Format a booking datetime string into a human-friendly label.
/// Input: "2025-03-15 14:30:00" or "2025-03-15T14:30:00"
/// Output: "Tomorrow at 2:30 PM" or "Sat, Mar 15 at 2:30 PM" or "Sat, Mar 15, 2026 at 2:30 PM"
fn format_booking_datetime(dt_str: &str) -> String {
    let ndt = match parse_booking_datetime(dt_str) {
        Some(d) => d,
        None => return dt_str.to_string(),
    };
    let now = Local::now().naive_local();
    let today = now.date();
    let date = ndt.date();
    let time = ndt.time().format("%-I:%M %p").to_string();

    let day_diff = (date - today).num_days();
    let date_part = if day_diff == 0 {
        "Today".to_string()
    } else if day_diff == 1 {
        "Tomorrow".to_string()
    } else if day_diff < 7 {
        date.format("%A").to_string() // e.g. "Wednesday"
    } else if date.year() == today.year() {
        date.format("%a, %b %-d").to_string() // e.g. "Sat, Mar 15"
    } else {
        date.format("%a, %b %-d, %Y").to_string() // e.g. "Sat, Mar 15, 2026"
    };
    format!("{} at {}", date_part, time)
}

/// Format a time range for booking display.
/// Returns e.g. "Tomorrow at 2:30 PM — 3:00 PM"
fn format_booking_range(start_str: &str, end_str: &str) -> String {
    let start_label = format_booking_datetime(start_str);
    // For the end, only show the time (same day implied)
    if let Some(end_ndt) = parse_booking_datetime(end_str) {
        let end_time = end_ndt.time().format("%-I:%M %p").to_string();
        format!("{} — {}", start_label, end_time)
    } else {
        format!("{} — {}", start_label, end_str)
    }
}

/// Convert a naive datetime from one timezone to another, going via UTC. Used
/// when the dashboard needs to show a stored time (which is naive in the
/// event-type's timezone) in either the host's profile timezone or the guest's
/// selected timezone.
fn convert_naive_between_tz(naive: NaiveDateTime, from: Tz, to: Tz) -> NaiveDateTime {
    let utc = from
        .from_local_datetime(&naive)
        .earliest()
        .unwrap_or_else(|| from.from_utc_datetime(&naive))
        .with_timezone(&Utc);
    utc.with_timezone(&to).naive_local()
}

/// Convert stored booking start/end (naive in `stored_tz`) to the guest's
/// timezone and return (date, start_time, end_time) strings used to populate
/// `BookingDetails`. `email::generate_ics` calls `convert_to_utc(date,
/// start_time, end_time, guest_timezone)`, so these fields must be guest-local
/// for the ICS and the rendered email body to match what the guest booked.
/// Fixes #101.
fn booking_strings_in_guest_tz(
    start_at: &str,
    end_at: &str,
    stored_tz: Tz,
    guest_tz: Tz,
) -> (String, String, String) {
    match (
        parse_booking_datetime(start_at),
        parse_booking_datetime(end_at),
    ) {
        (Some(s), Some(e)) => {
            let gs = convert_naive_between_tz(s, stored_tz, guest_tz);
            let ge = convert_naive_between_tz(e, stored_tz, guest_tz);
            (
                gs.date().format("%Y-%m-%d").to_string(),
                gs.time().format("%H:%M").to_string(),
                ge.time().format("%H:%M").to_string(),
            )
        }
        _ => (
            start_at.get(..10).unwrap_or(start_at).to_string(),
            extract_time_24h(start_at),
            extract_time_24h(end_at),
        ),
    }
}

/// Short timezone label for display next to a time, e.g. "CEST" or "EST".
/// Falls back to the IANA name when the abbreviation is numeric (zones like
/// Asia/Tehran which expose "+0330" rather than a letter code).
fn tz_short_label(tz: Tz, at: NaiveDateTime) -> String {
    let dt = tz
        .from_local_datetime(&at)
        .earliest()
        .unwrap_or_else(|| tz.from_utc_datetime(&at));
    let abbr = dt.offset().abbreviation();
    if abbr.len() >= 3 && abbr.chars().all(|c| c.is_ascii_alphabetic()) {
        abbr.to_string()
    } else {
        tz.name().to_string()
    }
}

/// Format a booking range for dashboard display: returns a primary label in the
/// host's profile timezone (with tz suffix), and an optional secondary label
/// showing the guest's view when the two timezones differ.
///
/// `start_str`/`end_str` are naive datetimes stored in `stored_tz` (the event
/// type's timezone, falling back to the host's profile tz for legacy rows).
fn format_booking_for_dashboard(
    start_str: &str,
    end_str: &str,
    stored_tz: &str,
    host_tz: &str,
    guest_tz: &str,
) -> (String, Option<String>) {
    let stored = stored_tz.parse::<Tz>().unwrap_or(Tz::UTC);
    let host = host_tz.parse::<Tz>().unwrap_or(Tz::UTC);
    let guest = guest_tz.parse::<Tz>().unwrap_or(Tz::UTC);

    let (start, end) = match (
        parse_booking_datetime(start_str),
        parse_booking_datetime(end_str),
    ) {
        (Some(s), Some(e)) => (s, e),
        _ => return (format_booking_range(start_str, end_str), None),
    };

    let host_start = convert_naive_between_tz(start, stored, host);
    let host_end = convert_naive_between_tz(end, stored, host);
    let today_host = Utc::now().with_timezone(&host).date_naive();
    let primary = format_dashboard_range(
        host_start,
        host_end,
        today_host,
        &tz_short_label(host, host_start),
    );

    let secondary = if guest != host {
        let g_start = convert_naive_between_tz(start, stored, guest);
        let g_end = convert_naive_between_tz(end, stored, guest);
        let g_time_start = g_start.time().format("%-I:%M %p").to_string();
        let g_time_end = g_end.time().format("%-I:%M %p").to_string();
        Some(format!(
            "{} — {} {}",
            g_time_start,
            g_time_end,
            tz_short_label(guest, g_start)
        ))
    } else {
        None
    };

    (primary, secondary)
}

fn format_dashboard_range(
    start: NaiveDateTime,
    end: NaiveDateTime,
    today: NaiveDate,
    tz_label: &str,
) -> String {
    let date = start.date();
    let time_start = start.time().format("%-I:%M %p").to_string();
    let time_end = end.time().format("%-I:%M %p").to_string();
    let day_diff = (date - today).num_days();
    let date_part = if day_diff == 0 {
        "Today".to_string()
    } else if day_diff == 1 {
        "Tomorrow".to_string()
    } else if (1..7).contains(&day_diff) {
        date.format("%A").to_string()
    } else if date.year() == today.year() {
        date.format("%a, %b %-d").to_string()
    } else {
        date.format("%a, %b %-d, %Y").to_string()
    };
    format!(
        "{} at {} — {} {}",
        date_part, time_start, time_end, tz_label
    )
}

/// Format a raw date string (YYYY-MM-DD or from datetime) into a human-friendly
/// localized date label. Returns e.g. "Saturday, March 15, 2026" / "samedi 15 mars 2026".
fn format_date_label(dt_str: &str, lang: &str) -> String {
    // Try parsing as full datetime first, then as date-only
    if let Some(ndt) = parse_booking_datetime(dt_str) {
        return crate::i18n::format_long_date(ndt.date(), lang);
    }
    if let Ok(d) = NaiveDate::parse_from_str(&dt_str[..10.min(dt_str.len())], "%Y-%m-%d") {
        return crate::i18n::format_long_date(d, lang);
    }
    dt_str.to_string()
}

/// Extract a human-friendly time (e.g. "2:30 PM") from a datetime string.
fn format_time_from_dt(dt_str: &str) -> String {
    if let Some(ndt) = parse_booking_datetime(dt_str) {
        ndt.time().format("%-I:%M %p").to_string()
    } else if dt_str.len() >= 16 {
        dt_str[11..16].to_string()
    } else {
        "00:00".to_string()
    }
}

/// Extract HH:MM (24-hour) from a booking datetime for ICS generation.
/// format_time_from_dt returns 12-hour display format ("2:00 PM") which
/// convert_to_utc cannot parse. This function returns "14:00" format.
fn extract_time_24h(dt_str: &str) -> String {
    if let Some(ndt) = parse_booking_datetime(dt_str) {
        ndt.time().format("%H:%M").to_string()
    } else if dt_str.len() >= 16 {
        dt_str[11..16].to_string()
    } else {
        "00:00".to_string()
    }
}

/// Parse availability windows from the form.
/// Supports new `avail_windows` format ("09:00-12:00,13:00-17:00") with fallback to
/// legacy single `avail_start`/`avail_end` pair. Returns at least one window.
fn parse_avail_windows(
    windows_str: Option<&str>,
    legacy_start: Option<&str>,
    legacy_end: Option<&str>,
) -> Vec<(String, String)> {
    if let Some(ws) = windows_str.filter(|s| !s.trim().is_empty()) {
        let parsed: Vec<(String, String)> = ws
            .split(',')
            .filter_map(|w| {
                let parts: Vec<&str> = w.trim().splitn(2, '-').collect();
                if parts.len() == 2
                    && NaiveTime::parse_from_str(parts[0], "%H:%M").is_ok()
                    && NaiveTime::parse_from_str(parts[1], "%H:%M").is_ok()
                {
                    Some((parts[0].to_string(), parts[1].to_string()))
                } else {
                    None
                }
            })
            .collect();
        if !parsed.is_empty() {
            return parsed;
        }
    }
    // Fallback to legacy single window
    vec![(
        legacy_start.unwrap_or("09:00").to_string(),
        legacy_end.unwrap_or("17:00").to_string(),
    )]
}

/// Parse a single schedule string in the new format.
/// Format: "1:09:00-17:00;2:09:00-12:00,13:00-17:00" (day:windows;day:windows)
fn parse_schedule_string(s: &str) -> std::collections::BTreeMap<i32, Vec<(String, String)>> {
    let mut result = std::collections::BTreeMap::new();
    let s = s.trim();
    if s.is_empty() {
        return result;
    }
    for segment in s.split(';') {
        let segment = segment.trim();
        if segment.is_empty() {
            continue;
        }
        let parts: Vec<&str> = segment.splitn(2, ':').collect();
        if parts.len() != 2 {
            continue;
        }
        let day: i32 = match parts[0].trim().parse() {
            Ok(d) if (0..=6).contains(&d) => d,
            _ => continue,
        };
        let windows: Vec<(String, String)> = parts[1]
            .split(',')
            .filter_map(|w| {
                let times: Vec<&str> = w.trim().split('-').collect();
                if times.len() == 2 {
                    let s = times[0].trim().to_string();
                    let e = times[1].trim().to_string();
                    if !s.is_empty() && !e.is_empty() {
                        Some((s, e))
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();
        if !windows.is_empty() {
            result.insert(day, windows);
        }
    }
    result
}

/// Parse per-day availability schedule.
/// Resolution order: submitted `schedule` (new format) → `user_default` (new format,
/// e.g. the user's profile default availability) → legacy form fields → hardcoded
/// Mon–Fri 09:00–17:00. The `user_default` step is what stops an empty submission
/// from silently snapping back to the hardcoded default.
fn parse_avail_schedule(
    schedule: Option<&str>,
    legacy_days: Option<&str>,
    legacy_windows: Option<&str>,
    legacy_start: Option<&str>,
    legacy_end: Option<&str>,
    user_default: Option<&str>,
) -> std::collections::BTreeMap<i32, Vec<(String, String)>> {
    if let Some(s) = schedule {
        let parsed = parse_schedule_string(s);
        if !parsed.is_empty() {
            return parsed;
        }
    }

    if let Some(s) = user_default {
        let parsed = parse_schedule_string(s);
        if !parsed.is_empty() {
            return parsed;
        }
    }

    // Fall back to legacy format
    let mut result = std::collections::BTreeMap::new();
    let days_str = legacy_days.unwrap_or("1,2,3,4,5");
    let windows = parse_avail_windows(legacy_windows, legacy_start, legacy_end);
    for day_str in days_str.split(',') {
        if let Ok(day) = day_str.trim().parse::<i32>() {
            if (0..=6).contains(&day) {
                result.insert(day, windows.clone());
            }
        }
    }
    result
}

/// Build an avail_schedule string from availability rules.
/// Output format: "1:09:00-17:00;2:09:00-12:00,13:00-17:00"
fn build_avail_schedule(all_rules: &[(i32, String, String)]) -> String {
    let mut day_map: std::collections::BTreeMap<i32, Vec<String>> =
        std::collections::BTreeMap::new();
    for (day, start, end) in all_rules {
        day_map
            .entry(*day)
            .or_default()
            .push(format!("{}-{}", start, end));
    }
    day_map
        .iter()
        .map(|(day, ws)| format!("{}:{}", day, ws.join(",")))
        .collect::<Vec<_>>()
        .join(";")
}

/// Query parameters that the embed-code generator threads into the booking
/// flow. When `embed=1`, the booking pages drop their chrome (logo, footer,
/// theme toggle) and emit a postMessage on load so the parent iframe can
/// auto-size. The other fields are passed straight through to the templates
/// as visual hints. None of them are persisted server-side — the embed code
/// embeds them as URL params on every iframe load.
#[derive(Deserialize, Default, Clone, Debug)]
struct EmbedParams {
    #[serde(default)]
    embed: Option<String>,
    #[serde(default)]
    layout: Option<String>,
    #[serde(default)]
    theme: Option<String>,
    #[serde(default)]
    brand: Option<String>,
}

impl EmbedParams {
    fn is_embedded(&self) -> bool {
        matches!(self.embed.as_deref(), Some("1") | Some("true"))
    }

    /// Full set of accent CSS variable declarations derived from `brand`,
    /// suitable for inlining inside a `:root, html.dark { … }` rule. Returns
    /// None if `brand` is missing, empty, or not 3/6 hex digits — we never pass
    /// raw user input into CSS to avoid breaking out of the rule.
    ///
    /// Besides `--accent`/`--accent-hover` (the brand hex), we derive the rgba
    /// variants `--accent-subtle`/`--accent-border`/`--accent-muted` from the
    /// same color so slot pills, borders and muted states pick up the brand
    /// too — otherwise those would keep the org accent and render half-themed.
    fn brand_css(&self) -> Option<String> {
        let raw = self.brand.as_deref()?.trim_start_matches('#');
        let (r, g, b) = hex_to_rgb(raw)?;
        Some(format!(
            "--accent: #{hex}; --accent-hover: #{hex}; \
             --accent-subtle: rgba({r},{g},{b},0.12); \
             --accent-border: rgba({r},{g},{b},0.3); \
             --accent-muted: rgba({r},{g},{b},0.5);",
            hex = raw
        ))
    }

    /// "?embed=1&layout=month&theme=dark&brand=ff0000" — used to keep params
    /// alive across page transitions inside the iframe. Returns empty string
    /// when not embedded so callers can unconditionally append it.
    fn query_suffix(&self, leading_amp: bool) -> String {
        if !self.is_embedded() {
            return String::new();
        }
        let mut parts: Vec<String> = vec!["embed=1".to_string()];
        if let Some(v) = self.layout.as_deref().filter(|s| !s.is_empty()) {
            parts.push(format!("layout={}", urlencode_simple(v)));
        }
        if let Some(v) = self.theme.as_deref().filter(|s| !s.is_empty()) {
            parts.push(format!("theme={}", urlencode_simple(v)));
        }
        if let Some(v) = self.brand.as_deref().filter(|s| !s.is_empty()) {
            parts.push(format!("brand={}", urlencode_simple(v)));
        }
        let sep = if leading_amp { "&" } else { "?" };
        format!("{}{}", sep, parts.join("&"))
    }
}

/// Parse a 3- or 6-digit hex color (no leading '#') into (r, g, b) decimal
/// components. Returns None for any other length or non-hex input. A 3-digit
/// value is expanded by doubling each nibble (e.g. "f30" → ff3300).
fn hex_to_rgb(raw: &str) -> Option<(u8, u8, u8)> {
    let full = match raw.len() {
        3 if raw.chars().all(|c| c.is_ascii_hexdigit()) => {
            raw.chars().flat_map(|c| [c, c]).collect::<String>()
        }
        6 if raw.chars().all(|c| c.is_ascii_hexdigit()) => raw.to_string(),
        _ => return None,
    };
    let r = u8::from_str_radix(&full[0..2], 16).ok()?;
    let g = u8::from_str_radix(&full[2..4], 16).ok()?;
    let b = u8::from_str_radix(&full[4..6], 16).ok()?;
    Some((r, g, b))
}

/// Minimal URL-encoder for the small whitelist of values EmbedParams carries
/// (slug-like layout names, theme tokens, hex colors). Keeps the helper
/// dependency-free; if we ever accept richer values we can swap in `urlencoding`.
fn urlencode_simple(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

/// Wrap an HTML render in a response. When `embed=1`, override the global
/// `X-Frame-Options: SAMEORIGIN` so legacy browsers don't refuse the iframe.
/// The matching `frame-ancestors *` CSP override is added by `csp_middleware`
/// — that keeps the CSP composition (captcha allowances + embed framing) in
/// one place. Modern browsers honour CSP's frame-ancestors over the legacy
/// header per CSP Level 2.
fn html_response(body: String, embed: &EmbedParams) -> Response {
    let mut resp = Html(body).into_response();
    if embed.is_embedded() {
        // `ALLOWALL` is non-standard; modern browsers ignore it once CSP
        // frame-ancestors is set, but it prevents the global SAMEORIGIN
        // layer from re-asserting itself for browsers that don't speak CSP.
        resp.headers_mut().insert(
            axum::http::header::X_FRAME_OPTIONS,
            axum::http::HeaderValue::from_static("ALLOWALL"),
        );
    }
    resp
}

/// Middleware that ensures a CSRF cookie is set on every response.
///
/// When the request URL carries `embed=1`, the cookie is issued with
/// `SameSite=None; Secure` so the booking flow inside a third-party iframe
/// can read its own cookie. Outside the embed flow, the strict `SameSite=Lax`
/// default applies.
async fn csrf_cookie_middleware(
    headers: HeaderMap,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let cross_site_cookie =
        is_embedded_booking_request(request.uri().path(), request.uri().query());
    let mut response = next.run(request).await;

    // Only set cookie if not already present in the request
    if csrf_token_from_headers(&headers).is_none() {
        let token = generate_csrf_token();
        if let Ok(cookie_val) = csrf_cookie_value_for(&token, cross_site_cookie).parse() {
            response
                .headers_mut()
                .append(axum::http::header::SET_COOKIE, cookie_val);
        }
    }

    response
}

/// Detects the `embed=1` (or `embed=true`) query param without pulling in a
/// full URL parser. Tolerates extra params and arbitrary parameter order.
fn is_embed_request(query: Option<&str>) -> bool {
    let Some(q) = query else { return false };
    q.split('&').any(|pair| {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        k == "embed" && (v == "1" || v == "true")
    })
}

/// Public booking surfaces that may legitimately be loaded inside a
/// third-party iframe.
///
/// SECURITY: this gates BOTH the relaxed `frame-ancestors *` CSP swap and the
/// `SameSite=None` CSRF cookie. It must never match authenticated or sensitive
/// surfaces (`/auth/...`, `/dashboard/...`, asset routes), otherwise those
/// pages become frameable by any site — e.g. `/auth/login?embed=1` would be a
/// fully functional login form inside an attacker's iframe (clickjacking /
/// login CSRF). The embed=1 flag alone is NOT sufficient; the path must also
/// be a booking surface.
fn is_embeddable_path(path: &str) -> bool {
    // Modern user/team booking routes (allowlist).
    if path == "/u"
        || path.starts_with("/u/")
        || path == "/team"
        || path.starts_with("/team/")
        || path == "/g"
        || path.starts_with("/g/")
    {
        return true;
    }
    // Legacy single-user booking pages: only `/{slug}` and `/{slug}/book`.
    // Everything is a single top-level segment, so reject any path whose first
    // segment is a reserved (non-booking) route. New reserved top-level routes
    // must be added to RESERVED below to stay out of the embed surface.
    let trimmed = path.trim_start_matches('/');
    if trimmed.is_empty() {
        return false;
    }
    let mut segs = trimmed.split('/');
    let first = segs.next().unwrap_or("");
    let rest: Vec<&str> = segs.collect();
    let shape_ok = rest.is_empty() || (rest.len() == 1 && rest[0] == "book");
    if !shape_ok {
        return false;
    }
    const RESERVED: &[&str] = &[
        "auth",
        "dashboard",
        "avatar",
        "team-avatar",
        "logo",
        "accent.css",
        "brand-logo",
        "embed.js",
        "fonts",
        "t",
        "booking",
        "u",
        "team",
        "g",
    ];
    !RESERVED.contains(&first)
}

/// True when the request is both flagged `embed=1` and targets an embeddable
/// booking surface. This is the single gate for embed-mode behavior changes.
fn is_embedded_booking_request(path: &str, query: Option<&str>) -> bool {
    is_embed_request(query) && is_embeddable_path(path)
}

fn build_csp(captcha: &Option<captcha::CaptchaConfig>) -> String {
    let (wasm_eval, worker_src, script_extra, connect_extra) = match captcha.as_ref() {
        Some(c) => {
            let widget_origin = c.widget_script_origin();
            let instance_origin = c.instance_origin();
            (
                " 'wasm-unsafe-eval'",
                "worker-src blob:; ",
                format!(" {}", widget_origin),
                format!(" {} {}", instance_origin, widget_origin),
            )
        }
        None => ("", "", String::new(), String::new()),
    };
    format!(
        "default-src 'self'; img-src 'self' data:; \
         style-src 'self' 'unsafe-inline'; \
         script-src 'self' 'unsafe-inline'{}{}; \
         {}connect-src 'self'{}; \
         object-src 'none'; base-uri 'self'; frame-ancestors 'self'",
        wasm_eval, script_extra, worker_src, connect_extra
    )
}

/// Booking form pages (`…/book`) are the only pages that embed the captcha
/// widget, so they are the only ones that get the relaxed CSP when captcha is
/// enabled. Every other page keeps the strict baseline policy.
fn is_booking_form_path(path: &str) -> bool {
    path.ends_with("/book")
}

async fn csp_middleware(
    State(state): State<Arc<AppState>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let booking_page = is_booking_form_path(request.uri().path());
    let embed_mode = is_embedded_booking_request(request.uri().path(), request.uri().query());
    let mut response = next.run(request).await;
    if !response
        .headers()
        .contains_key(axum::http::header::CONTENT_SECURITY_POLICY)
    {
        let strict = if booking_page {
            state.csp.read().await.clone()
        } else {
            state.csp_baseline.clone()
        };
        // In embed mode, swap the default `frame-ancestors 'self'` for `*` so
        // the page can be loaded inside a third-party iframe. The replacement
        // is safe because `build_csp` is the sole producer of the strict CSP
        // string and always uses that exact directive.
        let csp = if embed_mode {
            strict.replace("frame-ancestors 'self'", "frame-ancestors *")
        } else {
            strict
        };
        if let Ok(val) = axum::http::HeaderValue::from_str(&csp) {
            response
                .headers_mut()
                .insert(axum::http::header::CONTENT_SECURITY_POLICY, val);
        }
    }
    response
}

pub async fn create_router(pool: SqlitePool, data_dir: PathBuf, secret_key: [u8; 32]) -> Router {
    let mut env = Environment::new();
    env.set_undefined_behavior(minijinja::UndefinedBehavior::Lenient);
    env.set_loader(minijinja::path_loader("templates"));
    crate::i18n::register(&mut env);

    let initial_theme_css = build_theme_css(&pool).await;
    let initial_company_link = get_company_link(&pool).await;
    let initial_captcha = captcha::load_captcha_config(&pool, &secret_key).await;
    let initial_meeting = meeting::load_config(&pool, &secret_key).await;
    let initial_csp = build_csp(&initial_captcha);

    let state = Arc::new(AppState {
        pool,
        templates: env,
        // 10 login attempts per IP per 15 minutes
        login_limiter: RateLimiter::new(10, 900),
        booking_limiter: RateLimiter::new(10, 300),
        secret_key,
        data_dir,
        theme_css: tokio::sync::RwLock::new(initial_theme_css),
        company_link: tokio::sync::RwLock::new(initial_company_link),
        captcha_config: tokio::sync::RwLock::new(initial_captcha),
        meeting_config: tokio::sync::RwLock::new(initial_meeting),
        csp: tokio::sync::RwLock::new(initial_csp),
        csp_baseline: build_csp(&None),
    });

    Router::new()
        .merge(crate::auth::auth_router())
        .route("/", get(root_redirect))
        .route("/dashboard", get(dashboard))
        .route("/dashboard/event-types", get(dashboard_event_types))
        .route(
            "/dashboard/availability/default",
            get(dashboard_availability_default),
        )
        .route("/dashboard/bookings", get(dashboard_bookings))
        .route("/dashboard/teams", get(dashboard_teams))
        .route(
            "/dashboard/teams/new",
            get(show_team_form).post(create_team),
        )
        .route("/dashboard/sources", get(dashboard_sources))
        .route("/dashboard/invite-links", get(dashboard_organization))
        .route(
            "/dashboard/organization",
            get(|| async { Redirect::permanent("/dashboard/invite-links") }),
        )
        .route("/dashboard/bookings/{id}/cancel", post(cancel_booking))
        .route("/dashboard/bookings/{id}/confirm", post(confirm_booking))
        .route(
            "/dashboard/event-types/new",
            get(new_event_type_form).post(create_event_type),
        )
        .route(
            "/dashboard/event-types/{slug}/edit",
            get(edit_event_type_form).post(update_event_type),
        )
        .route(
            "/dashboard/event-types/{slug}/priority/{user_id}",
            post(update_event_type_member_priority),
        )
        .route(
            "/dashboard/event-types/{slug}/toggle",
            post(toggle_event_type),
        )
        .route(
            "/dashboard/event-types/{slug}/delete",
            post(delete_event_type),
        )
        // Invite management
        .route(
            "/dashboard/invites/{event_type_id}",
            get(invite_management_page),
        )
        .route(
            "/dashboard/invites/{event_type_id}/send",
            post(send_invite_bulk),
        )
        .route("/dashboard/invites/{invite_id}/delete", post(delete_invite))
        .route(
            "/dashboard/invites/{event_type_id}/quick-link",
            post(generate_quick_link),
        )
        // Availability overrides
        .route(
            "/dashboard/event-types/{slug}/overrides",
            get(overrides_page).post(create_override),
        )
        .route(
            "/dashboard/event-types/{slug}/overrides/{override_id}/delete",
            post(delete_override),
        )
        // Embed code generator
        .route("/dashboard/event-types/{slug}/embed", get(embed_page))
        // Calendar source management
        .route(
            "/dashboard/sources/new",
            get(new_source_form).post(create_source),
        )
        .route(
            "/dashboard/sources/{id}/edit",
            get(edit_source_form).post(update_source),
        )
        .route("/dashboard/sources/{id}/remove", post(remove_source))
        .route("/dashboard/sources/{id}/test", post(test_source))
        .route("/dashboard/sources/google/connect", get(google_connect))
        .route("/dashboard/sources/google/callback", get(google_callback))
        .route("/dashboard/sources/{id}/sync", post(sync_source))
        .route(
            "/dashboard/sources/{id}/force-sync",
            post(force_sync_source),
        )
        .route(
            "/dashboard/sources/{id}/setup-write",
            get(setup_write_calendar),
        )
        .route(
            "/dashboard/sources/{id}/write-calendar",
            post(set_write_calendar),
        )
        // Settings & avatar
        .route(
            "/dashboard/settings",
            get(settings_page).post(settings_save),
        )
        .route("/dashboard/settings/timezone", post(update_timezone))
        .route("/dashboard/settings/avatar", post(upload_avatar))
        .route("/dashboard/settings/avatar/delete", post(delete_avatar))
        .route("/avatar/{user_id}", get(serve_avatar))
        // Team settings & avatar
        .route(
            "/dashboard/teams/{team_id}/settings",
            get(team_settings_page).post(team_settings_save),
        )
        .route(
            "/dashboard/teams/{team_id}/avatar",
            post(upload_team_avatar),
        )
        .route(
            "/dashboard/teams/{team_id}/avatar/delete",
            post(delete_team_avatar),
        )
        .route("/dashboard/teams/{team_id}/delete", post(delete_team))
        .route("/team-avatar/{team_id}", get(serve_team_avatar))
        // Troubleshoot
        .route("/dashboard/troubleshoot", get(troubleshoot))
        // Admin routes
        .route("/dashboard/admin", get(admin_dashboard))
        .route(
            "/dashboard/admin/users/{id}/toggle-role",
            post(admin_toggle_role),
        )
        .route(
            "/dashboard/admin/users/{id}/toggle-enabled",
            post(admin_toggle_enabled),
        )
        .route(
            "/dashboard/admin/users/{id}/delete",
            post(admin_delete_user),
        )
        .route("/dashboard/admin/auth", post(admin_update_auth))
        .route("/dashboard/admin/accent", post(admin_update_accent))
        .route("/dashboard/admin/oidc", post(admin_update_oidc))
        .route(
            "/dashboard/admin/google-oauth2",
            post(admin_update_google_oauth2),
        )
        .route("/dashboard/admin/captcha", post(admin_update_captcha))
        .route("/dashboard/admin/jitsi", post(admin_update_jitsi))
        .route(
            "/dashboard/admin/meeting-webhook",
            post(admin_update_meeting_webhook),
        )
        .route("/dashboard/admin/logo", post(admin_upload_logo))
        .route("/dashboard/admin/logo/delete", post(admin_delete_logo))
        .route(
            "/dashboard/admin/company-link",
            post(admin_update_company_link),
        )
        .route(
            "/dashboard/admin/groups/{group_id}/members/{user_id}/weight",
            post(admin_update_member_weight),
        )
        .route("/dashboard/admin/impersonate/{id}", post(admin_impersonate))
        .route(
            "/dashboard/admin/stop-impersonate",
            post(admin_stop_impersonate),
        )
        // Group event type management
        .route(
            "/dashboard/group-event-types/new",
            get(new_group_event_type_form).post(create_group_event_type),
        )
        // Team event type management. The `team_id` is in the path so the
        // server-side WHERE clause can scope unambiguously: two teams may
        // legitimately share the same slug (e.g. "intro"), and looking up by
        // slug alone returns whichever row the DB picks first.
        .route(
            "/dashboard/group-event-types/{team_id}/{slug}/edit",
            get(edit_group_event_type_form).post(update_group_event_type),
        )
        .route(
            "/dashboard/group-event-types/{team_id}/{slug}/priority/{user_id}",
            post(update_group_event_type_member_priority),
        )
        .route(
            "/dashboard/group-event-types/{team_id}/{slug}/toggle",
            post(toggle_group_event_type),
        )
        .route(
            "/dashboard/group-event-types/{team_id}/{slug}/delete",
            post(delete_group_event_type),
        )
        .route(
            "/dashboard/group-event-types/{team_id}/{slug}/embed",
            get(group_embed_page),
        )
        // Serve logo and fonts
        .route("/logo", get(serve_logo))
        .route("/accent.css", get(serve_accent_css))
        .route("/brand-logo", get(serve_brand_logo))
        .route("/embed.js", get(serve_embed_js))
        .route("/fonts/inter-latin.woff2", get(serve_font_inter_latin))
        .route(
            "/fonts/inter-latin-ext.woff2",
            get(serve_font_inter_latin_ext),
        )
        // Group public routes
        .route("/team/{team_slug}", get(team_profile_page))
        .route("/team/{team_slug}/{slug}", get(show_group_slots))
        .route(
            "/team/{team_slug}/{slug}/book",
            get(show_group_book_form).post(handle_group_booking),
        )
        // Legacy /g/ redirects
        .route("/g/{team_slug}", get(redirect_g_to_team))
        .route("/g/{team_slug}/{slug}", get(redirect_g_to_team_slug))
        .route(
            "/g/{team_slug}/{slug}/book",
            get(redirect_g_to_team_slug_book),
        )
        // Legacy team link redirects → unified teams
        .route("/t/{token}", get(redirect_team_link_to_team))
        .route("/t/{token}/book", get(redirect_team_link_to_team))
        // User-scoped public booking routes
        .route(
            "/booking/claim/{booking_id}",
            get(claim_booking_form).post(claim_booking),
        )
        .route(
            "/booking/approve/{token}",
            get(approve_booking_form).post(approve_booking_by_token),
        )
        .route(
            "/booking/decline/{token}",
            get(decline_booking_form).post(decline_booking_by_token),
        )
        .route(
            "/booking/cancel/{token}",
            get(guest_cancel_form).post(guest_cancel_booking),
        )
        .route(
            "/booking/reschedule/{token}",
            get(guest_reschedule_slots).post(guest_reschedule_booking),
        )
        .route(
            "/dashboard/bookings/{id}/reschedule",
            get(host_reschedule_slots).post(host_reschedule_booking),
        )
        .route("/u/{username}", get(user_profile))
        .route("/u/{username}/{slug}", get(show_slots_for_user))
        .route(
            "/u/{username}/{slug}/book",
            get(show_book_form_for_user).post(handle_booking_for_user),
        )
        // Legacy single-user routes (kept for backward compatibility)
        .route("/{slug}", get(show_slots))
        .route("/{slug}/book", get(show_book_form).post(handle_booking))
        .layer(TraceLayer::new_for_http())
        .layer(axum::middleware::from_fn(csrf_cookie_middleware))
        // Defensive HTTP headers on every response (incl. error pages).
        //
        // CSP allows `'unsafe-inline'` for scripts and styles because the
        // templates rely on inline `<script>` blocks (CSRF auto-injection,
        // theme toggle, time-zone banner) and inline `style="..."` attributes.
        // Tightening this would require nonces wired through every render
        // site or a sweep across templates to externalize inline blocks.
        //
        // The CSP itself is set by `csp_middleware`: booking form pages
        // (`…/book`) get the captcha-relaxed policy when captcha is enabled,
        // everything else always gets the strict baseline.
        .layer(SetResponseHeaderLayer::if_not_present(
            axum::http::header::X_FRAME_OPTIONS,
            axum::http::HeaderValue::from_static("SAMEORIGIN"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            axum::http::header::X_CONTENT_TYPE_OPTIONS,
            axum::http::HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            axum::http::header::REFERRER_POLICY,
            axum::http::HeaderValue::from_static("strict-origin-when-cross-origin"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            axum::http::HeaderName::from_static("permissions-policy"),
            axum::http::HeaderValue::from_static(
                "geolocation=(), microphone=(), camera=(), payment=(), usb=()",
            ),
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            csp_middleware,
        ))
        .with_state(state)
}

/// Helper: create impersonation template context values (active, target_name, admin_name).
fn impersonation_ctx(auth_user: &crate::auth::AuthUser) -> (bool, String, String) {
    match &auth_user.impersonation {
        Some(info) => (true, info.target_name.clone(), info.admin_name.clone()),
        None => (false, String::new(), String::new()),
    }
}

/// Compute two-letter Matrix-style initials from a name (first letter of first + last word).
fn compute_initials(name: &str) -> String {
    let parts: Vec<&str> = name.split_whitespace().collect();
    let mut initials = String::new();
    if let Some(first) = parts.first() {
        if let Some(c) = first.chars().next() {
            initials.extend(c.to_uppercase());
        }
    }
    if parts.len() > 1 {
        if let Some(last) = parts.last() {
            if let Some(c) = last.chars().next() {
                initials.extend(c.to_uppercase());
            }
        }
    }
    if initials.is_empty() {
        "?".to_string()
    } else {
        initials
    }
}

/// Build OIDC groups context with member details for stacked avatars.
async fn build_groups_ctx(
    pool: &sqlx::SqlitePool,
    oidc_groups: &[(String, String, i64)],
    linked_set: &std::collections::HashSet<String>,
) -> Vec<minijinja::Value> {
    let mut out = Vec::new();
    for (id, name, member_count) in oidc_groups {
        let group_members: Vec<(String, String, Option<String>)> = sqlx::query_as(
            "SELECT u.id, u.name, u.avatar_path FROM users u \
             JOIN user_groups ug ON ug.user_id = u.id \
             WHERE ug.group_id = ? AND u.enabled = 1 ORDER BY u.name LIMIT 8",
        )
        .bind(id)
        .fetch_all(pool)
        .await
        .unwrap_or_default();
        let members_ctx: Vec<minijinja::Value> = group_members
            .iter()
            .map(|(uid, uname, ap)| {
                context! {
                    id => uid,
                    name => uname,
                    has_avatar => ap.is_some(),
                    initials => compute_initials(uname),
                }
            })
            .collect();
        out.push(context! {
            id => id,
            name => name,
            member_count => member_count,
            members => members_ctx,
            linked => linked_set.contains(id),
        });
    }
    out
}

/// Build sidebar context for dashboard templates.
fn sidebar_context(auth_user: &crate::auth::AuthUser, active: &str) -> minijinja::Value {
    let user = &auth_user.user;
    let (impersonating, _, _) = impersonation_ctx(auth_user);
    let effective_role = if impersonating {
        "admin".to_string()
    } else {
        user.role.clone()
    };
    context! {
        user_name => user.name,
        user_title => user.title.as_deref().unwrap_or(""),
        user_id => user.id,
        user_role => effective_role,
        user_timezone => user.timezone,
        has_avatar => user.avatar_path.is_some(),
        user_initials => compute_initials(&user.name),
        active => active,
        version => env!("CARGO_PKG_VERSION"),
    }
}

include!("dashboard.rs");
include!("event_types.rs");
include!("group_booking.rs");
include!("public_booking.rs");
// --- Troubleshoot ---

#[derive(Deserialize)]
struct TroubleshootQuery {
    date: Option<String>,
    event_type: Option<String>,
}

async fn troubleshoot(
    State(state): State<Arc<AppState>>,
    auth_user: crate::auth::AuthUser,
    Query(params): Query<TroubleshootQuery>,
) -> impl IntoResponse {
    let user = &auth_user.user;

    // Always sync before troubleshooting to ensure fresh data
    crate::commands::sync::sync_if_stale(&state.pool, &state.secret_key, &user.id).await;

    let host_tz = get_user_tz(&state.pool, &user.id).await;
    let now_host = Utc::now().with_timezone(&host_tz).naive_local();

    let target_date = params
        .date
        .as_deref()
        .and_then(|d| NaiveDate::parse_from_str(d, "%Y-%m-%d").ok())
        .unwrap_or(now_host.date());

    // Fetch user's event types for the selector
    let event_types: Vec<(String, String, i32, i32, i32, i32)> = sqlx::query_as(
        "SELECT et.slug, et.title, et.duration_min, et.buffer_before, et.buffer_after, et.min_notice_min
         FROM event_types et
         JOIN accounts a ON a.id = et.account_id
         WHERE a.user_id = ? AND et.team_id IS NULL AND et.enabled = 1
         ORDER BY et.created_at",
    )
    .bind(&user.id)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    if event_types.is_empty() {
        let tmpl = match state.templates.get_template("troubleshoot.html") {
            Ok(t) => t,
            Err(e) => return internal_error_html("template render", &e),
        };
        let (impersonating, impersonating_name, _) = impersonation_ctx(&auth_user);
        return Html(
            tmpl.render(context! {
                user_name => &user.name,
                no_event_types => true,
                sidebar => sidebar_context(&auth_user, "troubleshoot"),
                impersonating => impersonating,
                impersonating_name => impersonating_name,
            })
            .unwrap_or_default(),
        );
    }

    let selected_slug = params.event_type.as_deref().unwrap_or(&event_types[0].0);
    let selected_et = event_types
        .iter()
        .find(|et| et.0 == selected_slug)
        .unwrap_or(&event_types[0]);
    let (ref et_slug, ref et_title, duration, buf_before, buf_after, min_notice) = *selected_et;

    // Get event type ID
    let et_id: Option<(String,)> = sqlx::query_as(
        "SELECT et.id FROM event_types et JOIN accounts a ON a.id = et.account_id WHERE a.user_id = ? AND et.slug = ?",
    )
    .bind(&user.id)
    .bind(et_slug)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    let et_id = match et_id {
        Some((id,)) => id,
        None => return Html("Event type not found".to_string()),
    };

    // Check availability overrides for this date
    let target_date_str = target_date.format("%Y-%m-%d").to_string();
    let day_overrides: Vec<(Option<String>, Option<String>, i32)> = sqlx::query_as(
        "SELECT start_time, end_time, is_blocked FROM availability_overrides WHERE event_type_id = ? AND date = ? ORDER BY start_time",
    )
    .bind(&et_id)
    .bind(&target_date_str)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    let date_is_blocked = day_overrides.iter().any(|(_, _, b)| *b != 0);

    // Availability rules: use overrides if present, else weekly rules
    let rules: Vec<(String, String)> = if date_is_blocked {
        vec![] // blocked day — no availability
    } else if !day_overrides.is_empty() {
        // Custom hours replace weekly rules
        day_overrides
            .iter()
            .filter_map(|(s, e, _)| match (s, e) {
                (Some(start), Some(end)) => Some((start.clone(), end.clone())),
                _ => None,
            })
            .collect()
    } else {
        let weekday = target_date.weekday().num_days_from_sunday() as i32;
        sqlx::query_as(
            "SELECT start_time, end_time FROM availability_rules WHERE event_type_id = ? AND day_of_week = ? ORDER BY start_time",
        )
        .bind(&et_id)
        .bind(weekday)
        .fetch_all(&state.pool)
        .await
        .unwrap_or_default()
    };

    // Busy events for this date — enriched with title + calendar name
    let day_start_compact = target_date.format("%Y%m%d").to_string();
    let day_end_compact = (target_date + Duration::days(1))
        .format("%Y%m%d")
        .to_string();
    let day_start_iso = target_date.format("%Y-%m-%dT00:00:00").to_string();
    let day_end_iso = target_date.format("%Y-%m-%dT23:59:59").to_string();

    // Non-recurring busy events for this date
    let raw_busy_events: Vec<(
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
    )> = sqlx::query_as(
        "SELECT e.start_at, e.end_at, e.summary, c.display_name, e.timezone
         FROM events e
         JOIN calendars c ON c.id = e.calendar_id
         JOIN caldav_sources cs ON cs.id = c.source_id
         JOIN accounts a ON a.id = cs.account_id
         WHERE a.user_id = ? AND c.is_busy = 1
           AND (NOT EXISTS (SELECT 1 FROM event_type_calendars WHERE event_type_id = ?)
                OR c.id IN (SELECT calendar_id FROM event_type_calendars WHERE event_type_id = ?))
           AND (e.rrule IS NULL OR e.rrule = '')
           AND (e.status IS NULL OR e.status != 'CANCELLED')
           AND (e.transp IS NULL OR e.transp != 'TRANSPARENT')
           AND ((e.start_at < ? AND e.end_at > ?) OR (e.start_at < ? AND e.end_at > ?))
         ORDER BY e.start_at",
    )
    .bind(&user.id)
    .bind(&et_id)
    .bind(&et_id)
    .bind(&day_end_compact)
    .bind(&day_start_compact)
    .bind(&day_end_iso)
    .bind(&day_start_iso)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    let mut busy_events: Vec<(String, String, Option<String>, Option<String>)> = raw_busy_events
        .iter()
        .filter_map(|(s, e, summary, cal_name, event_tz)| {
            let start = convert_event_to_tz(parse_ical_datetime(s)?, event_tz.as_deref(), host_tz);
            let end = convert_event_to_tz(parse_ical_datetime(e)?, event_tz.as_deref(), host_tz);
            Some((
                start.format("%Y-%m-%dT%H:%M:%S").to_string(),
                end.format("%Y-%m-%dT%H:%M:%S").to_string(),
                summary.clone(),
                cal_name.clone(),
            ))
        })
        .collect();

    // Recurring busy events — expand into this date
    let recurring_events: Vec<(
        String,
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    )> = sqlx::query_as(
        "SELECT e.start_at, e.end_at, e.rrule, e.raw_ical, e.summary, c.display_name, e.timezone
         FROM events e
         JOIN calendars c ON c.id = e.calendar_id
         JOIN caldav_sources cs ON cs.id = c.source_id
         JOIN accounts a ON a.id = cs.account_id
         WHERE a.user_id = ? AND c.is_busy = 1
           AND (NOT EXISTS (SELECT 1 FROM event_type_calendars WHERE event_type_id = ?)
                OR c.id IN (SELECT calendar_id FROM event_type_calendars WHERE event_type_id = ?))
           AND (e.status IS NULL OR e.status != 'CANCELLED')
           AND (e.transp IS NULL OR e.transp != 'TRANSPARENT')
           AND e.rrule IS NOT NULL AND e.rrule != ''
           AND (e.start_at <= ? OR e.start_at <= ?)",
    )
    .bind(&user.id)
    .bind(&et_id)
    .bind(&et_id)
    .bind(&day_end_iso)
    .bind(&day_end_compact)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    let ts_window_start = target_date
        .and_hms_opt(0, 0, 0)
        .unwrap_or(target_date.and_time(NaiveTime::MIN));
    let ts_window_end = target_date
        .and_hms_opt(23, 59, 59)
        .unwrap_or(target_date.and_time(NaiveTime::MIN));
    for (s, e, rrule_str, raw_ical, summary, cal_name, event_tz) in &recurring_events {
        if let (Some(ev_start), Some(ev_end)) = (parse_ical_datetime(s), parse_ical_datetime(e)) {
            let exdates = raw_ical
                .as_deref()
                .map(crate::rrule::extract_exdates)
                .unwrap_or_default();
            let occurrences = crate::rrule::expand_rrule(
                ev_start,
                ev_end,
                rrule_str,
                &exdates,
                ts_window_start,
                ts_window_end,
            );
            for (os, oe) in occurrences {
                let cs = convert_event_to_tz(os, event_tz.as_deref(), host_tz);
                let ce = convert_event_to_tz(oe, event_tz.as_deref(), host_tz);
                busy_events.push((
                    cs.format("%Y-%m-%dT%H:%M:%S").to_string(),
                    ce.format("%Y-%m-%dT%H:%M:%S").to_string(),
                    summary.clone(),
                    cal_name.clone(),
                ));
            }
        }
    }

    // Bookings for this date
    let bookings: Vec<(String, String, String, String)> = sqlx::query_as(
        "SELECT b.start_at, b.end_at, b.guest_name, et2.title
         FROM bookings b
         JOIN event_types et2 ON et2.id = b.event_type_id
         JOIN accounts a ON a.id = et2.account_id
         WHERE a.user_id = ? AND b.status IN ('confirmed', 'pending')
           AND b.start_at < ? AND b.end_at > ?
         ORDER BY b.start_at",
    )
    .bind(&user.id)
    .bind(&day_end_iso)
    .bind(&day_start_iso)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    // Build timeline: scan 15-min ticks from display_start to display_end
    let display_start_hour: u32 = rules
        .iter()
        .filter_map(|(s, _)| NaiveTime::parse_from_str(s, "%H:%M").ok())
        .map(|t| t.hour())
        .min()
        .unwrap_or(8)
        .saturating_sub(1);
    let display_end_hour: u32 = rules
        .iter()
        .filter_map(|(_, e)| NaiveTime::parse_from_str(e, "%H:%M").ok())
        .map(|t| {
            if t.minute() > 0 {
                t.hour() + 1
            } else {
                t.hour()
            }
        })
        .max()
        .unwrap_or(18)
        .min(23)
        + 1;

    let display_start = NaiveTime::from_hms_opt(display_start_hour, 0, 0).unwrap_or(NaiveTime::MIN);
    let display_end = NaiveTime::from_hms_opt(display_end_hour, 0, 0).unwrap_or(NaiveTime::MIN);
    let total_minutes = (display_end - display_start).num_minutes() as f64;

    let min_start = now_host + Duration::minutes(min_notice as i64);

    // Parse availability windows
    let avail_windows: Vec<(NaiveTime, NaiveTime)> = rules
        .iter()
        .filter_map(|(s, e)| {
            let st = NaiveTime::parse_from_str(s, "%H:%M").ok()?;
            let en = NaiveTime::parse_from_str(e, "%H:%M").ok()?;
            Some((st, en))
        })
        .collect();

    // Parse busy events into (start_dt, end_dt, label, detail)
    let busy_parsed: Vec<(NaiveDateTime, NaiveDateTime, String, String)> = busy_events
        .iter()
        .filter_map(|(s, e, summary, cal)| {
            let start = parse_ical_datetime(s)?;
            let end = parse_ical_datetime(e)?;
            let label = summary.clone().unwrap_or_else(|| "Busy".to_string());
            let detail = cal.clone().unwrap_or_default();
            Some((start, end, label, detail))
        })
        .collect();

    // Parse bookings into (start_dt, end_dt, label, detail)
    let bookings_parsed: Vec<(NaiveDateTime, NaiveDateTime, String, String)> = bookings
        .iter()
        .filter_map(|(s, e, guest, et_title)| {
            let start = parse_ical_datetime(s)?;
            let end = parse_ical_datetime(e)?;
            Some((start, end, guest.clone(), et_title.clone()))
        })
        .collect();

    // Scan in 15-min increments and classify each tick
    struct Tick {
        time: NaiveTime,
        status: String, // "available", "outside", "busy_event", "booking", "buffer", "min_notice"
        label: String,
        detail: String,
    }

    let mut ticks: Vec<Tick> = Vec::new();
    let mut cursor = display_start;
    let tick_size = Duration::minutes(15);

    while cursor < display_end {
        let tick_dt = target_date.and_time(cursor);
        let tick_end = tick_dt + tick_size;

        // 1. Check if within availability window
        let in_avail = avail_windows
            .iter()
            .any(|(ws, we)| cursor >= *ws && cursor < *we);

        if !in_avail {
            ticks.push(Tick {
                time: cursor,
                status: "outside".to_string(),
                label: "Outside availability".to_string(),
                detail: String::new(),
            });
            cursor = (tick_dt + tick_size).time();
            continue;
        }

        // 2. Check minimum notice
        if tick_dt < min_start {
            ticks.push(Tick {
                time: cursor,
                status: "min_notice".to_string(),
                label: format!("Min. notice ({}min)", min_notice),
                detail: String::new(),
            });
            cursor = (tick_dt + tick_size).time();
            continue;
        }

        // 3. Check calendar events (with buffers)
        let event_conflict = busy_parsed.iter().find(|(s, e, _, _)| {
            let buf_s = *s - Duration::minutes(buf_before as i64);
            let buf_e = *e + Duration::minutes(buf_after as i64);
            tick_dt < buf_e && tick_end > buf_s
        });

        if let Some((ev_s, ev_e, ev_label, ev_detail)) = event_conflict {
            // Is it the event itself or just the buffer zone?
            let in_event = tick_dt < *ev_e && tick_end > *ev_s;
            if in_event {
                ticks.push(Tick {
                    time: cursor,
                    status: "busy_event".to_string(),
                    label: ev_label.clone(),
                    detail: ev_detail.clone(),
                });
            } else {
                ticks.push(Tick {
                    time: cursor,
                    status: "buffer".to_string(),
                    label: format!(
                        "Buffer ({}min)",
                        if tick_dt < *ev_s {
                            buf_before
                        } else {
                            buf_after
                        }
                    ),
                    detail: format!("Around: {}", ev_label),
                });
            }
            cursor = (tick_dt + tick_size).time();
            continue;
        }

        // 4. Check bookings (with buffers)
        let booking_conflict = bookings_parsed.iter().find(|(s, e, _, _)| {
            let buf_s = *s - Duration::minutes(buf_before as i64);
            let buf_e = *e + Duration::minutes(buf_after as i64);
            tick_dt < buf_e && tick_end > buf_s
        });

        if let Some((bk_s, bk_e, bk_guest, bk_et)) = booking_conflict {
            let in_booking = tick_dt < *bk_e && tick_end > *bk_s;
            if in_booking {
                ticks.push(Tick {
                    time: cursor,
                    status: "booking".to_string(),
                    label: bk_guest.clone(),
                    detail: bk_et.clone(),
                });
            } else {
                ticks.push(Tick {
                    time: cursor,
                    status: "buffer".to_string(),
                    label: format!(
                        "Buffer ({}min)",
                        if tick_dt < *bk_s {
                            buf_before
                        } else {
                            buf_after
                        }
                    ),
                    detail: format!("Around: {} booking", bk_guest),
                });
            }
            cursor = (tick_dt + tick_size).time();
            continue;
        }

        // 5. Available!
        ticks.push(Tick {
            time: cursor,
            status: "available".to_string(),
            label: "Available".to_string(),
            detail: String::new(),
        });
        cursor = (tick_dt + tick_size).time();
    }

    // Merge consecutive ticks with same status+label into blocks
    struct Block {
        start: NaiveTime,
        end: NaiveTime,
        status: String,
        label: String,
        detail: String,
        left_pct: f64,
        width_pct: f64,
    }

    let mut blocks: Vec<Block> = Vec::new();
    for tick in &ticks {
        let tick_end_time = (target_date.and_time(tick.time) + tick_size).time();
        if let Some(last) = blocks.last_mut() {
            if last.status == tick.status && last.label == tick.label {
                last.end = tick_end_time;
                let start_min = (last.start - display_start).num_minutes() as f64;
                let dur_min = (last.end - last.start).num_minutes() as f64;
                last.left_pct = start_min / total_minutes * 100.0;
                last.width_pct = dur_min / total_minutes * 100.0;
                continue;
            }
        }
        let start_min = (tick.time - display_start).num_minutes() as f64;
        let dur_min = tick_size.num_minutes() as f64;
        blocks.push(Block {
            start: tick.time,
            end: tick_end_time,
            status: tick.status.clone(),
            label: tick.label.clone(),
            detail: tick.detail.clone(),
            left_pct: start_min / total_minutes * 100.0,
            width_pct: dur_min / total_minutes * 100.0,
        });
    }

    // Build template data
    let blocks_ctx: Vec<minijinja::Value> = blocks
        .iter()
        .map(|b| {
            context! {
                start => b.start.format("%H:%M").to_string(),
                end => b.end.format("%H:%M").to_string(),
                status => &b.status,
                label => &b.label,
                detail => &b.detail,
                left_pct => format!("{:.2}", b.left_pct),
                width_pct => format!("{:.2}", b.width_pct),
            }
        })
        .collect();

    // Hour markers for the timeline
    let mut hour_markers: Vec<minijinja::Value> = Vec::new();
    let mut h = display_start_hour;
    while h <= display_end_hour {
        let min_offset = (h - display_start_hour) as f64 * 60.0;
        let left_pct = min_offset / total_minutes * 100.0;
        hour_markers.push(context! {
            label => format!("{:02}:00", h),
            left_pct => format!("{:.2}", left_pct),
        });
        h += 1;
    }

    // Breakdown: only non-available blocks
    let breakdown_ctx: Vec<minijinja::Value> = blocks
        .iter()
        .filter(|b| b.status != "available" && b.status != "outside")
        .map(|b| {
            let reason = match b.status.as_str() {
                "busy_event" => format!("Calendar event: {}", b.label),
                "booking" => format!("Booking: {}", b.label),
                "buffer" => b.label.clone(),
                "min_notice" => b.label.clone(),
                _ => b.status.clone(),
            };
            context! {
                start => b.start.format("%H:%M").to_string(),
                end => b.end.format("%H:%M").to_string(),
                status => &b.status,
                reason => reason,
                detail => &b.detail,
            }
        })
        .collect();

    let et_options: Vec<minijinja::Value> = event_types
        .iter()
        .map(|et| {
            context! {
                slug => &et.0,
                title => &et.1,
                selected => et.0 == *et_slug,
            }
        })
        .collect();

    let prev_date = (target_date - Duration::days(1))
        .format("%Y-%m-%d")
        .to_string();
    let next_date = (target_date + Duration::days(1))
        .format("%Y-%m-%d")
        .to_string();
    // Troubleshoot is a dashboard page; keep English until dashboard is translated.
    let date_label = crate::i18n::format_long_date(target_date, "en");

    let tmpl = match state.templates.get_template("troubleshoot.html") {
        Ok(t) => t,
        Err(e) => return internal_error_html("template render", &e),
    };

    let (impersonating, impersonating_name, _impersonating_admin) = impersonation_ctx(&auth_user);
    Html(
        tmpl.render(context! {
            user_name => &user.name,
            no_event_types => false,
            event_types => et_options,
            selected_slug => et_slug,
            selected_date => target_date.format("%Y-%m-%d").to_string(),
            date_label => date_label,
            prev_date => prev_date,
            next_date => next_date,
            has_rules => !rules.is_empty(),
            date_is_blocked => date_is_blocked,
            has_custom_hours => !day_overrides.is_empty() && !date_is_blocked,
            blocks => blocks_ctx,
            hour_markers => hour_markers,
            breakdown => breakdown_ctx,
            et_title => et_title,
            duration => duration,
            buf_before => buf_before,
            buf_after => buf_after,
            min_notice => min_notice,
            sidebar => sidebar_context(&auth_user, "troubleshoot"),
            impersonating => impersonating,
            impersonating_name => impersonating_name,
        })
        .unwrap_or_default(),
    )
}

// --- Admin dashboard ---

async fn admin_dashboard(
    State(state): State<Arc<AppState>>,
    admin: crate::auth::AdminUser,
    Query(query): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let current_user = &admin.0;
    let error_message = query.get("error").cloned().unwrap_or_default();

    // Fetch all users
    let users: Vec<(String, String, String, String, String, bool)> = sqlx::query_as(
        "SELECT id, name, email, role, auth_provider, enabled FROM users ORDER BY created_at",
    )
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    let user_count = users.len();

    // Fetch groups per user
    let user_groups_rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT ug.user_id, g.name FROM user_groups ug JOIN groups g ON g.id = ug.group_id ORDER BY g.name",
    )
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    // Build a map of user_id -> comma-separated group names
    let mut user_groups_map: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    for (uid, gname) in &user_groups_rows {
        user_groups_map
            .entry(uid.clone())
            .or_default()
            .push(gname.clone());
    }

    let users_ctx: Vec<minijinja::Value> = users
        .iter()
        .map(|(id, name, email, role, auth_provider, enabled)| {
            let groups = user_groups_map.get(id).cloned().unwrap_or_default();
            context! {
                id => id,
                name => name,
                email => email,
                role => role,
                auth_provider => auth_provider,
                enabled => enabled,
                groups => groups,
            }
        })
        .collect();

    // Fetch groups with member count
    let groups_rows: Vec<(String, String, i64)> = sqlx::query_as(
        "SELECT g.id, g.name, COUNT(ug.user_id) as member_count \
         FROM groups g LEFT JOIN user_groups ug ON ug.group_id = g.id \
         GROUP BY g.id ORDER BY g.name",
    )
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    let group_count = groups_rows.len();

    // Fetch all group members with weights
    let all_members: Vec<(String, String, String, i64)> = sqlx::query_as(
        "SELECT ug.group_id, ug.user_id, u.name, ug.weight \
         FROM user_groups ug JOIN users u ON u.id = ug.user_id \
         ORDER BY ug.weight DESC, u.name",
    )
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    let groups_ctx: Vec<minijinja::Value> = groups_rows
        .iter()
        .map(|(id, name, member_count)| {
            let members: Vec<minijinja::Value> = all_members
                .iter()
                .filter(|(gid, _, _, _)| gid == id)
                .map(|(_, uid, uname, w)| {
                    context! {
                        user_id => uid,
                        name => uname,
                        weight => w,
                    }
                })
                .collect();
            context! {
                id => id,
                name => name,
                member_count => member_count,
                members => members,
            }
        })
        .collect();

    // Fetch auth config
    let auth_config = crate::auth::get_auth_config(&state.pool).await.ok();
    let registration_enabled = auth_config
        .as_ref()
        .map(|c| c.registration_enabled)
        .unwrap_or(false);
    let allowed_email_domains = auth_config
        .as_ref()
        .and_then(|c| c.allowed_email_domains.clone())
        .unwrap_or_default();
    let oidc_enabled = auth_config
        .as_ref()
        .map(|c| c.oidc_enabled)
        .unwrap_or(false);
    let oidc_issuer_url = auth_config
        .as_ref()
        .and_then(|c| c.oidc_issuer_url.clone())
        .unwrap_or_default();
    let oidc_client_id = auth_config
        .as_ref()
        .and_then(|c| c.oidc_client_id.clone())
        .unwrap_or_default();
    let oidc_auto_register = auth_config
        .as_ref()
        .map(|c| c.oidc_auto_register)
        .unwrap_or(true);
    let google_oauth2_client_id = auth_config
        .as_ref()
        .and_then(|c| c.google_oauth2_client_id.clone())
        .unwrap_or_default();
    let google_oauth2_configured = !google_oauth2_client_id.is_empty();

    let (
        smtp_configured,
        smtp_host,
        smtp_port,
        smtp_from_email,
        smtp_enabled,
        smtp_from_env,
        smtp_error,
    ) = match crate::email::load_smtp_status(&state.pool).await {
        Ok(Some(status)) => (
            true,
            status.host,
            status.port,
            status.from_email,
            status.enabled,
            status.from_env,
            String::new(),
        ),
        Ok(None) => (
            false,
            String::new(),
            0u16,
            String::new(),
            false,
            false,
            String::new(),
        ),
        Err(e) => (
            false,
            String::new(),
            0u16,
            String::new(),
            false,
            true,
            e.to_string(),
        ),
    };

    let tmpl = match state.templates.get_template("admin.html") {
        Ok(t) => t,
        Err(e) => return internal_error_html("template render", &e),
    };

    let sidebar = context! {
        user_name => current_user.name,
        user_title => current_user.title.as_deref().unwrap_or(""),
        user_id => current_user.id,
        user_role => "admin",
        user_timezone => current_user.timezone,
        has_avatar => current_user.avatar_path.is_some(),
        user_initials => compute_initials(&current_user.name),
        active => "admin",
        version => env!("CARGO_PKG_VERSION"),
    };

    let captcha_cfg = state.captcha_config.read().await;
    let captcha_configured = captcha_cfg.is_some();
    let captcha_instance_url = captcha_cfg
        .as_ref()
        .map(|c| c.instance_url.clone())
        .unwrap_or_default();
    let captcha_site_key = captcha_cfg
        .as_ref()
        .map(|c| c.site_key.clone())
        .unwrap_or_default();
    let captcha_widget_url = captcha_cfg
        .as_ref()
        .map(|c| c.widget_url.clone())
        .unwrap_or_else(|| captcha::DEFAULT_WIDGET_URL.to_string());
    drop(captcha_cfg);

    let meeting_cfg = state.meeting_config.read().await;
    let jitsi_configured = meeting_cfg.jitsi.is_some();
    let jitsi_base_url = meeting_cfg
        .jitsi
        .as_ref()
        .map(|j| j.base_url.clone())
        .unwrap_or_default();
    let jitsi_pattern = meeting_cfg
        .jitsi
        .as_ref()
        .map(|j| j.pattern.clone())
        .unwrap_or_else(|| meeting::DEFAULT_JITSI_PATTERN.to_string());
    let jitsi_display_name = meeting_cfg
        .jitsi
        .as_ref()
        .and_then(|j| j.display_name.clone())
        .unwrap_or_default();
    let meeting_webhook_configured = meeting_cfg.webhook.is_some();
    let meeting_webhook_url = meeting_cfg
        .webhook
        .as_ref()
        .map(|w| w.url.clone())
        .unwrap_or_default();
    let meeting_webhook_auth_mode = meeting_cfg
        .webhook
        .as_ref()
        .map(|w| w.auth_mode.as_str().to_string())
        .unwrap_or_else(|| meeting::WEBHOOK_AUTH_NONE.to_string());
    let meeting_webhook_has_secret = meeting_cfg
        .webhook
        .as_ref()
        .map(|w| !w.secret.is_empty())
        .unwrap_or(false);
    let meeting_webhook_display_name = meeting_cfg
        .webhook
        .as_ref()
        .and_then(|w| w.display_name.clone())
        .unwrap_or_default();
    drop(meeting_cfg);

    Html(
        tmpl.render(context! {
            current_user_id => current_user.id,
            users => users_ctx,
            user_count => user_count,
            groups => groups_ctx,
            group_count => group_count,
            registration_enabled => registration_enabled,
            allowed_email_domains => allowed_email_domains,
            oidc_enabled => oidc_enabled,
            oidc_issuer_url => oidc_issuer_url,
            oidc_client_id => oidc_client_id,
            oidc_auto_register => oidc_auto_register,
            google_oauth2_client_id => google_oauth2_client_id,
            google_oauth2_configured => google_oauth2_configured,
            base_url => std::env::var("CALRS_BASE_URL").unwrap_or_default(),
            smtp_configured => smtp_configured,
            smtp_host => smtp_host,
            smtp_port => smtp_port,
            smtp_from_email => smtp_from_email,
            smtp_enabled => smtp_enabled,
            smtp_from_env => smtp_from_env,
            smtp_error => smtp_error,
            captcha_configured => captcha_configured,
            captcha_instance_url => captcha_instance_url,
            captcha_site_key => captcha_site_key,
            captcha_widget_url => captcha_widget_url,
            jitsi_configured => jitsi_configured,
            jitsi_base_url => jitsi_base_url,
            jitsi_pattern => jitsi_pattern,
            jitsi_display_name => jitsi_display_name,
            jitsi_default_pattern => meeting::DEFAULT_JITSI_PATTERN,
            meeting_webhook_configured => meeting_webhook_configured,
            meeting_webhook_url => meeting_webhook_url,
            meeting_webhook_auth_mode => meeting_webhook_auth_mode,
            meeting_webhook_has_secret => meeting_webhook_has_secret,
            meeting_webhook_display_name => meeting_webhook_display_name,
            has_logo => state.data_dir.join("logo.png").exists(),
            company_link => get_company_link(&state.pool).await.unwrap_or_default(),
            current_theme => get_theme_name(&state.pool).await,
            custom_colors => {
                let (a, ah, bg, s, t) = get_custom_colors(&state.pool).await;
                context! { accent => a, accent_hover => ah, bg => bg, surface => s, text => t }
            },
            sidebar => sidebar,
            impersonating => false,
            impersonating_name => "",
            error_message => error_message,
        })
        .unwrap_or_else(|e| internal_error_body("template render", &e)),
    )
}

async fn admin_toggle_role(
    State(state): State<Arc<AppState>>,
    _admin: crate::auth::AdminUser,
    headers: HeaderMap,
    Path(user_id): Path<String>,
    Form(csrf): Form<CsrfForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &csrf._csrf) {
        return resp;
    }
    // Get current role
    let current_role: Option<(String,)> = sqlx::query_as("SELECT role FROM users WHERE id = ?")
        .bind(&user_id)
        .fetch_optional(&state.pool)
        .await
        .unwrap_or(None);

    if let Some((role,)) = current_role {
        let new_role = if role == "admin" { "user" } else { "admin" };
        let _ = sqlx::query("UPDATE users SET role = ?, updated_at = datetime('now') WHERE id = ?")
            .bind(new_role)
            .bind(&user_id)
            .execute(&state.pool)
            .await;
        tracing::info!(target_user = %user_id, new_role = %new_role, admin = %_admin.0.email, "admin: role changed");
    }

    Redirect::to("/dashboard/admin").into_response()
}

async fn admin_toggle_enabled(
    State(state): State<Arc<AppState>>,
    _admin: crate::auth::AdminUser,
    headers: HeaderMap,
    Path(user_id): Path<String>,
    Form(csrf): Form<CsrfForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &csrf._csrf) {
        return resp;
    }
    // Get current enabled status
    let current: Option<(bool,)> = sqlx::query_as("SELECT enabled FROM users WHERE id = ?")
        .bind(&user_id)
        .fetch_optional(&state.pool)
        .await
        .unwrap_or(None);

    if let Some((enabled,)) = current {
        let new_enabled = !enabled;
        let _ =
            sqlx::query("UPDATE users SET enabled = ?, updated_at = datetime('now') WHERE id = ?")
                .bind(new_enabled)
                .bind(&user_id)
                .execute(&state.pool)
                .await;
        tracing::info!(target_user = %user_id, enabled = %new_enabled, admin = %_admin.0.email, "admin: user toggled");
    }

    Redirect::to("/dashboard/admin").into_response()
}

async fn admin_delete_user(
    State(state): State<Arc<AppState>>,
    admin: crate::auth::AdminUser,
    headers: HeaderMap,
    Path(user_id): Path<String>,
    Form(csrf): Form<CsrfForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &csrf._csrf) {
        return resp;
    }
    let admin_user = &admin.0;
    let avatars_dir = state.data_dir.join("avatars");
    match crate::auth::delete_user(
        &state.pool,
        &user_id,
        Some(&admin_user.id),
        Some(&avatars_dir),
    )
    .await
    {
        Ok(()) => {
            tracing::info!(target_user = %user_id, admin = %admin_user.email, "admin: user deleted");
            Redirect::to("/dashboard/admin").into_response()
        }
        Err(e) => {
            tracing::warn!(target_user = %user_id, admin = %admin_user.email, error = %e, "admin: user delete refused");
            let encoded = urlencoding::encode(&e.to_string()).into_owned();
            Redirect::to(&format!("/dashboard/admin?error={}", encoded)).into_response()
        }
    }
}

#[derive(Deserialize)]
struct AdminAuthForm {
    _csrf: Option<String>,
    registration_enabled: Option<String>,
    allowed_email_domains: Option<String>,
}

async fn admin_update_auth(
    State(state): State<Arc<AppState>>,
    _admin: crate::auth::AdminUser,
    headers: HeaderMap,
    Form(form): Form<AdminAuthForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }
    let registration_enabled = form.registration_enabled.is_some();
    let allowed_domains = form.allowed_email_domains.filter(|d| !d.trim().is_empty());

    let _ = sqlx::query(
        "UPDATE auth_config SET registration_enabled = ?, allowed_email_domains = ?, updated_at = datetime('now') WHERE id = 'singleton'",
    )
    .bind(registration_enabled)
    .bind(&allowed_domains)
    .execute(&state.pool)
    .await;

    tracing::info!(admin = %_admin.0.email, "admin: auth config updated");

    Redirect::to("/dashboard/admin").into_response()
}

#[derive(Deserialize)]
struct AdminThemeForm {
    _csrf: Option<String>,
    theme: Option<String>,
    custom_accent: Option<String>,
    custom_accent_hover: Option<String>,
    custom_bg: Option<String>,
    custom_surface: Option<String>,
    custom_text: Option<String>,
}

async fn admin_update_accent(
    State(state): State<Arc<AppState>>,
    _admin: crate::auth::AdminUser,
    headers: HeaderMap,
    Form(form): Form<AdminThemeForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }
    let theme = form
        .theme
        .filter(|t| {
            matches!(
                t.as_str(),
                "default"
                    | "nord"
                    | "dracula"
                    | "gruvbox"
                    | "solarized"
                    | "tokyo-night"
                    | "vates"
                    | "custom"
            )
        })
        .unwrap_or_else(|| "default".to_string());

    if theme == "custom" {
        let accent = form.custom_accent.as_deref().unwrap_or("#2563eb");
        let accent_hover = form.custom_accent_hover.as_deref().unwrap_or("#1d4ed8");
        let bg = form.custom_bg.as_deref().unwrap_or("#f4f4f5");
        let surface = form.custom_surface.as_deref().unwrap_or("#ffffff");
        let text = form.custom_text.as_deref().unwrap_or("#18181b");

        let _ = sqlx::query(
            "UPDATE auth_config SET theme = 'custom', custom_accent = ?, custom_accent_hover = ?, custom_bg = ?, custom_surface = ?, custom_text = ?, updated_at = datetime('now') WHERE id = 'singleton'",
        )
        .bind(accent)
        .bind(accent_hover)
        .bind(bg)
        .bind(surface)
        .bind(text)
        .execute(&state.pool)
        .await;
    } else {
        let _ = sqlx::query(
            "UPDATE auth_config SET theme = ?, updated_at = datetime('now') WHERE id = 'singleton'",
        )
        .bind(&theme)
        .execute(&state.pool)
        .await;
    }

    // Rebuild and cache the CSS
    let new_css = build_theme_css(&state.pool).await;
    *state.theme_css.write().await = new_css;

    tracing::info!(admin = %_admin.0.email, theme = %theme, "admin: theme updated");

    Redirect::to("/dashboard/admin").into_response()
}

#[derive(Deserialize)]
struct AdminOidcForm {
    _csrf: Option<String>,
    oidc_enabled: Option<String>,
    oidc_issuer_url: Option<String>,
    oidc_client_id: Option<String>,
    oidc_client_secret: Option<String>,
    oidc_auto_register: Option<String>,
}

async fn admin_update_oidc(
    State(state): State<Arc<AppState>>,
    _admin: crate::auth::AdminUser,
    headers: HeaderMap,
    Form(form): Form<AdminOidcForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }
    let oidc_enabled = form.oidc_enabled.is_some();
    let issuer_url = form.oidc_issuer_url.filter(|s| !s.trim().is_empty());
    let client_id = form.oidc_client_id.filter(|s| !s.trim().is_empty());
    let auto_register = form.oidc_auto_register.is_some();

    // If client_secret is provided (non-empty), update it; otherwise keep current value
    let secret_provided = form
        .oidc_client_secret
        .as_ref()
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false);

    if secret_provided {
        let client_secret = form.oidc_client_secret.unwrap_or_default();
        // Encrypt the secret at rest. We carry the auth_config row's
        // singleton SQLite primary key, so on the read side it goes
        // through crypto::decrypt_value.
        let encrypted_secret = match crate::crypto::encrypt_value(&state.secret_key, &client_secret)
        {
            Ok(s) => s,
            Err(e) => return internal_error_response("encrypt oidc client_secret", &e),
        };
        let _ = sqlx::query(
            "UPDATE auth_config SET oidc_enabled = ?, oidc_issuer_url = ?, oidc_client_id = ?, oidc_client_secret = ?, oidc_auto_register = ?, updated_at = datetime('now') WHERE id = 'singleton'",
        )
        .bind(oidc_enabled)
        .bind(&issuer_url)
        .bind(&client_id)
        .bind(&encrypted_secret)
        .bind(auto_register)
        .execute(&state.pool)
        .await;
    } else {
        let _ = sqlx::query(
            "UPDATE auth_config SET oidc_enabled = ?, oidc_issuer_url = ?, oidc_client_id = ?, oidc_auto_register = ?, updated_at = datetime('now') WHERE id = 'singleton'",
        )
        .bind(oidc_enabled)
        .bind(&issuer_url)
        .bind(&client_id)
        .bind(auto_register)
        .execute(&state.pool)
        .await;
    }

    tracing::info!(admin = %_admin.0.email, "admin: OIDC config updated");

    Redirect::to("/dashboard/admin").into_response()
}

#[derive(Deserialize)]
struct AdminGoogleOAuth2Form {
    _csrf: Option<String>,
    google_oauth2_client_id: Option<String>,
    google_oauth2_client_secret: Option<String>,
}

async fn admin_update_google_oauth2(
    State(state): State<Arc<AppState>>,
    _admin: crate::auth::AdminUser,
    headers: HeaderMap,
    Form(form): Form<AdminGoogleOAuth2Form>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }
    let client_id = form
        .google_oauth2_client_id
        .filter(|s| !s.trim().is_empty());

    let secret_provided = form
        .google_oauth2_client_secret
        .as_ref()
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false);

    if secret_provided {
        let client_secret = form.google_oauth2_client_secret.unwrap_or_default();
        let encrypted_secret = match crate::crypto::encrypt_value(&state.secret_key, &client_secret)
        {
            Ok(s) => s,
            Err(e) => return internal_error_response("encrypt google_oauth2 client_secret", &e),
        };
        let _ = sqlx::query(
            "UPDATE auth_config SET google_oauth2_client_id = ?, google_oauth2_client_secret = ?, updated_at = datetime('now') WHERE id = 'singleton'",
        )
        .bind(&client_id)
        .bind(&encrypted_secret)
        .execute(&state.pool)
        .await;
    } else {
        let _ = sqlx::query(
            "UPDATE auth_config SET google_oauth2_client_id = ?, updated_at = datetime('now') WHERE id = 'singleton'",
        )
        .bind(&client_id)
        .execute(&state.pool)
        .await;
    }

    tracing::info!(admin = %_admin.0.email, "admin: Google OAuth2 config updated");
    Redirect::to("/dashboard/admin").into_response()
}

// --- Google Calendar OAuth2 connect flow ---

async fn google_connect(
    State(state): State<Arc<AppState>>,
    auth_user: crate::auth::AuthUser,
) -> impl IntoResponse {
    // Load Google OAuth2 client credentials
    let creds: Option<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT google_oauth2_client_id, google_oauth2_client_secret FROM auth_config LIMIT 1",
    )
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    let client_id = match creds.and_then(|(id, _)| id).filter(|s| !s.is_empty()) {
        Some(id) => id,
        None => {
            return Html("Google Calendar integration is not configured. Ask your administrator to set up Google OAuth2 credentials in the admin panel.".to_string()).into_response();
        }
    };

    let base_url = std::env::var("CALRS_BASE_URL").unwrap_or_default();
    if base_url.is_empty() {
        return Html(
            "CALRS_BASE_URL environment variable must be set for OAuth2 flows.".to_string(),
        )
        .into_response();
    }

    let redirect_uri = format!(
        "{}/dashboard/sources/google/callback",
        base_url.trim_end_matches('/')
    );
    let csrf_state = uuid::Uuid::new_v4().to_string();

    let auth_url =
        crate::oauth2_caldav::build_google_auth_url(&client_id, &redirect_uri, &csrf_state);

    // Store state in cookies via Set-Cookie headers (CookieJar's String→Cookie
    // conversion treats the whole formatted string as the cookie name and drops
    // attributes, so set the headers directly).
    let cookie_opts = "; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600";
    let state_cookie = format!("__Host-calrs_google_state={}{}", csrf_state, cookie_opts);
    let user_cookie = format!(
        "__Host-calrs_google_user={}{}",
        auth_user.user.id, cookie_opts
    );

    let mut headers = axum::http::HeaderMap::new();
    headers.append(
        axum::http::header::SET_COOKIE,
        state_cookie.parse().unwrap(),
    );
    headers.append(axum::http::header::SET_COOKIE, user_cookie.parse().unwrap());

    (headers, Redirect::to(&auth_url)).into_response()
}

#[derive(Deserialize)]
struct GoogleCallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

async fn google_callback(
    State(state): State<Arc<AppState>>,
    auth_user: crate::auth::AuthUser,
    jar: axum_extra::extract::CookieJar,
    Query(query): Query<GoogleCallbackQuery>,
) -> impl IntoResponse {
    // Check for errors from Google
    if let Some(error) = &query.error {
        return Html(format!("Google authorization failed: {}", error)).into_response();
    }

    // Verify CSRF state
    let stored_state = jar
        .get("__Host-calrs_google_state")
        .map(|c| c.value().to_string())
        .unwrap_or_default();
    let query_state = query.state.unwrap_or_default();
    if stored_state.is_empty() || stored_state != query_state {
        return Html("Invalid state parameter. Please try again.".to_string()).into_response();
    }

    // Cross-tab defense-in-depth: the user cookie set at /connect must match
    // the current session. Guards against a tab swap where the OAuth flow was
    // started as user A but the callback fires while user B is logged in.
    let stored_user = jar
        .get("__Host-calrs_google_user")
        .map(|c| c.value().to_string())
        .unwrap_or_default();
    if stored_user.is_empty() || stored_user != auth_user.user.id {
        tracing::warn!(
            session_user = %auth_user.user.id,
            cookie_user = %stored_user,
            "Google OAuth2 callback: user cookie missing or does not match session"
        );
        return Html(
            "Session changed during Google authorization. Please start the connect flow again."
                .to_string(),
        )
        .into_response();
    }

    let code = match query.code {
        Some(c) => c,
        None => return Html("No authorization code received.".to_string()).into_response(),
    };

    // Load Google OAuth2 credentials
    let creds: Option<(String, String)> = sqlx::query_as(
        "SELECT google_oauth2_client_id, google_oauth2_client_secret FROM auth_config LIMIT 1",
    )
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    let (client_id, client_secret_enc) = match creds {
        Some(c) => c,
        None => return Html("Google OAuth2 not configured.".to_string()).into_response(),
    };

    // The stored Google OAuth2 client secret is encrypted at rest; the
    // startup migration ensures any pre-existing plaintext is upgraded
    // before we reach this path.
    let client_secret = match crate::crypto::decrypt_value(&state.secret_key, &client_secret_enc) {
        Ok(s) => s,
        Err(e) => return internal_error_response("decrypt google_oauth2 client_secret", &e),
    };

    let base_url = std::env::var("CALRS_BASE_URL").unwrap_or_default();
    let redirect_uri = format!(
        "{}/dashboard/sources/google/callback",
        base_url.trim_end_matches('/')
    );

    // Exchange code for tokens
    let (access_token, refresh_token, expires_in) =
        match crate::oauth2_caldav::exchange_google_code(
            &client_id,
            &client_secret,
            &code,
            &redirect_uri,
        )
        .await
        {
            Ok(t) => t,
            Err(e) => return Html(format!("Token exchange failed: {}", e)).into_response(),
        };

    // Identify the Google account that authorized us; its email is what goes in the CalDAV URL.
    // The local calrs user's email is unrelated and may not match the Google account.
    let google_email = match crate::oauth2_caldav::fetch_google_email(&access_token).await {
        Ok(e) => e,
        Err(e) => {
            return Html(format!("Failed to fetch Google account email: {}", e)).into_response();
        }
    };
    let caldav_url = crate::oauth2_caldav::google_caldav_url_for_email(&google_email);

    // Test the CalDAV connection (PROPFIND requires the per-user URL)
    let client = crate::caldav::CaldavClient::with_bearer(&caldav_url, &access_token);
    if let Err(e) = client.check_connection().await {
        tracing::warn!(error = %e, "Google CalDAV connection test failed (non-fatal)");
    }

    // Get user's account
    let account: Option<(String,)> =
        sqlx::query_as("SELECT a.id FROM accounts a WHERE a.user_id = ? LIMIT 1")
            .bind(&auth_user.user.id)
            .fetch_optional(&state.pool)
            .await
            .unwrap_or(None);

    let account_id = match account {
        Some((id,)) => id,
        None => return Html("No scheduling account found.".to_string()).into_response(),
    };

    // Encrypt tokens
    let access_token_enc = match crate::crypto::encrypt_password(&state.secret_key, &access_token) {
        Ok(enc) => enc,
        Err(_) => return Html("Encryption error.".to_string()).into_response(),
    };
    let refresh_token_enc = match crate::crypto::encrypt_password(&state.secret_key, &refresh_token)
    {
        Ok(enc) => enc,
        Err(_) => return Html("Encryption error.".to_string()).into_response(),
    };
    let expires_at = chrono::Utc::now() + chrono::Duration::seconds(expires_in);

    // Create the CalDAV source
    let source_id = uuid::Uuid::new_v4().to_string();
    let _ = sqlx::query(
        "INSERT INTO caldav_sources (id, account_id, name, url, username, auth_type, oauth2_provider, access_token_enc, refresh_token_enc, token_expires_at)
         VALUES (?, ?, 'Google Calendar', ?, ?, 'oauth2', 'google', ?, ?, ?)",
    )
    .bind(&source_id)
    .bind(&account_id)
    .bind(&caldav_url)
    .bind(&google_email)
    .bind(&access_token_enc)
    .bind(&refresh_token_enc)
    .bind(expires_at.to_rfc3339())
    .execute(&state.pool)
    .await;

    tracing::info!(user = %auth_user.user.email, google_email = %google_email, "Google Calendar source added via OAuth2");

    // Auto-sync
    let (_, calendar_count) = run_sync_for_source(
        &state.pool,
        &state.secret_key,
        &source_id,
        &caldav_url,
        &google_email,
        None,
        "oauth2",
        Some(&access_token_enc),
        Some(&expires_at.to_rfc3339()),
        crate::providers::factory::kinds::CALDAV,
    )
    .await;

    // Clear transient cookies. The browser only honors removal of
    // __Host-prefixed cookies when the Set-Cookie also has Secure and Path=/,
    // so emit explicit expiring headers (matches admin_stop_impersonate).
    let clear_opts = "; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0";
    let mut headers = axum::http::HeaderMap::new();
    headers.append(
        axum::http::header::SET_COOKIE,
        format!("__Host-calrs_google_state={}", clear_opts)
            .parse()
            .unwrap(),
    );
    headers.append(
        axum::http::header::SET_COOKIE,
        format!("__Host-calrs_google_user={}", clear_opts)
            .parse()
            .unwrap(),
    );

    let redirect = if calendar_count > 0 {
        Redirect::to(&format!("/dashboard/sources/{}/setup-write", source_id))
    } else {
        Redirect::to("/dashboard/sources")
    };
    (headers, redirect).into_response()
}

// --- Captcha settings ---

#[derive(Deserialize)]
struct AdminCaptchaForm {
    _csrf: Option<String>,
    captcha_instance_url: Option<String>,
    captcha_site_key: Option<String>,
    captcha_secret: Option<String>,
    captcha_widget_url: Option<String>,
}

async fn admin_update_captcha(
    State(state): State<Arc<AppState>>,
    _admin: crate::auth::AdminUser,
    headers: HeaderMap,
    Form(form): Form<AdminCaptchaForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }

    let instance_url = form.captcha_instance_url.filter(|s| !s.trim().is_empty());
    let site_key = form.captcha_site_key.filter(|s| !s.trim().is_empty());
    let widget_url = form.captcha_widget_url.filter(|s| !s.trim().is_empty());

    let secret_provided = form
        .captcha_secret
        .as_ref()
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false);

    if secret_provided {
        let secret = form.captcha_secret.unwrap_or_default();
        let encrypted = match crate::crypto::encrypt_value(&state.secret_key, &secret) {
            Ok(s) => s,
            Err(e) => return internal_error_response("encrypt captcha secret", &e),
        };
        if let Err(e) = sqlx::query(
            "UPDATE auth_config SET captcha_instance_url = ?, captcha_site_key = ?, captcha_secret = ?, captcha_widget_url = ?, updated_at = datetime('now') WHERE id = 'singleton'",
        )
        .bind(&instance_url)
        .bind(&site_key)
        .bind(&encrypted)
        .bind(&widget_url)
        .execute(&state.pool)
        .await
        {
            tracing::error!(error = %e, "failed to save captcha config");
        }
    } else {
        if let Err(e) = sqlx::query(
            "UPDATE auth_config SET captcha_instance_url = ?, captcha_site_key = ?, captcha_widget_url = ?, updated_at = datetime('now') WHERE id = 'singleton'",
        )
        .bind(&instance_url)
        .bind(&site_key)
        .bind(&widget_url)
        .execute(&state.pool)
        .await
        {
            tracing::error!(error = %e, "failed to save captcha config");
        }
    }

    let new_config = captcha::load_captcha_config(&state.pool, &state.secret_key).await;
    let new_csp = build_csp(&new_config);
    *state.captcha_config.write().await = new_config;
    *state.csp.write().await = new_csp;

    tracing::info!(admin = %_admin.0.email, "admin: captcha config updated");

    Redirect::to("/dashboard/admin").into_response()
}

// --- Auto-generated meeting link settings ---

#[derive(Deserialize)]
struct AdminJitsiForm {
    _csrf: Option<String>,
    jitsi_base_url: Option<String>,
    jitsi_pattern: Option<String>,
    jitsi_display_name: Option<String>,
}

async fn admin_update_jitsi(
    State(state): State<Arc<AppState>>,
    _admin: crate::auth::AdminUser,
    headers: HeaderMap,
    Form(form): Form<AdminJitsiForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }

    let base_url = form.jitsi_base_url.filter(|s| !s.trim().is_empty());
    let pattern = form.jitsi_pattern.filter(|s| !s.trim().is_empty());
    let display_name = form.jitsi_display_name.filter(|s| !s.trim().is_empty());

    if let Err(e) = sqlx::query(
        "UPDATE auth_config SET jitsi_base_url = ?, jitsi_pattern = ?, jitsi_display_name = ?, updated_at = datetime('now') WHERE id = 'singleton'",
    )
    .bind(&base_url)
    .bind(&pattern)
    .bind(&display_name)
    .execute(&state.pool)
    .await
    {
        tracing::error!(error = %e, "failed to save jitsi config");
    }

    *state.meeting_config.write().await =
        meeting::load_config(&state.pool, &state.secret_key).await;

    tracing::info!(admin = %_admin.0.email, "admin: jitsi config updated");
    Redirect::to("/dashboard/admin").into_response()
}

#[derive(Deserialize)]
struct AdminMeetingWebhookForm {
    _csrf: Option<String>,
    meeting_webhook_url: Option<String>,
    meeting_webhook_auth_mode: Option<String>,
    meeting_webhook_secret: Option<String>,
    meeting_webhook_display_name: Option<String>,
}

async fn admin_update_meeting_webhook(
    State(state): State<Arc<AppState>>,
    _admin: crate::auth::AdminUser,
    headers: HeaderMap,
    Form(form): Form<AdminMeetingWebhookForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }

    let url = form.meeting_webhook_url.filter(|s| !s.trim().is_empty());
    let auth_mode = match form.meeting_webhook_auth_mode.as_deref() {
        Some(meeting::WEBHOOK_AUTH_HMAC) => Some(meeting::WEBHOOK_AUTH_HMAC.to_string()),
        Some(meeting::WEBHOOK_AUTH_NONE) => Some(meeting::WEBHOOK_AUTH_NONE.to_string()),
        _ => None,
    };
    let display_name = form
        .meeting_webhook_display_name
        .filter(|s| !s.trim().is_empty());

    // Empty secret field on submit means "keep the current value" (same
    // pattern as OIDC and captcha). Wiping the secret requires switching
    // auth_mode away from "hmac".
    let secret_provided = form
        .meeting_webhook_secret
        .as_ref()
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false);

    if secret_provided {
        let secret = form.meeting_webhook_secret.unwrap_or_default();
        let encrypted = match crate::crypto::encrypt_value(&state.secret_key, &secret) {
            Ok(s) => s,
            Err(e) => return internal_error_response("encrypt webhook secret", &e),
        };
        if let Err(e) = sqlx::query(
            "UPDATE auth_config SET meeting_webhook_url = ?, meeting_webhook_auth_mode = ?, meeting_webhook_secret = ?, meeting_webhook_display_name = ?, updated_at = datetime('now') WHERE id = 'singleton'",
        )
        .bind(&url)
        .bind(&auth_mode)
        .bind(&encrypted)
        .bind(&display_name)
        .execute(&state.pool)
        .await
        {
            tracing::error!(error = %e, "failed to save meeting webhook config");
        }
    } else if let Err(e) = sqlx::query(
        "UPDATE auth_config SET meeting_webhook_url = ?, meeting_webhook_auth_mode = ?, meeting_webhook_display_name = ?, updated_at = datetime('now') WHERE id = 'singleton'",
    )
    .bind(&url)
    .bind(&auth_mode)
    .bind(&display_name)
    .execute(&state.pool)
    .await
    {
        tracing::error!(error = %e, "failed to save meeting webhook config");
    }

    *state.meeting_config.write().await =
        meeting::load_config(&state.pool, &state.secret_key).await;

    tracing::info!(admin = %_admin.0.email, "admin: meeting webhook config updated");
    Redirect::to("/dashboard/admin").into_response()
}

// --- Logo management ---

async fn serve_logo(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let logo_path = state.data_dir.join("logo.png");
    match tokio::fs::read(&logo_path).await {
        Ok(bytes) => {
            let content_type = if logo_path.exists() {
                // Detect from magic bytes
                if bytes.starts_with(&[0x89, 0x50, 0x4E, 0x47]) {
                    "image/png"
                } else if bytes.starts_with(&[0xFF, 0xD8]) {
                    "image/jpeg"
                } else if bytes.starts_with(b"<svg") || bytes.starts_with(b"<?xml") {
                    "image/svg+xml"
                } else {
                    "image/png"
                }
            } else {
                "image/png"
            };
            axum::response::Response::builder()
                .status(200)
                .header("Content-Type", content_type)
                .header("Cache-Control", "public, max-age=3600")
                .body(axum::body::Body::from(bytes))
                .unwrap_or_else(|_| axum::response::Response::new(axum::body::Body::empty()))
                .into_response()
        }
        Err(_) => (axum::http::StatusCode::NOT_FOUND, "").into_response(),
    }
}

async fn serve_accent_css(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let css = state.theme_css.read().await.clone();
    axum::response::Response::builder()
        .status(200)
        .header("Content-Type", "text/css; charset=utf-8")
        .header("Cache-Control", "no-cache")
        .body(axum::body::Body::from(css))
        .unwrap_or_else(|_| axum::response::Response::new(axum::body::Body::empty()))
        .into_response()
}

async fn serve_brand_logo() -> impl IntoResponse {
    static BRAND_LOGO: &[u8] = include_bytes!("../../assets/calrs.png");
    axum::response::Response::builder()
        .status(200)
        .header("Content-Type", "image/png")
        .header("Cache-Control", "public, max-age=86400")
        .body(axum::body::Body::from(BRAND_LOGO))
        .unwrap_or_else(|_| axum::response::Response::new(axum::body::Body::empty()))
        .into_response()
}

/// Serves the embed runtime that consumers paste into their own sites. It's
/// loaded cross-origin, so we set permissive CORS — there's no auth state to
/// leak. The contents are checked into `assets/embed.js` and baked into the
/// binary via `include_str!`.
async fn serve_embed_js() -> impl IntoResponse {
    static EMBED_JS: &str = include_str!("../../assets/embed.js");
    axum::response::Response::builder()
        .status(200)
        .header("Content-Type", "application/javascript; charset=utf-8")
        .header("Cache-Control", "public, max-age=3600")
        .header("Access-Control-Allow-Origin", "*")
        .body(axum::body::Body::from(EMBED_JS))
        .unwrap_or_else(|_| axum::response::Response::new(axum::body::Body::empty()))
        .into_response()
}

async fn serve_font_inter_latin() -> impl IntoResponse {
    static FONT: &[u8] = include_bytes!("../../assets/inter-latin.woff2");
    axum::response::Response::builder()
        .status(200)
        .header("Content-Type", "font/woff2")
        .header("Cache-Control", "public, max-age=31536000, immutable")
        .body(axum::body::Body::from(FONT))
        .unwrap_or_else(|_| axum::response::Response::new(axum::body::Body::empty()))
        .into_response()
}

async fn serve_font_inter_latin_ext() -> impl IntoResponse {
    static FONT: &[u8] = include_bytes!("../../assets/inter-latin-ext.woff2");
    axum::response::Response::builder()
        .status(200)
        .header("Content-Type", "font/woff2")
        .header("Cache-Control", "public, max-age=31536000, immutable")
        .body(axum::body::Body::from(FONT))
        .unwrap_or_else(|_| axum::response::Response::new(axum::body::Body::empty()))
        .into_response()
}

async fn admin_upload_logo(
    State(state): State<Arc<AppState>>,
    _admin: crate::auth::AdminUser,
    headers: HeaderMap,
    Query(csrf_query): Query<CsrfQuery>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &csrf_query._csrf) {
        return resp;
    }
    while let Ok(Some(field)) = multipart.next_field().await {
        if field.name() == Some("logo") {
            let content_type = field.content_type().unwrap_or("").to_string();
            if !content_type.starts_with("image/") {
                return Redirect::to("/dashboard/admin").into_response();
            }
            if let Ok(bytes) = field.bytes().await {
                if bytes.len() > 2 * 1024 * 1024 {
                    return Redirect::to("/dashboard/admin").into_response();
                }
                // Trust magic bytes, not the multipart Content-Type header.
                if detect_image_ext(&bytes).is_none() {
                    return Redirect::to("/dashboard/admin").into_response();
                }
                let logo_path = state.data_dir.join("logo.png");
                let _ = tokio::fs::write(&logo_path, &bytes).await;
            }
        }
    }
    Redirect::to("/dashboard/admin").into_response()
}

async fn admin_delete_logo(
    State(state): State<Arc<AppState>>,
    _admin: crate::auth::AdminUser,
    headers: HeaderMap,
    Form(csrf): Form<CsrfForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &csrf._csrf) {
        return resp;
    }
    let logo_path = state.data_dir.join("logo.png");
    let _ = tokio::fs::remove_file(&logo_path).await;
    Redirect::to("/dashboard/admin").into_response()
}

async fn admin_update_company_link(
    State(state): State<Arc<AppState>>,
    _admin: crate::auth::AdminUser,
    headers: HeaderMap,
    Form(form): Form<CompanyLinkForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }
    let link = form.company_link.trim().to_string();
    // Reject anything that isn't http(s). An admin (or attacker who has
    // taken over an admin account) could otherwise set `javascript:` and
    // turn the company link rendered on every public booking page into
    // stored XSS.
    if !link.is_empty() && !is_safe_company_link(&link) {
        tracing::warn!(
            admin = %_admin.0.email,
            "admin: company_link rejected (only http/https schemes allowed)"
        );
        let msg =
            urlencoding::encode("Company link must start with http:// or https://").into_owned();
        return Redirect::to(&format!("/dashboard/admin?error={}", msg)).into_response();
    }
    let link_value: Option<&str> = if link.is_empty() { None } else { Some(&link) };
    let _ = sqlx::query(
        "UPDATE auth_config SET company_link = ?, updated_at = datetime('now') WHERE id = 'singleton'",
    )
    .bind(link_value)
    .execute(&state.pool)
    .await;
    *state.company_link.write().await = if link.is_empty() { None } else { Some(link) };
    Redirect::to("/dashboard/admin").into_response()
}

// --- Impersonation ---

async fn admin_impersonate(
    State(_state): State<Arc<AppState>>,
    _admin: crate::auth::AdminUser,
    headers: HeaderMap,
    Path(user_id): Path<String>,
    Form(csrf): Form<CsrfForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &csrf._csrf) {
        return resp;
    }
    tracing::warn!(admin = %_admin.0.email, target = %user_id, "admin: impersonation started");
    let cookie = format!(
        "__Host-calrs_impersonate={}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age={}",
        user_id,
        86400 // 24 hours
    );
    ([("Set-Cookie", cookie)], Redirect::to("/dashboard")).into_response()
}

async fn admin_stop_impersonate(
    _admin: crate::auth::AdminUser,
    headers: HeaderMap,
    Form(csrf): Form<CsrfForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &csrf._csrf) {
        return resp;
    }
    tracing::info!("admin: impersonation ended");
    let cookie = "__Host-calrs_impersonate=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0";
    (
        [("Set-Cookie", cookie.to_string())],
        Redirect::to("/dashboard"),
    )
        .into_response()
}

// --- Admin: update member weight ---

#[derive(Deserialize)]
struct WeightForm {
    _csrf: Option<String>,
    weight: i64,
}

async fn admin_update_member_weight(
    State(state): State<Arc<AppState>>,
    _admin: crate::auth::AdminUser,
    headers: HeaderMap,
    Path((group_id, user_id)): Path<(String, String)>,
    Form(form): Form<WeightForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }
    let w = form.weight.clamp(1, 100);
    let _ = sqlx::query("UPDATE user_groups SET weight = ? WHERE group_id = ? AND user_id = ?")
        .bind(w)
        .bind(&group_id)
        .bind(&user_id)
        .execute(&state.pool)
        .await;
    tracing::info!(
        group_id,
        user_id,
        weight = w,
        "admin: updated member weight"
    );
    Redirect::to("/dashboard/admin").into_response()
}

// --- Token-based approve/decline (from email) ---

#[derive(Deserialize)]
struct DeclineForm {
    _csrf: Option<String>,
    reason: Option<String>,
}

/// Render an error page for token-based actions (shared by approve form and handler).
fn render_token_error(
    state: &AppState,
    headers: &HeaderMap,
    _token: &str,
    already: Option<(String,)>,
) -> axum::response::Response {
    let lang = crate::i18n::detect_from_headers(headers);
    let (title, message) = match already {
        Some((status,)) if status == "confirmed" => (
            "Already approved",
            "This booking has already been approved.",
        ),
        Some((status,)) if status == "declined" => (
            "Already declined",
            "This booking has already been declined.",
        ),
        Some((status,)) if status == "cancelled" => {
            ("Booking cancelled", "This booking was cancelled.")
        }
        _ => (
            "Invalid link",
            "This approval link is invalid or has expired.",
        ),
    };

    let tmpl = match state.templates.get_template("booking_action_error.html") {
        Ok(t) => t,
        Err(e) => return internal_error_response("internal", &e),
    };
    let rendered = tmpl
        .render(context! {
            title,
            message,
            lang => lang,
        })
        .unwrap_or_else(|e| internal_error_body("template render", &e));
    Html(rendered).into_response()
}

async fn approve_booking_form(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> impl IntoResponse {
    let lang = crate::i18n::detect_from_headers(&headers);
    // Look up pending booking by confirm_token
    let booking: Option<(String, String, String, String, String)> = sqlx::query_as(
        "SELECT b.guest_name, b.guest_email, b.start_at, b.end_at, et.title
         FROM bookings b
         JOIN event_types et ON et.id = b.event_type_id
         WHERE b.confirm_token = ? AND b.status = 'pending'",
    )
    .bind(&token)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    let (guest_name, guest_email, start_at, end_at, event_title) = match booking {
        Some(b) => b,
        None => {
            let already: Option<(String,)> =
                sqlx::query_as("SELECT status FROM bookings WHERE confirm_token = ?")
                    .bind(&token)
                    .fetch_optional(&state.pool)
                    .await
                    .unwrap_or(None);
            return render_token_error(&state, &headers, &token, already);
        }
    };

    let date_label = format_date_label(&start_at, lang);
    let start_time = extract_time_24h(&start_at);
    let end_time = extract_time_24h(&end_at);

    let tmpl = match state.templates.get_template("booking_approve_form.html") {
        Ok(t) => t,
        Err(e) => return internal_error_response("internal", &e),
    };
    tmpl.render(context! {
        event_title,
        date_label,
        start_time,
        end_time,
        guest_name,
        guest_email,
        lang => lang,
    })
    .map(|r| Html(r).into_response())
    .unwrap_or_else(|e| internal_error_response("template render", &e))
}

async fn approve_booking_by_token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> impl IntoResponse {
    let lang = crate::i18n::detect_from_headers(&headers);
    // Look up booking by confirm_token
    let booking: Option<(String, String, String, String, String, String, String, String, String, Option<String>, Option<String>, String, Option<String>, String)> =
        sqlx::query_as(
            "SELECT b.id, b.uid, b.guest_name, b.guest_email, b.start_at, b.end_at, et.title, a.user_id, u.name, et.location_value, b.cancel_token, COALESCE(b.guest_timezone, 'UTC'), b.reschedule_token, b.event_type_id
             FROM bookings b
             JOIN event_types et ON et.id = b.event_type_id
             JOIN accounts a ON a.id = et.account_id
             JOIN users u ON u.id = a.user_id
             WHERE b.confirm_token = ? AND b.status = 'pending'",
        )
        .bind(&token)
        .fetch_optional(&state.pool)
        .await
        .unwrap_or(None);

    let (
        bid,
        uid,
        guest_name,
        guest_email,
        start_at,
        end_at,
        event_title,
        user_id,
        host_name,
        location_value,
        cancel_token,
        guest_timezone,
        reschedule_token,
        event_type_id,
    ) = match booking {
        Some(b) => b,
        None => {
            let already: Option<(String,)> =
                sqlx::query_as("SELECT status FROM bookings WHERE confirm_token = ?")
                    .bind(&token)
                    .fetch_optional(&state.pool)
                    .await
                    .unwrap_or(None);
            return render_token_error(&state, &headers, &token, already);
        }
    };

    // Confirm the booking
    let _ = sqlx::query("UPDATE bookings SET status = 'confirmed' WHERE id = ?")
        .bind(&bid)
        .execute(&state.pool)
        .await;

    tracing::info!(booking_id = %bid, "booking approved via token");

    // start_at/end_at are naive in the event type's timezone; convert to the
    // guest's tz so the email body and the ICS attachment match what the
    // guest booked. See #101.
    let stored_tz = get_host_tz(&state.pool, &event_type_id).await;
    let guest_tz_parsed = guest_timezone.parse::<Tz>().unwrap_or(Tz::UTC);
    let (date, start_time, end_time) =
        booking_strings_in_guest_tz(&start_at, &end_at, stored_tz, guest_tz_parsed);
    let date_label = format_date_label(&date, lang);

    // Get host email for BookingDetails
    let host_email: String =
        sqlx::query_scalar("SELECT COALESCE(booking_email, email) FROM users WHERE id = ?")
            .bind(&user_id)
            .fetch_one(&state.pool)
            .await
            .unwrap_or_default();

    // Status is now 'confirmed' (we just transitioned it). Generate the
    // auto meeting URL if the event type uses one; otherwise fall back to
    // the static location_value.
    let location_display = resolve_booking_location(
        &state,
        &bid,
        &event_type_id,
        Some(&user_id),
        location_value.as_deref(),
        &guest_name,
        &guest_email,
        true,
    )
    .await;

    let details = crate::email::BookingDetails {
        event_title: event_title.clone(),
        date: date.clone(),
        start_time: start_time.clone(),
        end_time: end_time.clone(),
        guest_name: guest_name.clone(),
        guest_email: guest_email.clone(),
        guest_timezone,
        host_name: host_name.clone(),
        host_email,
        uid: uid.clone(),
        notes: None,
        location: location_display,
        reminder_minutes: None,
        additional_attendees: vec![],
        host_timezone: stored_tz.name().to_string(),
        ..Default::default()
    };

    // Push to CalDAV calendar
    caldav_push_booking(&state.pool, &state.secret_key, &user_id, &uid, &details).await;

    // Notify watcher teams
    notify_watchers(
        &state.pool,
        &state.secret_key,
        &bid,
        &event_type_id,
        &host_name,
        &details,
    )
    .await;

    // Send confirmation email to guest
    if let Ok(Some(smtp_config)) =
        crate::email::load_smtp_config(&state.pool, &state.secret_key).await
    {
        let base_url = std::env::var("CALRS_BASE_URL").ok();
        let guest_cancel_url = cancel_token.as_ref().and_then(|t| {
            base_url
                .as_ref()
                .map(|base| format!("{}/booking/cancel/{}", base.trim_end_matches('/'), t))
        });
        let guest_reschedule_url = reschedule_token.as_ref().and_then(|t| {
            base_url
                .as_ref()
                .map(|base| format!("{}/booking/reschedule/{}", base.trim_end_matches('/'), t))
        });
        let (cancel_notice_min, reschedule_notice_min) =
            fetch_event_type_notice_minutes(&state.pool, &event_type_id).await;
        let _ = crate::email::send_guest_confirmation_ex(
            &smtp_config,
            &details,
            guest_cancel_url.as_deref(),
            guest_reschedule_url.as_deref(),
            cancel_notice_min,
            reschedule_notice_min,
        )
        .await;

        // Also send host a confirmation email (no ICS, event pushed via CalDAV)
        if let Err(e) = crate::email::send_host_booking_confirmed(&smtp_config, &details).await {
            tracing::error!(error = %e, host_email = %details.host_email, "host confirmation email failed");
        }
    }

    let tmpl = match state.templates.get_template("booking_approved.html") {
        Ok(t) => t,
        Err(e) => return internal_error_response("internal", &e),
    };
    let rendered = tmpl
        .render(context! {
            event_title,
            date_label,
            date,
            start_time,
            end_time,
            guest_name,
            guest_email,
            lang => lang,
        })
        .unwrap_or_else(|e| internal_error_body("template render", &e));

    Html(rendered).into_response()
}

async fn decline_booking_form(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> impl IntoResponse {
    let lang = crate::i18n::detect_from_headers(&headers);
    let booking: Option<(String, String, String, String, String)> = sqlx::query_as(
        "SELECT b.guest_name, b.guest_email, b.start_at, b.end_at, et.title
             FROM bookings b
             JOIN event_types et ON et.id = b.event_type_id
             WHERE b.confirm_token = ? AND b.status = 'pending'",
    )
    .bind(&token)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    let (guest_name, guest_email, start_at, end_at, event_title) = match booking {
        Some(b) => b,
        None => {
            let tmpl = match state.templates.get_template("booking_action_error.html") {
                Ok(t) => t,
                Err(e) => return internal_error_response("internal", &e),
            };
            let rendered = tmpl.render(context! {
                title => "Invalid link",
                message => "This decline link is invalid, has expired, or the booking has already been processed.",
                lang => lang,
            }).unwrap_or_else(|e| internal_error_body("template render", &e));
            return Html(rendered).into_response();
        }
    };

    let date_label = format_date_label(&start_at, lang);
    let date = start_at.get(..10).unwrap_or(&start_at).to_string();
    let start_time = extract_time_24h(&start_at);
    let end_time = extract_time_24h(&end_at);

    let tmpl = match state.templates.get_template("booking_decline_form.html") {
        Ok(t) => t,
        Err(e) => return internal_error_response("internal", &e),
    };
    let rendered = tmpl
        .render(context! {
            event_title,
            date_label,
            date,
            start_time,
            end_time,
            guest_name,
            guest_email,
            lang => lang,
        })
        .unwrap_or_else(|e| internal_error_body("template render", &e));

    Html(rendered).into_response()
}

async fn decline_booking_by_token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(token): Path<String>,
    Form(form): Form<DeclineForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }
    let lang = crate::i18n::detect_from_headers(&headers);
    let booking: Option<(
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
    )> = sqlx::query_as(
        "SELECT b.id, b.guest_name, b.guest_email, b.start_at, b.end_at, et.title, u.name, COALESCE(u.booking_email, u.email), COALESCE(b.guest_timezone, 'UTC'), et.id
             FROM bookings b
             JOIN event_types et ON et.id = b.event_type_id
             JOIN accounts a ON a.id = et.account_id
             JOIN users u ON u.id = a.user_id
             WHERE b.confirm_token = ? AND b.status = 'pending'",
    )
    .bind(&token)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    let (
        bid,
        guest_name,
        guest_email,
        start_at,
        end_at,
        event_title,
        host_name,
        host_email,
        guest_timezone,
        et_id,
    ) = match booking {
        Some(b) => b,
        None => {
            let tmpl = match state.templates.get_template("booking_action_error.html") {
                Ok(t) => t,
                Err(e) => return internal_error_response("internal", &e),
            };
            let rendered = tmpl.render(context! {
                    title => "Invalid link",
                    message => "This decline link is invalid, has expired, or the booking has already been processed.",
                    lang => lang,
                }).unwrap_or_else(|e| internal_error_body("template render", &e));
            return Html(rendered).into_response();
        }
    };

    // Decline the booking
    let _ = sqlx::query("UPDATE bookings SET status = 'declined' WHERE id = ?")
        .bind(&bid)
        .execute(&state.pool)
        .await;

    tracing::info!(booking_id = %bid, "booking declined via token");

    // Convert event-type-local stored times into the guest's tz; see #101.
    let stored_tz = get_host_tz(&state.pool, &et_id).await;
    let guest_tz_parsed = guest_timezone.parse::<Tz>().unwrap_or(Tz::UTC);
    let (date, start_time, end_time) =
        booking_strings_in_guest_tz(&start_at, &end_at, stored_tz, guest_tz_parsed);
    let date_label = format_date_label(&date, lang);

    let reason = form.reason.filter(|r| !r.trim().is_empty());

    // Send decline notification to guest
    if let Ok(Some(smtp_config)) =
        crate::email::load_smtp_config(&state.pool, &state.secret_key).await
    {
        let details = crate::email::CancellationDetails {
            event_title: event_title.clone(),
            date: date.clone(),
            start_time: start_time.clone(),
            end_time: end_time.clone(),
            guest_name: guest_name.clone(),
            guest_email: guest_email.clone(),
            guest_timezone: guest_timezone.clone(),
            host_name: host_name.clone(),
            host_email,
            uid: String::new(),
            reason: reason.clone(),
            cancelled_by_host: true,
            host_timezone: stored_tz.name().to_string(),
            ..Default::default()
        };
        let _ = crate::email::send_guest_decline_notice(&smtp_config, &details).await;
    }

    let tmpl = match state.templates.get_template("booking_declined.html") {
        Ok(t) => t,
        Err(e) => return internal_error_response("internal", &e),
    };
    let rendered = tmpl
        .render(context! {
            event_title,
            date_label,
            date,
            start_time,
            end_time,
            guest_name,
            guest_email,
            reason,
            lang => lang,
        })
        .unwrap_or_else(|e| internal_error_body("template render", &e));

    Html(rendered).into_response()
}

// --- Guest cancel booking by token ---

/// Fetch `(cancel_notice_min, reschedule_notice_min)` for an event type by
/// id. Either column may be NULL (no restriction).
async fn fetch_event_type_notice_minutes(
    pool: &SqlitePool,
    event_type_id: &str,
) -> (Option<i32>, Option<i32>) {
    sqlx::query_as::<_, (Option<i32>, Option<i32>)>(
        "SELECT cancel_notice_min, reschedule_notice_min FROM event_types WHERE id = ?",
    )
    .bind(event_type_id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
    .unwrap_or((None, None))
}

/// Look up a notice-window column on the booking's event type. Returns
/// `(notice_min, host_email)` where `notice_min` is `None`/`Some(0)` when
/// no restriction applies. The `column` argument MUST be one of the two
/// known column names — it is interpolated into SQL but never sourced from
/// the request, so this is safe.
async fn fetch_notice_min_and_host_email(
    pool: &SqlitePool,
    booking_token_column: &str,
    token: &str,
    notice_column: &str,
) -> Option<(Option<i32>, String)> {
    debug_assert!(matches!(
        notice_column,
        "cancel_notice_min" | "reschedule_notice_min"
    ));
    debug_assert!(matches!(
        booking_token_column,
        "cancel_token" | "reschedule_token"
    ));
    let sql = format!(
        "SELECT et.{notice}, COALESCE(u.booking_email, u.email) \
         FROM bookings b \
         JOIN event_types et ON et.id = b.event_type_id \
         JOIN accounts a ON a.id = et.account_id \
         JOIN users u ON u.id = a.user_id \
         WHERE b.{tok} = ?",
        notice = notice_column,
        tok = booking_token_column
    );
    sqlx::query_as::<_, (Option<i32>, String)>(&sql)
        .bind(token)
        .fetch_optional(pool)
        .await
        .unwrap_or(None)
}

/// If `notice_min` is set and the booking starts inside the notice window,
/// render the blocked page and return it. Otherwise return `None` so the
/// caller can proceed.
///
/// Note on time semantics: `start_at` is the host-local naive timestamp
/// (matching how bookings are stored elsewhere) so we compare against
/// `Local::now().naive_local()` to mirror the existing `slot_start < now +
/// Duration::minutes(min_notice as i64)` precedent in the reschedule POST
/// path.
fn check_notice_window(
    state: &AppState,
    notice_min: Option<i32>,
    start_at: &str,
    host_email: &str,
    action: &'static str,
    lang: &'static str,
) -> Option<Response> {
    let n = notice_min.unwrap_or(0);
    if n <= 0 {
        return None;
    }
    let start = match NaiveDateTime::parse_from_str(start_at, "%Y-%m-%dT%H:%M:%S") {
        Ok(dt) => dt,
        Err(_) => return None,
    };
    let cutoff = start - chrono::Duration::minutes(n as i64);
    if Local::now().naive_local() <= cutoff {
        return None;
    }
    let tmpl = match state.templates.get_template("booking_action_blocked.html") {
        Ok(t) => t,
        Err(e) => return Some(internal_error_response("internal", &e)),
    };
    let rendered = tmpl
        .render(context! {
            notice_min => n,
            host_email => host_email,
            action => action,
            lang => lang,
        })
        .unwrap_or_else(|e| internal_error_body("template render", &e));
    Some(Html(rendered).into_response())
}

async fn guest_cancel_form(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> impl IntoResponse {
    let lang = crate::i18n::detect_from_headers(&headers);
    let booking: Option<(String, String, String, String, String, String)> = sqlx::query_as(
        "SELECT b.guest_name, b.guest_email, b.start_at, b.end_at, et.title, u.name
             FROM bookings b
             JOIN event_types et ON et.id = b.event_type_id
             JOIN accounts a ON a.id = et.account_id
             JOIN users u ON u.id = a.user_id
             WHERE b.cancel_token = ? AND b.status IN ('confirmed', 'pending')",
    )
    .bind(&token)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    let (guest_name, _guest_email, start_at, end_at, event_title, host_name) = match booking {
        Some(b) => b,
        None => {
            // Check if already cancelled
            let status_row: Option<(String,)> =
                sqlx::query_as("SELECT status FROM bookings WHERE cancel_token = ?")
                    .bind(&token)
                    .fetch_optional(&state.pool)
                    .await
                    .unwrap_or(None);

            let (title, message) = match status_row {
                Some((status,)) if status == "cancelled" => (
                    "Already cancelled",
                    "This booking has already been cancelled.",
                ),
                Some((status,)) if status == "declined" => (
                    "Booking declined",
                    "This booking has been declined by the host.",
                ),
                _ => (
                    "Invalid link",
                    "This cancellation link is invalid or has expired.",
                ),
            };

            let tmpl = match state.templates.get_template("booking_action_error.html") {
                Ok(t) => t,
                Err(e) => return internal_error_response("internal", &e),
            };
            let rendered = tmpl
                .render(context! {
                    title,
                    message,
                    lang => lang,
                })
                .unwrap_or_else(|e| internal_error_body("template render", &e));
            return Html(rendered).into_response();
        }
    };

    // Block the GET form before any state mutation if the booking falls
    // inside the host's configured cancel-notice window.
    if let Some((notice_min, host_email)) =
        fetch_notice_min_and_host_email(&state.pool, "cancel_token", &token, "cancel_notice_min")
            .await
    {
        if let Some(resp) =
            check_notice_window(&state, notice_min, &start_at, &host_email, "cancel", lang)
        {
            tracing::info!(action = "cancel", "guest action blocked by notice window");
            return resp;
        }
    }

    let date_label = format_date_label(&start_at, lang);
    let date = start_at.get(..10).unwrap_or(&start_at).to_string();
    let start_time = extract_time_24h(&start_at);
    let end_time = extract_time_24h(&end_at);

    let tmpl = match state.templates.get_template("booking_cancel_form.html") {
        Ok(t) => t,
        Err(e) => return internal_error_response("internal", &e),
    };
    let rendered = tmpl
        .render(context! {
            event_title,
            date_label,
            date,
            start_time,
            end_time,
            guest_name,
            host_name,
            lang => lang,
        })
        .unwrap_or_else(|e| internal_error_body("template render", &e));

    Html(rendered).into_response()
}

async fn guest_cancel_booking(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(token): Path<String>,
    Form(form): Form<CancelForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }
    let lang = crate::i18n::detect_from_headers(&headers);
    let booking: Option<(String, String, String, String, String, String, String, String, String, String, String)> =
        sqlx::query_as(
            "SELECT b.id, b.uid, b.guest_name, b.guest_email, b.start_at, b.end_at, et.title, u.name, COALESCE(u.booking_email, u.email), COALESCE(b.guest_timezone, 'UTC'), et.id
             FROM bookings b
             JOIN event_types et ON et.id = b.event_type_id
             JOIN accounts a ON a.id = et.account_id
             JOIN users u ON u.id = a.user_id
             WHERE b.cancel_token = ? AND b.status IN ('confirmed', 'pending')",
        )
        .bind(&token)
        .fetch_optional(&state.pool)
        .await
        .unwrap_or(None);

    let (
        bid,
        uid,
        guest_name,
        guest_email,
        start_at,
        end_at,
        event_title,
        host_name,
        host_email,
        guest_timezone,
        et_id,
    ) = match booking {
        Some(b) => b,
        None => {
            let tmpl = match state.templates.get_template("booking_action_error.html") {
                Ok(t) => t,
                Err(e) => return internal_error_response("internal", &e),
            };
            let rendered = tmpl
                    .render(context! {
                        title => "Invalid link",
                        message => "This cancellation link is invalid, has expired, or the booking has already been cancelled.",
                        lang => lang,
                    })
                    .unwrap_or_else(|e| internal_error_body("template render", &e));
            return Html(rendered).into_response();
        }
    };

    // Defensive notice-window check on POST too: the GET may have been
    // cached, or the cutoff may have rolled over between page load and
    // submit. Either way, never mutate state inside the blocked window.
    if let Some((notice_min, _)) =
        fetch_notice_min_and_host_email(&state.pool, "cancel_token", &token, "cancel_notice_min")
            .await
    {
        if let Some(resp) =
            check_notice_window(&state, notice_min, &start_at, &host_email, "cancel", lang)
        {
            tracing::info!(
                action = "cancel",
                booking_id = %bid,
                "guest action blocked by notice window (POST)"
            );
            return resp;
        }
    }

    // Cancel the booking
    let _ = sqlx::query("UPDATE bookings SET status = 'cancelled' WHERE id = ?")
        .bind(&bid)
        .execute(&state.pool)
        .await;

    tracing::info!(booking_id = %bid, "booking cancelled by guest");

    // Find the host user_id for CalDAV delete
    let host_user_id: Option<String> = sqlx::query_scalar(
        "SELECT a.user_id FROM accounts a JOIN event_types et ON et.account_id = a.id JOIN bookings b ON b.event_type_id = et.id WHERE b.id = ?",
    )
    .bind(&bid)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    // Delete from CalDAV calendar
    if let Some(user_id) = &host_user_id {
        caldav_delete_booking(&state.pool, &state.secret_key, user_id, &uid).await;
    }

    // Convert event-type-local stored times into the guest's tz; see #101.
    let stored_tz = get_host_tz(&state.pool, &et_id).await;
    let guest_tz_parsed = guest_timezone.parse::<Tz>().unwrap_or(Tz::UTC);
    let (date, start_time, end_time) =
        booking_strings_in_guest_tz(&start_at, &end_at, stored_tz, guest_tz_parsed);
    let date_label = format_date_label(&date, lang);

    let reason = form.reason.filter(|r| !r.trim().is_empty());

    // Send cancellation emails
    if let Ok(Some(smtp_config)) =
        crate::email::load_smtp_config(&state.pool, &state.secret_key).await
    {
        let details = crate::email::CancellationDetails {
            event_title: event_title.clone(),
            date: date.clone(),
            start_time: start_time.clone(),
            end_time: end_time.clone(),
            guest_name: guest_name.clone(),
            guest_email: guest_email.clone(),
            guest_timezone,
            host_name: host_name.clone(),
            host_email,
            uid,
            reason: reason.clone(),
            cancelled_by_host: false,
            // Guest is the one cancelling; their browser language now is the
            // best signal we have (they chose this language to view the form).
            guest_language: Some(lang.to_string()),
            host_timezone: stored_tz.name().to_string(),
            ..Default::default()
        };

        let _ = crate::email::send_guest_cancellation(&smtp_config, &details).await;
        let _ = crate::email::send_host_cancellation(&smtp_config, &details).await;
    }

    let tmpl = match state.templates.get_template("booking_cancelled_guest.html") {
        Ok(t) => t,
        Err(e) => return internal_error_response("internal", &e),
    };
    let rendered = tmpl
        .render(context! {
            event_title,
            date_label,
            date,
            start_time,
            end_time,
            host_name,
            reason,
            lang => lang,
        })
        .unwrap_or_else(|e| internal_error_body("template render", &e));

    Html(rendered).into_response()
}

// --- Reschedule handlers ---

#[derive(Deserialize)]
struct RescheduleQuery {
    #[serde(default)]
    date: Option<String>,
    #[serde(default)]
    time: Option<String>,
    #[serde(default)]
    tz: Option<String>,
    #[serde(default)]
    month: Option<String>,
}

#[derive(Deserialize)]
struct RescheduleForm {
    _csrf: Option<String>,
    date: String,
    time: String,
    #[serde(default)]
    tz: Option<String>,
}

/// Guest reschedule: show slot picker or confirmation page
async fn guest_reschedule_slots(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(token): Path<String>,
    Query(query): Query<RescheduleQuery>,
) -> impl IntoResponse {
    let lang = crate::i18n::detect_from_headers(&headers);
    // Look up booking by reschedule_token
    let booking: Option<(String, String, String, String, String, String)> = sqlx::query_as(
        "SELECT b.id, b.guest_name, b.start_at, b.end_at, b.event_type_id, b.uid
             FROM bookings b
             WHERE b.reschedule_token = ? AND b.status IN ('confirmed', 'pending')",
    )
    .bind(&token)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    let (booking_id, _guest_name, start_at, end_at, et_id_raw, _uid) = match booking {
        Some(b) => b,
        None => {
            let tmpl = match state.templates.get_template("booking_action_error.html") {
                Ok(t) => t,
                Err(e) => return internal_error_response("internal", &e),
            };
            let rendered = tmpl.render(context! {
                title => "Invalid link",
                message => "This reschedule link is invalid, has expired, or the booking has already been processed.",
                lang => lang,
            }).unwrap_or_else(|e| internal_error_body("template render", &e));
            return Html(rendered).into_response();
        }
    };

    // Block the slot picker before any costly work (CalDAV sync, slot
    // computation, template render) if the booking falls inside the host's
    // configured reschedule-notice window.
    if let Some((notice_min, host_email)) = fetch_notice_min_and_host_email(
        &state.pool,
        "reschedule_token",
        &token,
        "reschedule_notice_min",
    )
    .await
    {
        if let Some(resp) = check_notice_window(
            &state,
            notice_min,
            &start_at,
            &host_email,
            "reschedule",
            lang,
        ) {
            tracing::info!(
                action = "reschedule",
                booking_id = %booking_id,
                "guest action blocked by notice window"
            );
            return resp;
        }
    }

    // Fetch event type + host details
    let et_info: Option<(
        String,
        String,
        i32,
        i32,
        i32,
        i32,
        Option<String>,
        Option<String>,
        String,
        String,
        Option<String>,
        Option<String>,
        String,
    )> = sqlx::query_as(
        "SELECT et.id, et.slug, et.duration_min, et.buffer_before, et.buffer_after,
                    et.min_notice_min, et.location_type, et.location_value,
                    u.id, u.name, u.title, u.avatar_path, et.default_calendar_view
             FROM event_types et
             JOIN accounts a ON a.id = et.account_id
             JOIN users u ON u.id = a.user_id
             WHERE et.id = ?",
    )
    .bind(&et_id_raw)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    let (
        et_id,
        et_slug,
        duration,
        buf_before,
        buf_after,
        min_notice,
        loc_type,
        loc_value,
        host_user_id,
        host_name,
        host_title,
        host_avatar_path,
        default_calendar_view,
    ) = match et_info {
        Some(e) => e,
        None => return Html("Event type not found.".to_string()).into_response(),
    };

    let et_title: String = sqlx::query_scalar("SELECT title FROM event_types WHERE id = ?")
        .bind(&et_id)
        .fetch_one(&state.pool)
        .await
        .unwrap_or_default();

    let old_date_label = format_date_label(&start_at, lang);
    let old_start_time = extract_time_24h(&start_at);
    let old_end_time = extract_time_24h(&end_at);
    let old_date = start_at.get(..10).unwrap_or(&start_at).to_string();

    // If date + time + tz are present, show confirmation page
    if let (Some(date), Some(time)) = (&query.date, &query.time) {
        let guest_tz = parse_guest_tz(query.tz.as_deref());
        let new_date = match NaiveDate::parse_from_str(date, "%Y-%m-%d") {
            Ok(d) => d,
            Err(_) => return Html("Invalid date.".to_string()).into_response(),
        };
        let new_time = match NaiveTime::parse_from_str(time, "%H:%M") {
            Ok(t) => t,
            Err(_) => return Html("Invalid time.".to_string()).into_response(),
        };
        let new_end = new_date.and_time(new_time) + Duration::minutes(duration as i64);
        let new_date_label = crate::i18n::format_long_date(new_date, lang);
        let new_start_time_str = new_time.format("%H:%M").to_string();
        let new_end_time_str = new_end.time().format("%H:%M").to_string();

        let back_url = format!("/booking/reschedule/{}?tz={}", token, guest_tz.name());

        let tmpl = match state
            .templates
            .get_template("booking_reschedule_confirm.html")
        {
            Ok(t) => t,
            Err(e) => return internal_error_response("internal", &e),
        };
        let rendered = tmpl
            .render(context! {
                event_title => et_title,
                old_date_label => old_date_label,
                old_start_time => old_start_time,
                old_end_time => old_end_time,
                new_date_label => new_date_label,
                new_start_time => new_start_time_str,
                new_end_time => new_end_time_str,
                host_name => host_name,
                date => date,
                time => time,
                tz => guest_tz.name(),
                back_url => back_url,
                company_link => state.company_link.read().await.clone(),
                lang => lang,
            })
            .unwrap_or_else(|e| internal_error_body("template render", &e));
        return Html(rendered).into_response();
    }

    // Show slot picker with reschedule context
    crate::commands::sync::sync_if_stale(&state.pool, &state.secret_key, &host_user_id).await;

    let guest_tz = parse_guest_tz(query.tz.as_deref());
    let host_tz = get_host_tz(&state.pool, &et_id).await;
    let guest_tz_name = guest_tz.name().to_string();

    let (year, month) = parse_month_param(query.month.as_deref(), guest_tz);
    let (
        start_offset,
        days_ahead,
        month_label,
        prev_month,
        next_month,
        first_weekday,
        days_in_month,
        today_date,
        month_year,
    ) = build_month_params(year, month, host_tz, guest_tz, lang);

    let now_host = Utc::now().with_timezone(&host_tz).naive_local();
    let end_date = now_host.date() + Duration::days((start_offset + days_ahead) as i64);
    let window_end = end_date.and_hms_opt(23, 59, 59).unwrap_or(now_host);
    let busy = BusySource::Individual(
        fetch_busy_times_for_user_ex(
            &state.pool,
            &host_user_id,
            now_host,
            window_end,
            host_tz,
            Some(&et_id),
            Some(&booking_id),
        )
        .await,
    );
    let slot_days = compute_slots(
        &state.pool,
        &et_id,
        duration,
        buf_before,
        buf_after,
        min_notice,
        start_offset,
        days_ahead,
        host_tz,
        guest_tz,
        busy,
    )
    .await;

    let days_ctx: Vec<minijinja::Value> = slot_days.iter().map(|d| {
        let slots: Vec<minijinja::Value> = d.slots.iter().map(|s| {
            context! { start => s.start, end => s.end, host_date => s.host_date, host_time => s.host_time, guest_date => s.guest_date }
        }).collect();
        context! { date => d.date, label => d.label, slots => slots }
    }).collect();
    let available_dates: Vec<String> = slot_days.iter().map(|d| d.date.clone()).collect();

    let tz_options: Vec<minijinja::Value> = common_timezones_with(&guest_tz_name)
        .iter()
        .map(|(iana, label)| {
            context! { value => iana, label => label, selected => (*iana == guest_tz_name) }
        })
        .collect();

    let reschedule_base = format!("/booking/reschedule/{}", token);

    let (meeting_jitsi_label, meeting_webhook_label) = meeting_provider_labels(&state).await;
    let tmpl = match state.templates.get_template("slots.html") {
        Ok(t) => t,
        Err(e) => return internal_error_response("internal", &e),
    };
    let rendered = tmpl
        .render(context! {
            meeting_jitsi_label => meeting_jitsi_label,
            meeting_webhook_label => meeting_webhook_label,
            event_type => context! {
                slug => et_slug,
                title => et_title.clone(),
                description => Option::<String>::None,
                duration_min => duration,
                location_type => loc_type,
                location_value => loc_value,
            },
            host_name => host_name,
            host_title => host_title.as_deref().unwrap_or(""),
            host_user_id => host_user_id,
            host_has_avatar => host_avatar_path.is_some(),
            host_initials => compute_initials(&host_name),
            days => days_ctx,
            available_dates => available_dates,
            month_label => month_label,
            month_year => month_year,
            prev_month => prev_month,
            next_month => next_month,
            first_weekday => first_weekday,
            days_in_month => days_in_month,
            today_date => today_date,
            guest_tz => guest_tz_name,
            tz_options => tz_options,
            reschedule_base => reschedule_base,
            reschedule_info => context! {
                event_title => et_title,
                old_date => old_date,
                old_time => old_start_time,
            },
            default_calendar_view => default_calendar_view,
            company_link => state.company_link.read().await.clone(),
            lang => lang,
        })
        .unwrap_or_else(|e| internal_error_body("template render", &e));

    Html(rendered).into_response()
}

/// Guest reschedule: process the reschedule
async fn guest_reschedule_booking(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(token): Path<String>,
    Form(form): Form<RescheduleForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }
    let lang = crate::i18n::detect_from_headers(&headers);
    // Rate limit
    let client_ip = client_ip_for_rate_limit(&headers);
    if state.booking_limiter.check_limited(&client_ip).await {
        return Html("Too many requests. Please try again later.".to_string()).into_response();
    }

    let booking: Option<(
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        i32,
        Option<String>,
        Option<String>,
        Option<String>,
        i32,
        i32,
    )> = sqlx::query_as(
        "SELECT b.id, b.uid, b.guest_name, b.guest_email, b.start_at, b.end_at,
                    et.id, et.title, u.id, u.name, et.duration_min,
                    COALESCE(NULLIF(b.meeting_url, ''), et.location_value),
                    b.caldav_calendar_href, COALESCE(b.guest_timezone, 'UTC'),
                    et.min_notice_min, b.reschedule_by_host
             FROM bookings b
             JOIN event_types et ON et.id = b.event_type_id
             JOIN accounts a ON a.id = et.account_id
             JOIN users u ON u.id = a.user_id
             WHERE b.reschedule_token = ? AND b.status IN ('confirmed', 'pending')",
    )
    .bind(&token)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    let (
        booking_id,
        uid,
        guest_name,
        guest_email,
        old_start_at,
        old_end_at,
        et_id,
        et_title,
        host_user_id,
        host_name,
        duration,
        loc_value,
        caldav_href,
        _guest_timezone_str,
        min_notice,
        reschedule_by_host,
    ) = match booking {
        Some(b) => b,
        None => {
            let tmpl = match state.templates.get_template("booking_action_error.html") {
                Ok(t) => t,
                Err(e) => return internal_error_response("internal", &e),
            };
            let rendered = tmpl.render(context! {
                title => "Invalid link",
                message => "This reschedule link is invalid, has expired, or the booking has already been processed.",
                lang => lang,
            }).unwrap_or_else(|e| internal_error_body("template render", &e));
            return Html(rendered).into_response();
        }
    };

    // Defensive notice-window check on POST too: the GET may have been
    // cached, or the cutoff may have rolled over between page load and
    // submit. Either way, never mutate state inside the blocked window.
    if let Some((notice_min, host_email)) = fetch_notice_min_and_host_email(
        &state.pool,
        "reschedule_token",
        &token,
        "reschedule_notice_min",
    )
    .await
    {
        if let Some(resp) = check_notice_window(
            &state,
            notice_min,
            &old_start_at,
            &host_email,
            "reschedule",
            lang,
        ) {
            tracing::info!(
                action = "reschedule",
                booking_id = %booking_id,
                "guest action blocked by notice window (POST)"
            );
            return resp;
        }
    }

    let date = match NaiveDate::parse_from_str(&form.date, "%Y-%m-%d") {
        Ok(d) => d,
        Err(_) => return Html("Invalid date.".to_string()).into_response(),
    };
    if let Err(e) = validate_date_not_too_far(date) {
        return Html(e).into_response();
    }
    let start_time = match NaiveTime::parse_from_str(&form.time, "%H:%M") {
        Ok(t) => t,
        Err(_) => return Html("Invalid time.".to_string()).into_response(),
    };

    let guest_tz = parse_guest_tz(form.tz.as_deref());
    let new_guest_timezone = guest_tz.name().to_string();
    let host_tz = get_host_tz(&state.pool, &et_id).await;

    // The URL carries guest-local date/time; convert to host-local for storage
    // and availability checks (existing semantics).
    let guest_local_start = date.and_time(start_time);
    let guest_local_end = guest_local_start + Duration::minutes(duration as i64);
    let slot_start = guest_to_host_local(guest_local_start, guest_tz, host_tz);
    let slot_end = slot_start + Duration::minutes(duration as i64);
    let guest_end_time = guest_local_end.time().format("%H:%M").to_string();

    let now = Local::now().naive_local();
    if slot_start < now + Duration::minutes(min_notice as i64) {
        return Html("This slot is no longer available (too soon).".to_string()).into_response();
    }

    // Check conflicts excluding this booking
    let busy = fetch_busy_times_for_user_ex(
        &state.pool,
        &host_user_id,
        slot_start,
        slot_end,
        host_tz,
        Some(&et_id),
        Some(&booking_id),
    )
    .await;
    if has_conflict(&busy, slot_start, slot_end) {
        return Html("This slot is no longer available.".to_string()).into_response();
    }

    let new_start_at = slot_start.format("%Y-%m-%dT%H:%M:%S").to_string();
    let new_end_at = slot_end.format("%Y-%m-%dT%H:%M:%S").to_string();
    let new_reschedule_token = uuid::Uuid::new_v4().to_string();
    let new_cancel_token = uuid::Uuid::new_v4().to_string();
    let new_confirm_token = uuid::Uuid::new_v4().to_string();

    // Check if the event type requires confirmation
    let requires_confirmation: i32 =
        sqlx::query_scalar("SELECT requires_confirmation FROM event_types WHERE id = ?")
            .bind(&et_id)
            .fetch_one(&state.pool)
            .await
            .unwrap_or(0);

    // Determine new status:
    // - Host-initiated reschedule → confirmed (host already approved)
    // - Guest-initiated + requires_confirmation → pending (needs host approval)
    // - Guest-initiated + no confirmation needed → confirmed (auto-approved)
    let host_initiated = reschedule_by_host != 0;
    let needs_approval = !host_initiated && requires_confirmation != 0;
    let new_status = if needs_approval {
        "pending"
    } else {
        "confirmed"
    };
    let new_confirm = if needs_approval {
        Some(new_confirm_token.clone())
    } else {
        None
    };

    let _ = sqlx::query(
        "UPDATE bookings SET start_at = ?, end_at = ?, status = ?,
                reschedule_token = ?, cancel_token = ?, confirm_token = ?,
                reminder_sent_at = NULL, guest_timezone = ?, reschedule_by_host = 0
         WHERE id = ?",
    )
    .bind(&new_start_at)
    .bind(&new_end_at)
    .bind(new_status)
    .bind(&new_reschedule_token)
    .bind(&new_cancel_token)
    .bind(&new_confirm)
    .bind(&new_guest_timezone)
    .bind(&booking_id)
    .execute(&state.pool)
    .await;

    if host_initiated {
        tracing::info!(booking_id = %booking_id, old_start = %old_start_at, new_start = %new_start_at, "booking rescheduled by guest (host-initiated, confirmed)");
    } else if needs_approval {
        tracing::info!(booking_id = %booking_id, old_start = %old_start_at, new_start = %new_start_at, "booking rescheduled by guest (now pending, needs approval)");
    } else {
        tracing::info!(booking_id = %booking_id, old_start = %old_start_at, new_start = %new_start_at, "booking rescheduled by guest (auto-confirmed)");
    }

    let host_email: String =
        sqlx::query_scalar("SELECT COALESCE(booking_email, email) FROM users WHERE id = ?")
            .bind(&host_user_id)
            .fetch_one(&state.pool)
            .await
            .unwrap_or_default();

    // old_start_at/old_end_at are stored in the event-type tz. Convert into the
    // guest's tz so `RescheduleDetails` carries guest-local wall-clock for
    // both the OLD and NEW times — matches the contract used elsewhere and
    // lets `host_time_display` correctly recover the host wall-clock.
    let (old_date, old_start_time, old_end_time) =
        booking_strings_in_guest_tz(&old_start_at, &old_end_at, host_tz, guest_tz);

    if needs_approval {
        // Guest-initiated reschedule on requires_confirmation event → pending.
        // Delete the prior CalDAV event (it will be re-pushed if/when the host approves),
        // and clear caldav_calendar_href on the booking so the sync orphan sweep does not
        // race the approval flow and cancel this pending booking before the host clicks
        // approve. See cancel_orphaned_bookings in src/commands/sync.rs.
        if caldav_href.is_some() {
            caldav_delete_for_user(&state.pool, &state.secret_key, &host_user_id, &uid).await;
            let _ = sqlx::query("UPDATE bookings SET caldav_calendar_href = NULL WHERE id = ?")
                .bind(&booking_id)
                .execute(&state.pool)
                .await;
        }

        if let Ok(Some(smtp_config)) =
            crate::email::load_smtp_config(&state.pool, &state.secret_key).await
        {
            let base_url = std::env::var("CALRS_BASE_URL").ok();

            // Send host reschedule approval request
            let reschedule_details = crate::email::RescheduleDetails {
                event_title: et_title.clone(),
                old_date,
                old_start_time,
                old_end_time,
                new_date: form.date.clone(),
                new_start_time: form.time.clone(),
                new_end_time: guest_end_time.clone(),
                guest_name: guest_name.clone(),
                guest_email: guest_email.clone(),
                guest_timezone: new_guest_timezone.clone(),
                host_name: host_name.clone(),
                host_email,
                uid: uid.clone(),
                location: loc_value.clone(),
                host_timezone: host_tz.name().to_string(),
            };
            let _ = crate::email::send_host_reschedule_request(
                &smtp_config,
                &reschedule_details,
                Some(&new_confirm_token),
                base_url.as_deref(),
            )
            .await;

            // Send guest pending notice with new tokens
            let guest_cancel_url = base_url.as_ref().map(|base| {
                format!(
                    "{}/booking/cancel/{}",
                    base.trim_end_matches('/'),
                    new_cancel_token
                )
            });
            let guest_reschedule_url = base_url.as_ref().map(|base| {
                format!(
                    "{}/booking/reschedule/{}",
                    base.trim_end_matches('/'),
                    new_reschedule_token
                )
            });
            let pending_details = crate::email::BookingDetails {
                event_title: et_title.clone(),
                date: form.date.clone(),
                start_time: form.time.clone(),
                end_time: guest_end_time.clone(),
                guest_name: guest_name.clone(),
                guest_email: guest_email.clone(),
                guest_timezone: new_guest_timezone,
                host_name: host_name.clone(),
                host_email: String::new(),
                uid,
                notes: None,
                location: loc_value,
                reminder_minutes: None,
                additional_attendees: vec![],
                host_timezone: host_tz.name().to_string(),
                ..Default::default()
            };
            let _ = crate::email::send_guest_pending_notice_ex(
                &smtp_config,
                &pending_details,
                guest_cancel_url.as_deref(),
                guest_reschedule_url.as_deref(),
            )
            .await;
        }
    } else {
        // Confirmed reschedule (host-initiated or guest on non-confirmation event)
        // Push updated event to CalDAV
        let push_details = crate::email::BookingDetails {
            event_title: et_title.clone(),
            date: form.date.clone(),
            start_time: form.time.clone(),
            end_time: guest_end_time.clone(),
            guest_name: guest_name.clone(),
            guest_email: guest_email.clone(),
            guest_timezone: new_guest_timezone.clone(),
            host_name: host_name.clone(),
            host_email: host_email.clone(),
            uid: uid.clone(),
            notes: None,
            location: loc_value.clone(),
            reminder_minutes: None,
            additional_attendees: vec![],
            host_timezone: host_tz.name().to_string(),
            ..Default::default()
        };
        caldav_push_booking(
            &state.pool,
            &state.secret_key,
            &host_user_id,
            &uid,
            &push_details,
        )
        .await;

        if let Ok(Some(smtp_config)) =
            crate::email::load_smtp_config(&state.pool, &state.secret_key).await
        {
            let base_url = std::env::var("CALRS_BASE_URL").ok();
            let guest_cancel_url = base_url.as_ref().map(|base| {
                format!(
                    "{}/booking/cancel/{}",
                    base.trim_end_matches('/'),
                    new_cancel_token
                )
            });
            let guest_reschedule_url = base_url.as_ref().map(|base| {
                format!(
                    "{}/booking/reschedule/{}",
                    base.trim_end_matches('/'),
                    new_reschedule_token
                )
            });

            // Notify guest with confirmation + ICS
            let _ = crate::email::send_guest_reschedule_notification(
                &smtp_config,
                &crate::email::RescheduleDetails {
                    event_title: et_title.clone(),
                    old_date,
                    old_start_time,
                    old_end_time,
                    new_date: form.date.clone(),
                    new_start_time: form.time.clone(),
                    new_end_time: guest_end_time.clone(),
                    guest_name: guest_name.clone(),
                    guest_email: guest_email.clone(),
                    guest_timezone: new_guest_timezone,
                    host_name: host_name.clone(),
                    host_email: host_email.clone(),
                    uid,
                    location: loc_value,
                    host_timezone: host_tz.name().to_string(),
                },
                guest_cancel_url.as_deref(),
                guest_reschedule_url.as_deref(),
            )
            .await;

            // Notify host
            let _ = crate::email::send_host_booking_confirmed(&smtp_config, &push_details).await;
        }
    }

    let date_label = crate::i18n::format_long_date(date, lang);
    let (cancel_notice_min, reschedule_notice_min) =
        fetch_event_type_notice_minutes(&state.pool, &et_id).await;

    let tmpl = match state.templates.get_template("confirmed.html") {
        Ok(t) => t,
        Err(e) => return internal_error_response("internal", &e),
    };
    let rendered = tmpl
        .render(context! {
            event_title => et_title,
            date_label => date_label,
            time_start => form.time,
            time_end => guest_end_time,
            host_name => host_name,
            guest_email => guest_email,
            pending => needs_approval,
            rescheduled => true,
            cancel_notice_min => cancel_notice_min,
            reschedule_notice_min => reschedule_notice_min,
            company_link => state.company_link.read().await.clone(),
            lang => lang,
        })
        .unwrap_or_else(|e| internal_error_body("template render", &e));

    Html(rendered).into_response()
}

/// Host reschedule: send the guest a link to pick a new time.
/// GET shows a confirmation page, POST sends the email.
async fn host_reschedule_slots(
    State(state): State<Arc<AppState>>,
    auth_user: crate::auth::AuthUser,
    Path(booking_id): Path<String>,
) -> impl IntoResponse {
    let user = &auth_user.user;
    // Dashboard handler: no Accept-Language available, so honour the user's
    // saved preference and fall back to English. Once the dashboard is
    // translated this should switch to crate::i18n::resolve(...).
    let lang = user.language.as_deref().unwrap_or("en");

    let booking: Option<(String, String, String, String, String, String)> = sqlx::query_as(
        "SELECT b.id, b.guest_name, b.guest_email, b.start_at, b.end_at, et.title
         FROM bookings b
         JOIN event_types et ON et.id = b.event_type_id
         JOIN accounts a ON a.id = et.account_id
         WHERE b.id = ? AND a.user_id = ? AND b.status IN ('confirmed', 'pending')",
    )
    .bind(&booking_id)
    .bind(&user.id)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    let (bid, guest_name, guest_email, start_at, end_at, event_title) = match booking {
        Some(b) => b,
        None => return Redirect::to("/dashboard/bookings").into_response(),
    };

    let date_label = format_date_label(&start_at, lang);
    let start_time = extract_time_24h(&start_at);
    let end_time = extract_time_24h(&end_at);

    let tmpl = match state.templates.get_template("booking_host_reschedule.html") {
        Ok(t) => t,
        Err(e) => return internal_error_response("internal", &e),
    };
    let rendered = tmpl
        .render(context! {
            sidebar => sidebar_context(&auth_user, "bookings"),
            booking_id => bid,
            event_title => event_title,
            guest_name => guest_name,
            guest_email => guest_email,
            date_label => date_label,
            start_time => start_time,
            end_time => end_time,
        })
        .unwrap_or_else(|e| internal_error_body("template render", &e));

    Html(rendered).into_response()
}

/// Host reschedule: set reschedule_by_host flag, regenerate token, email guest
async fn host_reschedule_booking(
    State(state): State<Arc<AppState>>,
    auth_user: crate::auth::AuthUser,
    headers: HeaderMap,
    Path(booking_id): Path<String>,
    Form(form): Form<CancelForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }
    let user = &auth_user.user;

    let booking: Option<(
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
    )> = sqlx::query_as(
        "SELECT b.id, b.uid, b.guest_name, b.guest_email, b.start_at, b.end_at,
                    et.title, COALESCE(b.guest_timezone, 'UTC'), et.id
             FROM bookings b
             JOIN event_types et ON et.id = b.event_type_id
             JOIN accounts a ON a.id = et.account_id
             WHERE b.id = ? AND a.user_id = ? AND b.status IN ('confirmed', 'pending')",
    )
    .bind(&booking_id)
    .bind(&user.id)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    let (bid, _uid, guest_name, guest_email, start_at, end_at, event_title, guest_timezone, et_id) =
        match booking {
            Some(b) => b,
            None => return Redirect::to("/dashboard/bookings").into_response(),
        };

    // Generate new reschedule token and set the host-initiated flag
    let new_reschedule_token = uuid::Uuid::new_v4().to_string();
    let _ = sqlx::query(
        "UPDATE bookings SET reschedule_token = ?, reschedule_by_host = 1 WHERE id = ?",
    )
    .bind(&new_reschedule_token)
    .bind(&bid)
    .execute(&state.pool)
    .await;

    tracing::info!(booking_id = %bid, guest = %guest_email, "host requested reschedule — guest will pick new time");

    // Send email to guest asking them to pick a new time
    if let Ok(Some(smtp_config)) =
        crate::email::load_smtp_config(&state.pool, &state.secret_key).await
    {
        let base_url = std::env::var("CALRS_BASE_URL").ok();
        let reschedule_url = base_url.as_ref().map(|base| {
            format!(
                "{}/booking/reschedule/{}",
                base.trim_end_matches('/'),
                new_reschedule_token
            )
        });
        let cancel_url: Option<String> =
            sqlx::query_scalar("SELECT cancel_token FROM bookings WHERE id = ?")
                .bind(&bid)
                .fetch_optional(&state.pool)
                .await
                .unwrap_or(None)
                .and_then(|t: String| {
                    base_url
                        .as_ref()
                        .map(|base| format!("{}/booking/cancel/{}", base.trim_end_matches('/'), t))
                });

        // start_at/end_at are stored in the event-type tz (see #101). Convert
        // into the guest's tz before populating BookingDetails so the
        // guest-facing "pick new time" email shows their wall-clock with their
        // tz label.
        let host_tz = get_host_tz(&state.pool, &et_id).await;
        let guest_tz_parsed = guest_timezone.parse::<Tz>().unwrap_or(Tz::UTC);
        let (date, start_time, end_time) =
            booking_strings_in_guest_tz(&start_at, &end_at, host_tz, guest_tz_parsed);

        let details = crate::email::BookingDetails {
            event_title,
            date,
            start_time,
            end_time,
            guest_name,
            guest_email,
            guest_timezone,
            host_name: user.name.clone(),
            host_email: user
                .booking_email
                .clone()
                .unwrap_or_else(|| user.email.clone()),
            uid: String::new(),
            notes: None,
            location: None,
            reminder_minutes: None,
            additional_attendees: vec![],
            host_timezone: host_tz.name().to_string(),
            ..Default::default()
        };

        if let Some(url) = &reschedule_url {
            let _ = crate::email::send_guest_pick_new_time(
                &smtp_config,
                &details,
                url,
                cancel_url.as_deref(),
            )
            .await;
        }
    }

    Redirect::to("/dashboard/bookings").into_response()
}

// --- CalDAV write-back ---

/// Push a confirmed booking to the host's CalDAV calendar.
/// Finds the first CalDAV source with a write_calendar_href set for this user,
/// generates the ICS, and PUTs it to the CalDAV server.
async fn caldav_push_booking(
    pool: &SqlitePool,
    key: &[u8; 32],
    user_id: &str,
    booking_uid: &str,
    details: &crate::email::BookingDetails,
) {
    // Find all sources with write_calendar_href configured for this user
    let sources: Vec<(
        String,
        String,
        String,
        Option<String>,
        String,
        String,
        Option<String>,
        Option<String>,
        String,
    )> = sqlx::query_as(
        "SELECT cs.id, cs.url, cs.username, cs.password_enc, cs.write_calendar_href, cs.auth_type, cs.access_token_enc, cs.token_expires_at, cs.provider_type
         FROM caldav_sources cs
         JOIN accounts a ON a.id = cs.account_id
         WHERE a.user_id = ? AND cs.enabled = 1 AND cs.write_calendar_href IS NOT NULL",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    if sources.is_empty() {
        // Distinguish "user has no sources" (debug) from "user has sources but none
        // are write-configured" (warn). The second case is almost always a misconfig.
        let unconfigured: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM caldav_sources cs
             JOIN accounts a ON a.id = cs.account_id
             WHERE a.user_id = ? AND cs.enabled = 1 AND cs.write_calendar_href IS NULL",
        )
        .bind(user_id)
        .fetch_one(pool)
        .await
        .unwrap_or(0);

        if unconfigured > 0 {
            tracing::warn!(
                user_id = %user_id,
                uid = %booking_uid,
                unconfigured_sources = unconfigured,
                "calendar write-back skipped: booking confirmed but no source has a write calendar selected. Pick one at /dashboard/sources",
            );
        } else {
            tracing::debug!(user_id = %user_id, "calendar write-back skipped: no enabled sources for user");
        }
        return;
    }

    let ics = crate::email::generate_ics(details, "");

    for (
        source_id,
        url,
        username,
        password_enc,
        calendar_href,
        auth_type,
        access_token_enc,
        token_expires_at,
        provider_type,
    ) in &sources
    {
        tracing::debug!(uid = %booking_uid, calendar_href = %calendar_href, provider = %provider_type, "pushing booking to calendar");

        let put_result = if provider_type == crate::providers::factory::kinds::EWS {
            let enc = match password_enc.as_deref() {
                Some(e) => e,
                None => {
                    tracing::error!(url = %url, "calendar write-back failed: EWS source missing password");
                    continue;
                }
            };
            let password = match crate::crypto::decrypt_password(key, enc) {
                Ok(p) => p,
                Err(e) => {
                    tracing::error!(url = %url, error = %e, "calendar write-back failed: could not decrypt credentials");
                    continue;
                }
            };
            let client = match crate::providers::build_provider(
                provider_type,
                url,
                username,
                &password,
            ) {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!(url = %url, error = %e, "calendar write-back failed: unknown provider");
                    continue;
                }
            };
            client.put_event(calendar_href, booking_uid, &ics).await
        } else {
            let client = match crate::oauth2_caldav::build_client_for_source(
                pool,
                key,
                source_id,
                url,
                auth_type,
                username,
                password_enc.as_deref(),
                access_token_enc.as_deref(),
                token_expires_at.as_deref(),
            )
            .await
            {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!(url = %url, error = %e, "calendar write-back failed: could not build client");
                    continue;
                }
            };
            client.put_event(calendar_href, booking_uid, &ics).await
        };

        if let Err(e) = put_result {
            tracing::error!(uid = %booking_uid, calendar_href = %calendar_href, error = %e, "calendar write-back failed");
            continue;
        }

        tracing::info!(uid = %booking_uid, calendar_href = %calendar_href, "calendar write-back succeeded");

        // Record which calendar href the booking was pushed to (last successful one)
        let _ = sqlx::query("UPDATE bookings SET caldav_calendar_href = ? WHERE uid = ?")
            .bind(calendar_href)
            .bind(booking_uid)
            .execute(pool)
            .await;
    }
}

/// Delete a booking from a user's CalDAV calendar by looking up their write-enabled source directly.
/// Used for team bookings where we don't track per-booking caldav_calendar_href.
async fn caldav_delete_for_user(
    pool: &SqlitePool,
    key: &[u8; 32],
    user_id: &str,
    booking_uid: &str,
) {
    let sources: Vec<(
        String,
        String,
        String,
        Option<String>,
        String,
        String,
        Option<String>,
        Option<String>,
        String,
    )> = sqlx::query_as(
        "SELECT cs.id, cs.url, cs.username, cs.password_enc, cs.write_calendar_href, cs.auth_type, cs.access_token_enc, cs.token_expires_at, cs.provider_type
         FROM caldav_sources cs
         JOIN accounts a ON a.id = cs.account_id
         WHERE a.user_id = ? AND cs.enabled = 1 AND cs.write_calendar_href IS NOT NULL",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    for (
        source_id,
        url,
        username,
        password_enc,
        calendar_href,
        auth_type,
        access_token_enc,
        token_expires_at,
        provider_type,
    ) in &sources
    {
        let delete_result = if provider_type == crate::providers::factory::kinds::EWS {
            let enc = match password_enc.as_deref() {
                Some(e) => e,
                None => continue,
            };
            let password = match crate::crypto::decrypt_password(key, enc) {
                Ok(p) => p,
                Err(_) => continue,
            };
            let client =
                match crate::providers::build_provider(provider_type, url, username, &password) {
                    Ok(c) => c,
                    Err(_) => continue,
                };
            client.delete_event(calendar_href, booking_uid).await
        } else {
            let client = match crate::oauth2_caldav::build_client_for_source(
                pool,
                key,
                source_id,
                url,
                auth_type,
                username,
                password_enc.as_deref(),
                access_token_enc.as_deref(),
                token_expires_at.as_deref(),
            )
            .await
            {
                Ok(c) => c,
                Err(_) => continue,
            };
            client.delete_event(calendar_href, booking_uid).await
        };
        if let Err(e) = delete_result {
            tracing::error!(uid = %booking_uid, user = %user_id, calendar = %calendar_href, error = %e, "calendar event delete failed");
        }
    }

    // Remove cached event
    let _ = sqlx::query(
        "DELETE FROM events WHERE uid = ? AND calendar_id IN (
            SELECT c.id FROM calendars c
            JOIN caldav_sources cs ON cs.id = c.source_id
            JOIN accounts a ON a.id = cs.account_id
            WHERE a.user_id = ?
        )",
    )
    .bind(booking_uid)
    .bind(user_id)
    .execute(pool)
    .await;
}

/// Delete a booking from the host's CalDAV calendar.
async fn caldav_delete_booking(
    pool: &SqlitePool,
    key: &[u8; 32],
    user_id: &str,
    booking_uid: &str,
) {
    // Check if this booking was pushed to CalDAV
    let info: Option<(String,)> = sqlx::query_as(
        "SELECT caldav_calendar_href FROM bookings WHERE uid = ? AND caldav_calendar_href IS NOT NULL",
    )
    .bind(booking_uid)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    let calendar_href = match info {
        Some((href,)) => href,
        None => return, // Was never pushed to CalDAV
    };

    // Get the source credentials and provider type
    let source: Option<(
        String,
        String,
        String,
        Option<String>,
        String,
        Option<String>,
        Option<String>,
        String,
    )> = sqlx::query_as(
        "SELECT cs.id, cs.url, cs.username, cs.password_enc, cs.auth_type, cs.access_token_enc, cs.token_expires_at, cs.provider_type
         FROM caldav_sources cs
         JOIN accounts a ON a.id = cs.account_id
         WHERE a.user_id = ? AND cs.enabled = 1 AND cs.write_calendar_href = ?
         LIMIT 1",
    )
    .bind(user_id)
    .bind(&calendar_href)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    let (
        source_id,
        url,
        username,
        password_enc,
        auth_type,
        access_token_enc,
        token_expires_at,
        provider_type,
    ) = match source {
        Some(s) => s,
        None => return,
    };

    let delete_result = if provider_type == crate::providers::factory::kinds::EWS {
        let enc = match password_enc.as_deref() {
            Some(e) => e,
            None => return,
        };
        let password = match crate::crypto::decrypt_password(key, enc) {
            Ok(p) => p,
            Err(_) => return,
        };
        let client =
            match crate::providers::build_provider(&provider_type, &url, &username, &password) {
                Ok(c) => c,
                Err(_) => return,
            };
        client.delete_event(&calendar_href, booking_uid).await
    } else {
        let client = match crate::oauth2_caldav::build_client_for_source(
            pool,
            key,
            &source_id,
            &url,
            &auth_type,
            &username,
            password_enc.as_deref(),
            access_token_enc.as_deref(),
            token_expires_at.as_deref(),
        )
        .await
        {
            Ok(c) => c,
            Err(_) => return,
        };
        client.delete_event(&calendar_href, booking_uid).await
    };
    if let Err(e) = delete_result {
        tracing::error!(uid = %booking_uid, error = %e, "calendar event delete failed");
    }

    // Also remove the cached event from local DB so it doesn't block availability
    let _ = sqlx::query(
        "DELETE FROM events WHERE uid = ? AND calendar_id IN (
            SELECT c.id FROM calendars c
            JOIN caldav_sources cs ON cs.id = c.source_id
            JOIN accounts a ON a.id = cs.account_id
            WHERE a.user_id = ?
        )",
    )
    .bind(booking_uid)
    .bind(user_id)
    .execute(pool)
    .await;
}

// --- Booking watchers ---

/// Notify watcher team members that a booking is available to claim.
/// Generates a claim token per watcher member and sends notification emails.
async fn notify_watchers(
    pool: &SqlitePool,
    key: &[u8; 32],
    booking_id: &str,
    event_type_id: &str,
    assigned_to_name: &str,
    details: &crate::email::BookingDetails,
) {
    // Find watcher teams for this event type
    let watcher_team_ids: Vec<(String,)> =
        sqlx::query_as("SELECT team_id FROM event_type_watchers WHERE event_type_id = ?")
            .bind(event_type_id)
            .fetch_all(pool)
            .await
            .unwrap_or_default();

    if watcher_team_ids.is_empty() {
        return;
    }

    let base_url = match std::env::var("CALRS_BASE_URL").ok() {
        Some(u) => u,
        None => {
            tracing::warn!("CALRS_BASE_URL not set, skipping watcher notifications");
            return;
        }
    };

    let smtp_config = match crate::email::load_smtp_config(pool, key).await {
        Ok(Some(c)) => c,
        _ => {
            tracing::warn!("SMTP not configured, skipping watcher notifications");
            return;
        }
    };

    for (team_id,) in &watcher_team_ids {
        // Get all members of the watcher team
        let members: Vec<(String, String, String)> = sqlx::query_as(
            "SELECT u.id, u.name, COALESCE(u.booking_email, u.email) \
             FROM users u JOIN team_members tm ON tm.user_id = u.id \
             WHERE tm.team_id = ? AND u.enabled = 1",
        )
        .bind(team_id)
        .fetch_all(pool)
        .await
        .unwrap_or_default();

        for (user_id, user_name, user_email) in &members {
            let token = uuid::Uuid::new_v4().to_string();
            let token_id = uuid::Uuid::new_v4().to_string();

            // Insert claim token with 7-day expiry
            let _ = sqlx::query(
                "INSERT INTO booking_claim_tokens (id, booking_id, user_id, token, expires_at) \
                 VALUES (?, ?, ?, ?, datetime('now', '+7 days'))",
            )
            .bind(&token_id)
            .bind(booking_id)
            .bind(user_id)
            .bind(&token)
            .execute(pool)
            .await;

            let claim_url = format!(
                "{}/booking/claim/{}?token={}",
                base_url.trim_end_matches('/'),
                booking_id,
                token
            );

            let _ = crate::email::send_watcher_claim_notification(
                &smtp_config,
                details,
                user_name,
                user_email,
                assigned_to_name,
                &claim_url,
            )
            .await;
        }
    }

    tracing::info!(booking_id = %booking_id, event_type_id = %event_type_id, "watcher claim notifications sent");
}

// --- Claim endpoints ---

async fn claim_booking_form(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(booking_id): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let lang = crate::i18n::detect_from_headers(&headers);
    let token = match params.get("token") {
        Some(t) => t,
        None => {
            return render_booking_action_error(
                &state,
                &headers,
                "Invalid link",
                "No claim token provided.",
            );
        }
    };

    // Validate token
    let claim_info: Option<(String, String)> = sqlx::query_as(
        "SELECT bct.user_id, bct.booking_id FROM booking_claim_tokens bct \
         WHERE bct.token = ? AND bct.booking_id = ? AND bct.used_at IS NULL \
         AND bct.expires_at > datetime('now')",
    )
    .bind(token)
    .bind(&booking_id)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    if claim_info.is_none() {
        // Check if already claimed
        let claimed: Option<(String,)> = sqlx::query_as(
            "SELECT u.name FROM bookings b \
             JOIN users u ON u.id = b.claimed_by_user_id \
             WHERE b.id = ?",
        )
        .bind(&booking_id)
        .fetch_optional(&state.pool)
        .await
        .unwrap_or(None);

        if let Some((claimed_by_name,)) = claimed {
            let tmpl = match state.templates.get_template("booking_already_claimed.html") {
                Ok(t) => t,
                Err(e) => return internal_error_response("internal", &e),
            };
            return Html(
                tmpl.render(context! {
                    claimed_by_name => claimed_by_name,
                    lang => lang,
                })
                .unwrap_or_else(|e| internal_error_body("template render", &e)),
            )
            .into_response();
        }

        return render_booking_action_error(
            &state,
            &headers,
            "Invalid or expired link",
            "This claim link is no longer valid.",
        );
    }

    // Fetch booking details for display
    let booking: Option<(String, String, String, String, String, Option<String>)> = sqlx::query_as(
        "SELECT et.title, b.guest_name, b.guest_email, b.start_at, b.end_at, u.name \
             FROM bookings b \
             JOIN event_types et ON et.id = b.event_type_id \
             LEFT JOIN users u ON u.id = b.assigned_user_id \
             WHERE b.id = ?",
    )
    .bind(&booking_id)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    let (event_title, guest_name, guest_email, start_at, end_at, assigned_to) = match booking {
        Some(b) => b,
        None => {
            return render_booking_action_error(
                &state,
                &headers,
                "Booking not found",
                "This booking no longer exists.",
            )
        }
    };

    let date_label = format_date_label(&start_at, lang);
    let start_time = extract_time_24h(&start_at);
    let end_time = extract_time_24h(&end_at);

    let tmpl = match state.templates.get_template("booking_claim_form.html") {
        Ok(t) => t,
        Err(e) => return internal_error_response("internal", &e),
    };

    Html(
        tmpl.render(context! {
            event_title => event_title,
            date_label => date_label,
            start_time => start_time,
            end_time => end_time,
            guest_name => guest_name,
            guest_email => guest_email,
            assigned_to => assigned_to.unwrap_or_default(),
            token => token,
            lang => lang,
        })
        .unwrap_or_else(|e| internal_error_body("template render", &e)),
    )
    .into_response()
}

#[derive(Deserialize)]
struct ClaimForm {
    _csrf: Option<String>,
    token: String,
}

async fn claim_booking(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(booking_id): Path<String>,
    Form(form): Form<ClaimForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }
    let lang = crate::i18n::detect_from_headers(&headers);

    // Validate token
    let claim_info: Option<(String, String)> = sqlx::query_as(
        "SELECT bct.user_id, bct.booking_id FROM booking_claim_tokens bct \
         WHERE bct.token = ? AND bct.booking_id = ? AND bct.used_at IS NULL \
         AND bct.expires_at > datetime('now')",
    )
    .bind(&form.token)
    .bind(&booking_id)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    let (claimant_user_id, _) = match claim_info {
        Some(c) => c,
        None => {
            // Check if already claimed
            let claimed: Option<(String,)> = sqlx::query_as(
                "SELECT u.name FROM bookings b \
                 JOIN users u ON u.id = b.claimed_by_user_id \
                 WHERE b.id = ?",
            )
            .bind(&booking_id)
            .fetch_optional(&state.pool)
            .await
            .unwrap_or(None);

            if let Some((claimed_by_name,)) = claimed {
                let tmpl = match state.templates.get_template("booking_already_claimed.html") {
                    Ok(t) => t,
                    Err(e) => return internal_error_response("internal", &e),
                };
                return Html(
                    tmpl.render(context! {
                        claimed_by_name => claimed_by_name,
                        lang => lang,
                    })
                    .unwrap_or_else(|e| internal_error_body("template render", &e)),
                )
                .into_response();
            }

            return render_booking_action_error(
                &state,
                &headers,
                "Invalid or expired link",
                "This claim link is no longer valid.",
            )
            .into_response();
        }
    };

    // Use BEGIN IMMEDIATE to prevent race conditions
    let mut tx = match sqlx::pool::Pool::begin(&state.pool).await {
        Ok(tx) => tx,
        Err(e) => return internal_error_response("database query", &e),
    };

    // Check booking is not already claimed (inside transaction)
    let already_claimed: Option<(String,)> = sqlx::query_as(
        "SELECT claimed_by_user_id FROM bookings WHERE id = ? AND claimed_by_user_id IS NOT NULL",
    )
    .bind(&booking_id)
    .fetch_optional(&mut *tx)
    .await
    .unwrap_or(None);

    if already_claimed.is_some() {
        let _ = tx.rollback().await;
        let claimed_name: Option<(String,)> = sqlx::query_as(
            "SELECT u.name FROM bookings b JOIN users u ON u.id = b.claimed_by_user_id WHERE b.id = ?",
        )
        .bind(&booking_id)
        .fetch_optional(&state.pool)
        .await
        .unwrap_or(None);

        let tmpl = match state.templates.get_template("booking_already_claimed.html") {
            Ok(t) => t,
            Err(e) => return internal_error_response("internal", &e),
        };
        return Html(
            tmpl.render(context! {
                claimed_by_name => claimed_name.map(|(n,)| n).unwrap_or_default(),
                lang => lang,
            })
            .unwrap_or_else(|e| internal_error_body("template render", &e)),
        )
        .into_response();
    }

    // Claim the booking
    let _ = sqlx::query(
        "UPDATE bookings SET claimed_by_user_id = ?, claimed_at = datetime('now') WHERE id = ?",
    )
    .bind(&claimant_user_id)
    .bind(&booking_id)
    .execute(&mut *tx)
    .await;

    // Mark this token as used
    let _ =
        sqlx::query("UPDATE booking_claim_tokens SET used_at = datetime('now') WHERE token = ?")
            .bind(&form.token)
            .execute(&mut *tx)
            .await;

    if let Err(e) = tx.commit().await {
        return internal_error_response("database query", &e);
    }

    tracing::info!(booking_id = %booking_id, claimant_user_id = %claimant_user_id, "booking claimed");

    // Fetch booking + claimant details for CalDAV push and email
    let booking: Option<(
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        Option<String>,
        String,
    )> = sqlx::query_as(
        "SELECT et.title, b.guest_name, b.guest_email, b.start_at, b.end_at, b.uid, \
             COALESCE(b.guest_timezone, 'UTC'), a.user_id, et.location_value, b.event_type_id \
             FROM bookings b \
             JOIN event_types et ON et.id = b.event_type_id \
             JOIN accounts a ON a.id = et.account_id \
             WHERE b.id = ?",
    )
    .bind(&booking_id)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    let (
        event_title,
        guest_name,
        guest_email,
        start_at,
        end_at,
        uid,
        guest_tz,
        host_user_id,
        location,
        event_type_id,
    ) = match booking {
        Some(b) => b,
        None => {
            return render_booking_action_error(
                &state,
                &headers,
                "Booking not found",
                "This booking no longer exists.",
            )
            .into_response()
        }
    };

    let claimant: Option<(String, String)> =
        sqlx::query_as("SELECT name, COALESCE(booking_email, email) FROM users WHERE id = ?")
            .bind(&claimant_user_id)
            .fetch_optional(&state.pool)
            .await
            .unwrap_or(None);

    let (claimant_name, claimant_email) = claimant.unwrap_or_default();

    let host: Option<(String, String)> =
        sqlx::query_as("SELECT name, COALESCE(booking_email, email) FROM users WHERE id = ?")
            .bind(&host_user_id)
            .fetch_optional(&state.pool)
            .await
            .unwrap_or(None);

    let (host_name, host_email) = host.unwrap_or_default();

    let date = start_at.get(..10).unwrap_or(&start_at).to_string();
    let start_time = extract_time_24h(&start_at);
    let end_time = extract_time_24h(&end_at);

    // Add claimant as a booking attendee
    let attendee_id = uuid::Uuid::new_v4().to_string();
    let _ = sqlx::query("INSERT INTO booking_attendees (id, booking_id, email) VALUES (?, ?, ?)")
        .bind(&attendee_id)
        .bind(&booking_id)
        .bind(&claimant_email)
        .execute(&state.pool)
        .await;

    let claim_host_tz = get_host_tz(&state.pool, &event_type_id).await;

    // Build details with claimant as additional attendee for CalDAV push
    let mut details = crate::email::BookingDetails {
        event_title: event_title.clone(),
        date: date.clone(),
        start_time: start_time.clone(),
        end_time: end_time.clone(),
        guest_name: guest_name.clone(),
        guest_email: guest_email.clone(),
        guest_timezone: guest_tz,
        host_name,
        host_email,
        uid: uid.clone(),
        notes: None,
        location,
        reminder_minutes: None,
        additional_attendees: vec![claimant_email.clone()],
        host_timezone: claim_host_tz.name().to_string(),
        ..Default::default()
    };

    // Also include any pre-existing additional attendees
    let existing_attendees: Vec<(String,)> =
        sqlx::query_as("SELECT email FROM booking_attendees WHERE booking_id = ? AND email != ?")
            .bind(&booking_id)
            .bind(&claimant_email)
            .fetch_all(&state.pool)
            .await
            .unwrap_or_default();
    for (email,) in &existing_attendees {
        details.additional_attendees.push(email.clone());
    }

    // Re-push updated ICS to host's CalDAV (with claimant as ATTENDEE)
    caldav_push_booking(
        &state.pool,
        &state.secret_key,
        &host_user_id,
        &uid,
        &details,
    )
    .await;

    // Push to claimant's CalDAV calendar too
    caldav_push_booking(
        &state.pool,
        &state.secret_key,
        &claimant_user_id,
        &uid,
        &details,
    )
    .await;

    // Send confirmation email to claimant
    if let Ok(Some(smtp_config)) =
        crate::email::load_smtp_config(&state.pool, &state.secret_key).await
    {
        let _ = crate::email::send_claim_confirmation(
            &smtp_config,
            &details,
            &claimant_name,
            &claimant_email,
        )
        .await;
    }

    // Render success page
    let date_label = format_date_label(&start_at, lang);
    let tmpl = match state.templates.get_template("booking_claimed.html") {
        Ok(t) => t,
        Err(e) => return internal_error_response("internal", &e),
    };

    Html(
        tmpl.render(context! {
            event_title => event_title,
            date_label => date_label,
            start_time => start_time,
            end_time => end_time,
            guest_name => guest_name,
            guest_email => guest_email,
            lang => lang,
        })
        .unwrap_or_else(|e| internal_error_body("template render", &e)),
    )
    .into_response()
}

fn render_booking_action_error(
    state: &AppState,
    headers: &HeaderMap,
    title: &str,
    message: &str,
) -> axum::response::Response {
    let lang = crate::i18n::detect_from_headers(headers);
    let tmpl = match state.templates.get_template("booking_action_error.html") {
        Ok(t) => t,
        Err(e) => return internal_error_response("internal", &e),
    };
    Html(
        tmpl.render(context! {
            title => title,
            message => message,
            lang => lang,
        })
        .unwrap_or_else(|e| internal_error_body("template render", &e)),
    )
    .into_response()
}

#[cfg(test)]
mod tests;
