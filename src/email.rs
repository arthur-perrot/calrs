use anyhow::{bail, Result};
use chrono::NaiveDateTime;
use chrono_tz::Tz;
use fluent_bundle::{FluentArgs, FluentValue};
use lettre::message::header::ContentType;
use lettre::message::{Attachment, Mailbox, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use sqlx::SqlitePool;

/// Translate a Fluent message id with no arguments. Local helper so call
/// sites stay readable.
fn t(lang: &str, key: &str) -> String {
    crate::i18n::translate(lang, key, None)
}

/// Translate with named arguments. Each tuple is `(arg_name, value)`.
fn ta<const N: usize>(lang: &str, key: &str, args: [(&str, &str); N]) -> String {
    let mut fa = FluentArgs::new();
    for (k, v) in args.iter() {
        fa.set(*k, FluentValue::from(*v));
    }
    crate::i18n::translate(lang, key, Some(&fa))
}

/// Resolve guest language from booking details, falling back to English.
fn guest_lang(details: &BookingDetails) -> &str {
    details.guest_language.as_deref().unwrap_or("en")
}

#[allow(dead_code)]
fn host_lang(details: &BookingDetails) -> &str {
    details.host_language.as_deref().unwrap_or("en")
}

pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub from_email: String,
    pub from_name: Option<String>,
    pub tls_mode: SmtpTlsMode,
}

impl std::fmt::Debug for SmtpConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmtpConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("from_email", &self.from_email)
            .field("from_name", &self.from_name)
            .field("tls_mode", &self.tls_mode)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SmtpTlsMode {
    StartTls,
    Tls,
}

impl SmtpTlsMode {
    fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "starttls" => Ok(Self::StartTls),
            "tls" => Ok(Self::Tls),
            other => bail!(
                "CALRS_SMTP_TLS_MODE must be 'starttls' or 'tls' (got '{}')",
                other
            ),
        }
    }
}

pub struct SmtpStatus {
    pub host: String,
    pub port: u16,
    pub from_email: String,
    pub enabled: bool,
    pub from_env: bool,
}

impl SmtpConfig {
    /// Get "from" Mailbox, compliant with RFC 5322
    fn mailbox_from(&self) -> Result<Mailbox> {
        Ok(Mailbox::new(
            self.from_name.clone(),
            self.from_email.parse()?,
        ))
    }
}

#[derive(Clone, Default)]
pub struct BookingDetails {
    pub event_title: String,
    pub date: String,
    pub start_time: String,
    pub end_time: String,
    pub guest_name: String,
    pub guest_email: String,
    pub guest_timezone: String,
    pub host_name: String,
    pub host_email: String,
    pub uid: String,
    pub notes: Option<String>,
    pub location: Option<String>,
    pub reminder_minutes: Option<i32>,
    pub additional_attendees: Vec<String>,
    /// Guest's preferred language at booking time (from `bookings.language`).
    /// `None` falls back to English at send time.
    pub guest_language: Option<String>,
    /// Host's saved UI-language preference (from `users.language`).
    /// `None` falls back to English at send time.
    pub host_language: Option<String>,
    /// Host's IANA timezone — the event type's tz when set (via `get_host_tz`),
    /// otherwise the host user's tz. When set and different from
    /// `guest_timezone`, host-targeted emails display the wall-clock time
    /// converted into this zone. Empty string falls back to guest-zone display.
    pub host_timezone: String,
}

#[derive(Default)]
pub struct CancellationDetails {
    pub event_title: String,
    pub date: String,
    pub start_time: String,
    pub end_time: String,
    pub guest_name: String,
    pub guest_email: String,
    pub guest_timezone: String,
    pub host_name: String,
    pub host_email: String,
    pub uid: String,
    pub reason: Option<String>,
    pub cancelled_by_host: bool,
    pub guest_language: Option<String>,
    pub host_language: Option<String>,
    /// Host's IANA timezone (from `users.timezone`). See `BookingDetails::host_timezone`.
    pub host_timezone: String,
}

include!("email/templates.rs");
include!("email/ics.rs");
include!("email/senders.rs");
include!("email/utility.rs");
include!("email/reschedule.rs");
include!("email/claim.rs");

#[cfg(test)]
mod tests;
