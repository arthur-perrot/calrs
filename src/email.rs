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

// --- HTML email template helpers ---

fn h(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

struct EmailRow {
    label: String,
    value: String,
}

struct EmailAction {
    label: String,
    url: String,
    color: String,
}

fn render_html_email(
    greeting: &str,
    message: &str,
    accent: &str,
    rows: &[EmailRow],
    footer_note: Option<&str>,
) -> String {
    render_html_email_with_actions(greeting, message, accent, rows, footer_note, &[])
}

fn render_html_email_with_actions(
    greeting: &str,
    message: &str,
    accent: &str,
    rows: &[EmailRow],
    footer_note: Option<&str>,
    actions: &[EmailAction],
) -> String {
    let mut detail_rows = String::new();
    for (i, row) in rows.iter().enumerate() {
        let bg = if i % 2 == 0 { "#f8f9fa" } else { "#ffffff" };
        detail_rows.push_str(&format!(
            "<tr>\
               <td style=\"padding:8px 12px;color:#6b7280;font-size:13px;white-space:nowrap;vertical-align:top;\">{}</td>\
               <td style=\"padding:8px 12px;color:#111827;font-size:14px;background:{bg};\">{}</td>\
             </tr>",
            row.label, h(&row.value),
        ));
    }

    let actions_html = if actions.is_empty() {
        String::new()
    } else {
        let buttons: Vec<String> = actions.iter().map(|a| {
            format!(
                "<a href=\"{}\" style=\"display:inline-block;padding:12px 28px;background:{};color:#ffffff;text-decoration:none;border-radius:6px;font-weight:600;font-size:14px;margin:0 6px;\">{}</a>",
                h(&a.url), a.color, h(&a.label)
            )
        }).collect();
        format!(
            "<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" style=\"margin:20px 0 0;\"><tr><td align=\"center\">{}</td></tr></table>",
            buttons.join(" ")
        )
    };

    let footer_html = footer_note
        .map(|n| {
            format!(
                "<p style=\"margin:16px 0 0;font-size:13px;color:#6b7280;\">{}</p>",
                h(n)
            )
        })
        .unwrap_or_default();

    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"></head>
<body style="margin:0;padding:0;background:#f4f4f7;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f4f4f7;">
<tr><td align="center" style="padding:32px 16px;">
  <table role="presentation" width="520" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:8px;border:1px solid #e5e7eb;max-width:520px;width:100%;">
    <!-- Accent bar -->
    <tr><td style="height:4px;background:{accent};border-radius:8px 8px 0 0;"></td></tr>
    <!-- Content -->
    <tr><td style="padding:32px 28px;">
      <p style="margin:0 0 4px;font-size:15px;color:#374151;">{greeting}</p>
      <p style="margin:0 0 20px;font-size:15px;color:#111827;font-weight:500;">{message}</p>
      <!-- Details table -->
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #e5e7eb;border-radius:6px;overflow:hidden;">
        {detail_rows}
      </table>
      {actions_html}
      {footer_html}
    </td></tr>
    <!-- Footer -->
    <tr><td style="padding:16px 28px;border-top:1px solid #f0f0f3;text-align:center;">
      <span style="font-size:12px;color:#9ca3af;">Sent by </span>
      <a href="https://cal.rs" style="font-size:12px;color:#6b7280;font-weight:600;text-decoration:none;">calrs</a>
    </td></tr>
  </table>
</td></tr>
</table>
</body>
</html>"##
    )
}

fn build_multipart_body(plain: &str, html: &str) -> MultiPart {
    MultiPart::alternative()
        .singlepart(SinglePart::plain(plain.to_string()))
        .singlepart(
            SinglePart::builder()
                .header(ContentType::parse("text/html; charset=UTF-8").unwrap())
                .body(html.to_string()),
        )
}

// --- ICS generation ---

/// Sanitize a value for use in an ICS field.
/// Strips CR/LF to prevent ICS injection (RFC 5545 field breakout).
fn sanitize_ics(value: &str) -> String {
    value
        .replace('\r', "")
        .replace('\n', " ")
        .replace(';', "\\;")
        .replace(',', "\\,")
}

/// Convert date + start/end times from a guest timezone to UTC ICS format (YYYYMMDDTHHMMSSZ).
/// Falls back to floating time (no Z) if timezone parsing fails.
fn convert_to_utc(
    date: &str,
    start_time: &str,
    end_time: &str,
    timezone: &str,
) -> (String, String) {
    let fallback_start = format!(
        "{}T{}00",
        date.replace('-', ""),
        start_time.replace(':', "")
    );
    let fallback_end = format!("{}T{}00", date.replace('-', ""), end_time.replace(':', ""));

    let tz: Tz = match timezone.parse() {
        Ok(t) => t,
        Err(_) => return (fallback_start, fallback_end),
    };

    let start_naive = match NaiveDateTime::parse_from_str(
        &format!("{} {}:00", date, start_time),
        "%Y-%m-%d %H:%M:%S",
    ) {
        Ok(dt) => dt,
        Err(_) => return (fallback_start, fallback_end),
    };
    let end_naive = match NaiveDateTime::parse_from_str(
        &format!("{} {}:00", date, end_time),
        "%Y-%m-%d %H:%M:%S",
    ) {
        Ok(dt) => dt,
        Err(_) => return (fallback_start, fallback_end),
    };

    use chrono::TimeZone;
    let start_utc = match tz.from_local_datetime(&start_naive).earliest() {
        Some(dt) => dt.with_timezone(&chrono::Utc),
        None => return (fallback_start, fallback_end),
    };
    let end_utc = match tz.from_local_datetime(&end_naive).earliest() {
        Some(dt) => dt.with_timezone(&chrono::Utc),
        None => return (fallback_start, fallback_end),
    };

    (
        start_utc.format("%Y%m%dT%H%M%SZ").to_string(),
        end_utc.format("%Y%m%dT%H%M%SZ").to_string(),
    )
}

/// Convert a (date, start_time, end_time) tuple from `from_tz` into `to_tz`,
/// returning the wall-clock equivalents.
///
/// Returns `(date, start_time, end_time)` formatted as `YYYY-MM-DD` / `HH:MM`.
/// The date can roll over (e.g. LA 22:00 → Paris 07:00 next day), so the
/// returned date may differ from the input. If either timezone fails to parse
/// or the local time is invalid (DST gap), returns `None` and the caller
/// should fall back to displaying the original values.
fn convert_time_between_tz(
    date: &str,
    start_time: &str,
    end_time: &str,
    from_tz: &str,
    to_tz: &str,
) -> Option<(String, String, String)> {
    use chrono::TimeZone;

    let from: Tz = from_tz.parse().ok()?;
    let to: Tz = to_tz.parse().ok()?;

    let start_naive =
        NaiveDateTime::parse_from_str(&format!("{} {}:00", date, start_time), "%Y-%m-%d %H:%M:%S")
            .ok()?;
    let end_naive =
        NaiveDateTime::parse_from_str(&format!("{} {}:00", date, end_time), "%Y-%m-%d %H:%M:%S")
            .ok()?;

    let start_target = from
        .from_local_datetime(&start_naive)
        .earliest()?
        .with_timezone(&to);
    let end_target = from
        .from_local_datetime(&end_naive)
        .earliest()?
        .with_timezone(&to);

    Some((
        start_target.format("%Y-%m-%d").to_string(),
        start_target.format("%H:%M").to_string(),
        end_target.format("%H:%M").to_string(),
    ))
}

/// Build the date + time strings to display in a host-targeted email.
///
/// When `host_timezone` is set and differs from `guest_timezone`, the times are
/// converted into the host's zone. Otherwise the original guest-zone values are
/// kept. The returned `time_display` always includes a `(TZ)` suffix so the
/// host can tell which zone they're looking at.
pub(crate) fn host_time_display(
    date: &str,
    start_time: &str,
    end_time: &str,
    guest_timezone: &str,
    host_timezone: &str,
) -> (String, String) {
    if !host_timezone.is_empty() && host_timezone != guest_timezone {
        if let Some((host_date, host_start, host_end)) =
            convert_time_between_tz(date, start_time, end_time, guest_timezone, host_timezone)
        {
            return (
                host_date,
                format!("{} \u{2013} {} ({})", host_start, host_end, host_timezone),
            );
        }
    }

    let tz_label = if !guest_timezone.is_empty() {
        guest_timezone
    } else if !host_timezone.is_empty() {
        host_timezone
    } else {
        ""
    };

    let time_display = if tz_label.is_empty() {
        format!("{} \u{2013} {}", start_time, end_time)
    } else {
        format!("{} \u{2013} {} ({})", start_time, end_time, tz_label)
    };

    (date.to_string(), time_display)
}

/// Generate an .ics VCALENDAR string for a booking
/// Extract first name (first word) from a full name.
fn first_name(full_name: &str) -> &str {
    full_name.split_whitespace().next().unwrap_or(full_name)
}

pub fn generate_ics(details: &BookingDetails, method: &str) -> String {
    let guest_first = first_name(&details.guest_name);
    let host_first = first_name(&details.host_name);
    let summary = sanitize_ics(&format!(
        "{} \u{2014} {} & {}",
        details.event_title, guest_first, host_first
    ));
    let host_name = sanitize_ics(&details.host_name);
    let guest_name = sanitize_ics(&details.guest_name);
    let host_email = sanitize_ics(&details.host_email);
    let guest_email = sanitize_ics(&details.guest_email);
    let location_line = details
        .location
        .as_ref()
        .map(|l| format!("LOCATION:{}\r\n", sanitize_ics(l)))
        .unwrap_or_default();
    let description_line = details
        .notes
        .as_ref()
        .filter(|n| !n.trim().is_empty())
        .map(|n| format!("DESCRIPTION:{}\r\n", sanitize_ics(n)))
        .unwrap_or_default();
    let valarm = details
        .reminder_minutes
        .filter(|&m| m > 0)
        .map(|m| {
            format!(
                "BEGIN:VALARM\r\n\
                 TRIGGER:-PT{m}M\r\n\
                 ACTION:DISPLAY\r\n\
                 DESCRIPTION:Reminder\r\n\
                 END:VALARM\r\n"
            )
        })
        .unwrap_or_default();
    let additional_attendee_lines: String = details
        .additional_attendees
        .iter()
        .map(|email| format!("ATTENDEE;RSVP=TRUE:mailto:{}\r\n", sanitize_ics(email)))
        .collect();
    let dtstamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    // Convert guest-timezone times to UTC for the ICS
    let (dtstart, dtend) = convert_to_utc(
        &details.date,
        &details.start_time,
        &details.end_time,
        &details.guest_timezone,
    );
    format!(
        "BEGIN:VCALENDAR\r\n\
         VERSION:2.0\r\n\
         PRODID:-//calrs//calrs//EN\r\n\
         {method_line}\
         BEGIN:VEVENT\r\n\
         UID:{uid}\r\n\
         DTSTAMP:{dtstamp}\r\n\
         DTSTART:{dtstart}\r\n\
         DTEND:{dtend}\r\n\
         SUMMARY:{summary}\r\n\
         {description_line}\
         {location_line}\
         ORGANIZER;CN={host_name}:mailto:{host_email}\r\n\
         ATTENDEE;CN={guest_name};RSVP=TRUE:mailto:{guest_email}\r\n\
         {additional_attendee_lines}\
         STATUS:CONFIRMED\r\n\
         {valarm}\
         END:VEVENT\r\n\
         END:VCALENDAR\r\n",
        method_line = if method.is_empty() {
            String::new()
        } else {
            format!("METHOD:{method}\r\n")
        },
        uid = details.uid,
        dtstamp = dtstamp,
        dtstart = dtstart,
        dtend = dtend,
        summary = summary,
        description_line = description_line,
        location_line = location_line,
        host_name = host_name,
        host_email = host_email,
        guest_name = guest_name,
        guest_email = guest_email,
        additional_attendee_lines = additional_attendee_lines,
    )
}

/// Generate an .ics VCALENDAR for cancellation (METHOD:CANCEL)
fn generate_cancel_ics(details: &CancellationDetails) -> String {
    let guest_first = first_name(&details.guest_name);
    let host_first = first_name(&details.host_name);
    let summary = sanitize_ics(&format!(
        "{} \u{2014} {} & {}",
        details.event_title, guest_first, host_first
    ));
    let host_name = sanitize_ics(&details.host_name);
    let guest_name = sanitize_ics(&details.guest_name);
    let host_email = sanitize_ics(&details.host_email);
    let guest_email = sanitize_ics(&details.guest_email);
    let dtstamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let (dtstart, dtend) = convert_to_utc(
        &details.date,
        &details.start_time,
        &details.end_time,
        &details.guest_timezone,
    );
    format!(
        "BEGIN:VCALENDAR\r\n\
         VERSION:2.0\r\n\
         PRODID:-//calrs//calrs//EN\r\n\
         METHOD:CANCEL\r\n\
         BEGIN:VEVENT\r\n\
         UID:{uid}\r\n\
         DTSTAMP:{dtstamp}\r\n\
         DTSTART:{dtstart}\r\n\
         DTEND:{dtend}\r\n\
         SUMMARY:{summary}\r\n\
         ORGANIZER;CN={host_name}:mailto:{host_email}\r\n\
         ATTENDEE;CN={guest_name}:mailto:{guest_email}\r\n\
         STATUS:CANCELLED\r\n\
         END:VEVENT\r\n\
         END:VCALENDAR\r\n",
        uid = details.uid,
        dtstamp = dtstamp,
        dtstart = dtstart,
        dtend = dtend,
        summary = summary,
        host_name = host_name,
        host_email = host_email,
        guest_name = guest_name,
        guest_email = guest_email,
    )
}

// --- Email senders ---

/// Send booking confirmation to the guest
pub async fn send_guest_confirmation(
    config: &SmtpConfig,
    details: &BookingDetails,
    cancel_url: Option<&str>,
) -> Result<()> {
    send_guest_confirmation_ex(config, details, cancel_url, None, None, None).await
}

pub async fn send_guest_confirmation_ex(
    config: &SmtpConfig,
    details: &BookingDetails,
    cancel_url: Option<&str>,
    reschedule_url: Option<&str>,
    cancel_notice_min: Option<i32>,
    reschedule_notice_min: Option<i32>,
) -> Result<()> {
    let ics = generate_ics(details, "REQUEST");
    let lang = guest_lang(details);

    let to = format!("{} <{}>", details.guest_name, details.guest_email).parse()?;

    let time_display = format!(
        "{} \u{2013} {} ({})",
        details.start_time, details.end_time, details.guest_timezone
    );

    let greeting = ta(
        lang,
        "email-confirm-greeting",
        [("name", &details.guest_name)],
    );
    let headline = t(lang, "email-confirm-headline");
    let label_event = t(lang, "confirmed-detail-event");
    let label_date = t(lang, "confirmed-detail-date");
    let label_time = t(lang, "confirmed-detail-time");
    let label_with = t(lang, "confirmed-detail-with");
    let label_location = t(lang, "confirmed-detail-location");
    let label_notes = t(lang, "confirmed-detail-notes");
    let ics_attached_plain = t(lang, "email-confirm-ics-attached-plain");
    let ics_attached_html = t(lang, "email-confirm-ics-attached-html");
    let signature = t(lang, "email-signature");

    // Notice-window policy lines, mentioned just before the cancel link in
    // both the plain and HTML bodies. Translated to the guest's language.
    let cancel_notice_line = cancel_notice_min.filter(|m| *m > 0).map(|m| {
        ta(
            lang,
            "email-confirm-cancel-notice",
            [("minutes", m.to_string().as_str())],
        )
    });
    let reschedule_notice_line = reschedule_notice_min.filter(|m| *m > 0).map(|m| {
        ta(
            lang,
            "email-confirm-reschedule-notice",
            [("minutes", m.to_string().as_str())],
        )
    });

    let plain = format!(
        "{}\n\n\
         {}\n\n\
         {} {}\n\
         {} {}\n\
         {} {}\n\
         {} {}\n\
         {}{}\
         {}\n\
         {}{}{}\
         {}",
        greeting,
        headline,
        label_event,
        details.event_title,
        label_date,
        details.date,
        label_time,
        time_display,
        label_with,
        details.host_name,
        details
            .location
            .as_ref()
            .map(|l| format!("{} {}\n", label_location, l))
            .unwrap_or_default(),
        details
            .notes
            .as_ref()
            .map(|n| format!("{} {}\n", label_notes, n))
            .unwrap_or_default(),
        ics_attached_plain,
        reschedule_notice_line
            .as_ref()
            .map(|l| format!("\n{}\n", l))
            .unwrap_or_default(),
        cancel_notice_line
            .as_ref()
            .map(|l| format!("\n{}\n", l))
            .unwrap_or_default(),
        cancel_url
            .map(|u| format!(
                "\n{}\n",
                ta(lang, "email-confirm-need-to-cancel", [("url", u)])
            ))
            .unwrap_or_default(),
        signature,
    );

    let mut rows = vec![
        EmailRow {
            label: label_event.clone(),
            value: details.event_title.clone(),
        },
        EmailRow {
            label: label_date.clone(),
            value: details.date.clone(),
        },
        EmailRow {
            label: label_time.clone(),
            value: time_display,
        },
        EmailRow {
            label: label_with.clone(),
            value: details.host_name.clone(),
        },
    ];
    if let Some(loc) = &details.location {
        rows.push(EmailRow {
            label: label_location.clone(),
            value: loc.clone(),
        });
    }
    if let Some(notes) = &details.notes {
        rows.push(EmailRow {
            label: label_notes.clone(),
            value: notes.clone(),
        });
    }

    let mut actions: Vec<EmailAction> = Vec::new();
    if let Some(u) = reschedule_url {
        actions.push(EmailAction {
            label: t(lang, "email-action-reschedule"),
            url: u.to_string(),
            color: "#3b82f6".to_string(),
        });
    }
    if let Some(u) = cancel_url {
        actions.push(EmailAction {
            label: t(lang, "email-action-cancel-booking"),
            url: u.to_string(),
            color: "#dc2626".to_string(),
        });
    }

    // Append notice lines to the footer note so they sit just below the
    // action buttons, alongside the existing "ICS attached" copy.
    let mut footer_note_html = ics_attached_html.clone();
    if let Some(line) = &reschedule_notice_line {
        footer_note_html.push('\n');
        footer_note_html.push_str(line);
    }
    if let Some(line) = &cancel_notice_line {
        footer_note_html.push('\n');
        footer_note_html.push_str(line);
    }
    let html = render_html_email_with_actions(
        &h(&greeting),
        &headline,
        "#16a34a",
        &rows,
        Some(&footer_note_html),
        &actions,
    );

    let body = build_multipart_body(&plain, &html);

    let ics_attachment = Attachment::new("invite.ics".to_string()).body(
        ics,
        ContentType::parse("text/calendar; method=REQUEST; charset=UTF-8")?,
    );

    let subject = ta(
        lang,
        "email-confirm-subject",
        [("event", &details.event_title), ("date", &details.date)],
    );

    let from = config.mailbox_from()?;

    let email = Message::builder()
        .from(from.clone())
        .to(to)
        .subject(subject)
        .multipart(
            MultiPart::mixed()
                .multipart(body)
                .singlepart(ics_attachment),
        )?;

    send_email(config, email).await?;

    // Send confirmation to additional attendees
    for attendee_email in &details.additional_attendees {
        let ics2 = generate_ics(details, "REQUEST");
        let to2: lettre::message::Mailbox = attendee_email.parse()?;
        let plain2 = format!(
            "Hi,\n\n\
             You've been added as an attendee to a booking.\n\n\
             Event: {}\n\
             Date: {}\n\
             Time: {} \u{2013} {} ({})\n\
             Organizer: {}\n\
             Booked by: {} <{}>\n\n\
             A calendar invite is attached.\n\n\
             \u{2014} calrs",
            details.event_title,
            details.date,
            details.start_time,
            details.end_time,
            details.guest_timezone,
            details.host_name,
            details.guest_name,
            details.guest_email,
        );
        let html2 = render_html_email(
            "Hi,",
            "You've been added as an attendee to a booking.",
            "#16a34a",
            &[
                EmailRow {
                    label: "Event".to_string(),
                    value: details.event_title.clone(),
                },
                EmailRow {
                    label: "Date".to_string(),
                    value: details.date.clone(),
                },
                EmailRow {
                    label: "Time".to_string(),
                    value: format!(
                        "{} \u{2013} {} ({})",
                        details.start_time, details.end_time, details.guest_timezone
                    ),
                },
                EmailRow {
                    label: "Organizer".to_string(),
                    value: details.host_name.clone(),
                },
                EmailRow {
                    label: "Booked by".to_string(),
                    value: format!("{} <{}>", details.guest_name, details.guest_email),
                },
            ],
            Some("A calendar invite is attached to this email."),
        );
        let body2 = build_multipart_body(&plain2, &html2);
        let att2 = Attachment::new("invite.ics".to_string()).body(
            ics2,
            ContentType::parse("text/calendar; method=REQUEST; charset=UTF-8")?,
        );
        let email2 = Message::builder()
            .from(from.clone())
            .to(to2)
            .subject(format!(
                "Invite: {} \u{2014} {}",
                details.event_title, details.date
            ))
            .multipart(MultiPart::mixed().multipart(body2).singlepart(att2))?;
        if let Err(e) = send_email(config, email2).await {
            tracing::warn!(attendee = %attendee_email, error = %e, "failed to send attendee confirmation");
        }
    }

    Ok(())
}

/// Send booking notification to the host
pub async fn send_host_notification(config: &SmtpConfig, details: &BookingDetails) -> Result<()> {
    let ics = generate_ics(details, "REQUEST");

    let to = format!("{} <{}>", details.host_name, details.host_email).parse()?;

    let (date_display, time_display) = host_time_display(
        &details.date,
        &details.start_time,
        &details.end_time,
        &details.guest_timezone,
        &details.host_timezone,
    );

    let plain = format!(
        "New booking!\n\n\
         Event: {}\n\
         Date: {}\n\
         Time: {}\n\
         Guest: {} <{}>\n\
         {}{}\n\
         A calendar invite is attached.\n\n\
         \u{2014} calrs",
        details.event_title,
        date_display,
        time_display,
        details.guest_name,
        details.guest_email,
        details
            .location
            .as_ref()
            .map(|l| format!("Location: {}\n", l))
            .unwrap_or_default(),
        details
            .notes
            .as_ref()
            .map(|n| format!("Notes: {}\n", n))
            .unwrap_or_default(),
    );

    let mut rows = vec![
        EmailRow {
            label: "Event".to_string(),
            value: details.event_title.clone(),
        },
        EmailRow {
            label: "Date".to_string(),
            value: date_display.clone(),
        },
        EmailRow {
            label: "Time".to_string(),
            value: time_display,
        },
        EmailRow {
            label: "Guest".to_string(),
            value: format!("{} <{}>", details.guest_name, details.guest_email),
        },
    ];
    if let Some(loc) = &details.location {
        rows.push(EmailRow {
            label: "Location".to_string(),
            value: loc.clone(),
        });
    }
    if let Some(notes) = &details.notes {
        rows.push(EmailRow {
            label: "Notes".to_string(),
            value: notes.clone(),
        });
    }

    let html = render_html_email(
        "New booking!",
        &format!("{} booked a slot with you.", h(&details.guest_name)),
        "#16a34a",
        &rows,
        Some("A calendar invite is attached to this email."),
    );

    let body = build_multipart_body(&plain, &html);

    let ics_attachment = Attachment::new("invite.ics".to_string()).body(
        ics,
        ContentType::parse("text/calendar; method=REQUEST; charset=UTF-8")?,
    );

    let email = Message::builder()
        .from(config.mailbox_from()?)
        .to(to)
        .subject(format!(
            "New booking: {} \u{2014} {} ({})",
            details.event_title, details.guest_name, date_display
        ))
        .multipart(
            MultiPart::mixed()
                .multipart(body)
                .singlepart(ics_attachment),
        )?;

    send_email(config, email).await
}

/// Send host a confirmation that a pending booking was approved (no ICS — event is already
/// pushed via CalDAV write-back).
pub async fn send_host_booking_confirmed(
    config: &SmtpConfig,
    details: &BookingDetails,
) -> Result<()> {
    let to = format!("{} <{}>", details.host_name, details.host_email).parse()?;

    let (date_display, time_display) = host_time_display(
        &details.date,
        &details.start_time,
        &details.end_time,
        &details.guest_timezone,
        &details.host_timezone,
    );

    let plain = format!(
        "Booking confirmed!\n\n\
         Event: {}\n\
         Date: {}\n\
         Time: {}\n\
         Guest: {} <{}>\n\
         {}\
         The event has been added to your calendar.\n\n\
         \u{2014} calrs",
        details.event_title,
        date_display,
        time_display,
        details.guest_name,
        details.guest_email,
        details
            .location
            .as_ref()
            .map(|l| format!("Location: {}\n", l))
            .unwrap_or_default(),
    );

    let mut rows = vec![
        EmailRow {
            label: "Event".to_string(),
            value: details.event_title.clone(),
        },
        EmailRow {
            label: "Date".to_string(),
            value: date_display.clone(),
        },
        EmailRow {
            label: "Time".to_string(),
            value: time_display,
        },
        EmailRow {
            label: "Guest".to_string(),
            value: format!("{} <{}>", details.guest_name, details.guest_email),
        },
    ];
    if let Some(loc) = &details.location {
        rows.push(EmailRow {
            label: "Location".to_string(),
            value: loc.clone(),
        });
    }

    let html = render_html_email(
        "Booking confirmed",
        &format!("You approved the booking with {}.", h(&details.guest_name)),
        "#16a34a",
        &rows,
        Some("The event has been added to your calendar."),
    );

    let body = build_multipart_body(&plain, &html);

    let email = Message::builder()
        .from(config.mailbox_from()?)
        .to(to)
        .subject(format!(
            "Confirmed: {} \u{2014} {} ({})",
            details.event_title, details.guest_name, date_display
        ))
        .multipart(body)?;

    send_email(config, email).await
}

/// Send booking reminder to the guest
pub async fn send_guest_reminder(
    config: &SmtpConfig,
    details: &BookingDetails,
    cancel_url: Option<&str>,
) -> Result<()> {
    let lang = guest_lang(details);
    let to = format!("{} <{}>", details.guest_name, details.guest_email).parse()?;

    let time_display = format!(
        "{} \u{2013} {} ({})",
        details.start_time, details.end_time, details.guest_timezone
    );

    let greeting = ta(
        lang,
        "email-confirm-greeting",
        [("name", &details.guest_name)],
    );
    let headline = t(lang, "email-reminder-headline");
    let label_event = t(lang, "confirmed-detail-event");
    let label_date = t(lang, "confirmed-detail-date");
    let label_time = t(lang, "confirmed-detail-time");
    let label_with = t(lang, "confirmed-detail-with");
    let label_location = t(lang, "confirmed-detail-location");
    let signature = t(lang, "email-signature");

    let plain = format!(
        "{}\n\n\
         {}\n\n\
         {} {}\n\
         {} {}\n\
         {} {}\n\
         {} {}\n\
         {}{}\n\
         {}",
        greeting,
        headline,
        label_event,
        details.event_title,
        label_date,
        details.date,
        label_time,
        time_display,
        label_with,
        details.host_name,
        details
            .location
            .as_ref()
            .map(|l| format!("{} {}\n", label_location, l))
            .unwrap_or_default(),
        cancel_url
            .map(|u| format!(
                "\n{}\n",
                ta(lang, "email-confirm-need-to-cancel", [("url", u)])
            ))
            .unwrap_or_default(),
        signature,
    );

    let mut rows = vec![
        EmailRow {
            label: label_event.clone(),
            value: details.event_title.clone(),
        },
        EmailRow {
            label: label_date.clone(),
            value: details.date.clone(),
        },
        EmailRow {
            label: label_time.clone(),
            value: time_display,
        },
        EmailRow {
            label: label_with.clone(),
            value: details.host_name.clone(),
        },
    ];
    if let Some(loc) = &details.location {
        rows.push(EmailRow {
            label: label_location.clone(),
            value: loc.clone(),
        });
    }

    let actions: Vec<EmailAction> = cancel_url
        .map(|u| {
            vec![EmailAction {
                label: t(lang, "email-action-cancel-booking"),
                url: u.to_string(),
                color: "#dc2626".to_string(),
            }]
        })
        .unwrap_or_default();

    let html =
        render_html_email_with_actions(&h(&greeting), &headline, "#3b82f6", &rows, None, &actions);

    let body = build_multipart_body(&plain, &html);

    let subject = ta(
        lang,
        "email-reminder-subject",
        [
            ("event", &details.event_title),
            ("time", &details.start_time),
        ],
    );
    let email = Message::builder()
        .from(config.mailbox_from()?)
        .to(to)
        .subject(subject)
        .multipart(body)?;

    send_email(config, email).await
}

/// Send booking reminder to the host
pub async fn send_host_reminder(config: &SmtpConfig, details: &BookingDetails) -> Result<()> {
    let to = format!("{} <{}>", details.host_name, details.host_email).parse()?;

    let (date_display, time_display) = host_time_display(
        &details.date,
        &details.start_time,
        &details.end_time,
        &details.guest_timezone,
        &details.host_timezone,
    );

    let plain = format!(
        "Reminder: you have an upcoming booking.\n\n\
         Event: {}\n\
         Date: {}\n\
         Time: {}\n\
         Guest: {} <{}>\n\
         {}\n\
         \u{2014} calrs",
        details.event_title,
        date_display,
        time_display,
        details.guest_name,
        details.guest_email,
        details
            .location
            .as_ref()
            .map(|l| format!("Location: {}\n", l))
            .unwrap_or_default(),
    );

    let rows = vec![
        EmailRow {
            label: "Event".to_string(),
            value: details.event_title.clone(),
        },
        EmailRow {
            label: "Date".to_string(),
            value: date_display.clone(),
        },
        EmailRow {
            label: "Time".to_string(),
            value: time_display,
        },
        EmailRow {
            label: "Guest".to_string(),
            value: format!("{} <{}>", details.guest_name, details.guest_email),
        },
    ];

    let html = render_html_email(
        "Upcoming booking",
        &format!(
            "Reminder: you have a booking with {} coming up.",
            h(&details.guest_name)
        ),
        "#3b82f6",
        &rows,
        None,
    );

    let body = build_multipart_body(&plain, &html);

    let email = Message::builder()
        .from(config.mailbox_from()?)
        .to(to)
        .subject(format!(
            "Reminder: {} \u{2014} {} ({})",
            details.event_title, details.guest_name, date_display
        ))
        .multipart(body)?;

    send_email(config, email).await
}

/// Send cancellation notification to the guest
pub async fn send_guest_cancellation(
    config: &SmtpConfig,
    details: &CancellationDetails,
) -> Result<()> {
    let ics = generate_cancel_ics(details);
    let lang = details.guest_language.as_deref().unwrap_or("en");

    let to = format!("{} <{}>", details.guest_name, details.guest_email).parse()?;

    let time_display = if details.guest_timezone.is_empty() {
        format!("{} \u{2013} {}", details.start_time, details.end_time)
    } else {
        format!(
            "{} \u{2013} {} ({})",
            details.start_time, details.end_time, details.guest_timezone
        )
    };

    let greeting = ta(
        lang,
        "email-confirm-greeting",
        [("name", &details.guest_name)],
    );
    let headline = if details.cancelled_by_host {
        ta(
            lang,
            "email-cancel-headline-by-host",
            [("host", &details.host_name)],
        )
    } else {
        t(lang, "email-cancel-headline-by-guest")
    };
    let label_event = t(lang, "confirmed-detail-event");
    let label_date = t(lang, "confirmed-detail-date");
    let label_time = t(lang, "confirmed-detail-time");
    let label_with = t(lang, "confirmed-detail-with");
    let label_reason = t(lang, "common-detail-reason");
    let ics_attached_plain = t(lang, "email-cancel-ics-attached-plain");
    let ics_attached_html = t(lang, "email-cancel-ics-attached-html");
    let signature = t(lang, "email-signature");

    let reason_text = details
        .reason
        .as_ref()
        .map(|r| format!("{} {}\n\n", label_reason, r))
        .unwrap_or_default();

    let plain = format!(
        "{}\n\n\
         {}\n\n\
         {} {}\n\
         {} {}\n\
         {} {}\n\
         {} {}\n\n\
         {}\
         {}\n\n\
         {}",
        greeting,
        headline,
        label_event,
        details.event_title,
        label_date,
        details.date,
        label_time,
        time_display,
        label_with,
        details.host_name,
        reason_text,
        ics_attached_plain,
        signature,
    );

    let mut rows = vec![
        EmailRow {
            label: label_event.clone(),
            value: details.event_title.clone(),
        },
        EmailRow {
            label: label_date.clone(),
            value: details.date.clone(),
        },
        EmailRow {
            label: label_time.clone(),
            value: time_display,
        },
        EmailRow {
            label: label_with.clone(),
            value: details.host_name.clone(),
        },
    ];
    if let Some(reason) = &details.reason {
        rows.push(EmailRow {
            label: label_reason.clone(),
            value: reason.clone(),
        });
    }

    let html = render_html_email(
        &h(&greeting),
        &headline,
        "#dc2626",
        &rows,
        Some(&ics_attached_html),
    );

    let body = build_multipart_body(&plain, &html);

    let ics_attachment = Attachment::new("cancel.ics".to_string()).body(
        ics,
        ContentType::parse("text/calendar; method=CANCEL; charset=UTF-8")?,
    );

    let subject = ta(
        lang,
        "email-cancel-subject",
        [("event", &details.event_title), ("date", &details.date)],
    );
    let email = Message::builder()
        .from(config.mailbox_from()?)
        .to(to)
        .subject(subject)
        .multipart(
            MultiPart::mixed()
                .multipart(body)
                .singlepart(ics_attachment),
        )?;

    send_email(config, email).await
}

/// Send cancellation notification to the host
pub async fn send_host_cancellation(
    config: &SmtpConfig,
    details: &CancellationDetails,
) -> Result<()> {
    let ics = generate_cancel_ics(details);

    let to = format!("{} <{}>", details.host_name, details.host_email).parse()?;

    let (date_display, time_display) = host_time_display(
        &details.date,
        &details.start_time,
        &details.end_time,
        &details.guest_timezone,
        &details.host_timezone,
    );
    let reason_text = details
        .reason
        .as_ref()
        .map(|r| format!("Reason: {}\n\n", r))
        .unwrap_or_default();

    let plain = format!(
        "Booking cancelled.\n\n\
         Event: {}\n\
         Date: {}\n\
         Time: {}\n\
         Guest: {} <{}>\n\n\
         {}\
         A calendar cancellation is attached.\n\n\
         \u{2014} calrs",
        details.event_title,
        date_display,
        time_display,
        details.guest_name,
        details.guest_email,
        reason_text,
    );

    let mut rows = vec![
        EmailRow {
            label: "Event".to_string(),
            value: details.event_title.clone(),
        },
        EmailRow {
            label: "Date".to_string(),
            value: date_display.clone(),
        },
        EmailRow {
            label: "Time".to_string(),
            value: time_display,
        },
        EmailRow {
            label: "Guest".to_string(),
            value: format!("{} <{}>", details.guest_name, details.guest_email),
        },
    ];
    if let Some(reason) = &details.reason {
        rows.push(EmailRow {
            label: "Reason".to_string(),
            value: reason.clone(),
        });
    }

    let html = render_html_email(
        "Booking cancelled.",
        &if details.cancelled_by_host {
            "You cancelled this booking.".to_string()
        } else {
            format!("{} cancelled their booking.", h(&details.guest_name))
        },
        "#dc2626",
        &rows,
        Some("A calendar cancellation is attached to this email."),
    );

    let body = build_multipart_body(&plain, &html);

    let ics_attachment = Attachment::new("cancel.ics".to_string()).body(
        ics,
        ContentType::parse("text/calendar; method=CANCEL; charset=UTF-8")?,
    );

    let email = Message::builder()
        .from(config.mailbox_from()?)
        .to(to)
        .subject(format!(
            "Cancelled: {} \u{2014} {} ({})",
            details.event_title, details.guest_name, date_display
        ))
        .multipart(
            MultiPart::mixed()
                .multipart(body)
                .singlepart(ics_attachment),
        )?;

    send_email(config, email).await
}

/// Send pending notice to guest (booking awaits host approval)
pub async fn send_guest_pending_notice(
    config: &SmtpConfig,
    details: &BookingDetails,
    cancel_url: Option<&str>,
) -> Result<()> {
    send_guest_pending_notice_ex(config, details, cancel_url, None).await
}

pub async fn send_guest_pending_notice_ex(
    config: &SmtpConfig,
    details: &BookingDetails,
    cancel_url: Option<&str>,
    reschedule_url: Option<&str>,
) -> Result<()> {
    let to = format!("{} <{}>", details.guest_name, details.guest_email).parse()?;

    let time_display = format!(
        "{} \u{2013} {} ({})",
        details.start_time, details.end_time, details.guest_timezone
    );

    // Don't include location in pending emails — it should only be revealed
    // after the booking is confirmed (prevents meeting link leaking).
    let plain = format!(
        "Hi {},\n\n\
         Your booking request has been received and is awaiting confirmation from {}.\n\n\
         Event: {}\n\
         Date: {}\n\
         Time: {}\n\
         {}\
         You'll receive another email once it's confirmed.\n\
         {}\n\
         \u{2014} calrs",
        details.guest_name,
        details.host_name,
        details.event_title,
        details.date,
        time_display,
        details
            .notes
            .as_ref()
            .map(|n| format!("Notes: {}\n", n))
            .unwrap_or_default(),
        cancel_url
            .map(|u| format!("\nNeed to cancel? {}\n", u))
            .unwrap_or_default(),
    );

    let mut rows = vec![
        EmailRow {
            label: "Event".to_string(),
            value: details.event_title.clone(),
        },
        EmailRow {
            label: "Date".to_string(),
            value: details.date.clone(),
        },
        EmailRow {
            label: "Time".to_string(),
            value: time_display,
        },
        EmailRow {
            label: "Host".to_string(),
            value: details.host_name.clone(),
        },
    ];
    if let Some(notes) = &details.notes {
        rows.push(EmailRow {
            label: "Notes".to_string(),
            value: notes.clone(),
        });
    }

    let mut actions: Vec<EmailAction> = Vec::new();
    if let Some(u) = reschedule_url {
        actions.push(EmailAction {
            label: "Reschedule".to_string(),
            url: u.to_string(),
            color: "#3b82f6".to_string(),
        });
    }
    if let Some(u) = cancel_url {
        actions.push(EmailAction {
            label: "Cancel booking".to_string(),
            url: u.to_string(),
            color: "#dc2626".to_string(),
        });
    }

    let html = render_html_email_with_actions(
        &format!("Hi {},", h(&details.guest_name)),
        &format!(
            "Your booking request is awaiting confirmation from {}.",
            h(&details.host_name)
        ),
        "#f59e0b",
        &rows,
        Some("You\u{2019}ll receive another email once it\u{2019}s confirmed."),
        &actions,
    );

    let body = build_multipart_body(&plain, &html);

    let email = Message::builder()
        .from(config.mailbox_from()?)
        .to(to)
        .subject(format!(
            "Pending: {} \u{2014} {}",
            details.event_title, details.date
        ))
        .multipart(body)?;

    send_email(config, email).await
}

/// Send approval request to host with approve/decline buttons
pub async fn send_host_approval_request(
    config: &SmtpConfig,
    details: &BookingDetails,
    _booking_id: &str,
    confirm_token: Option<&str>,
    base_url: Option<&str>,
) -> Result<()> {
    let to = format!("{} <{}>", details.host_name, details.host_email).parse()?;

    let (date_display, time_display) = host_time_display(
        &details.date,
        &details.start_time,
        &details.end_time,
        &details.guest_timezone,
        &details.host_timezone,
    );

    let (approve_url, decline_url) = match (confirm_token, base_url) {
        (Some(token), Some(url)) => (
            Some(format!(
                "{}/booking/approve/{}",
                url.trim_end_matches('/'),
                token
            )),
            Some(format!(
                "{}/booking/decline/{}",
                url.trim_end_matches('/'),
                token
            )),
        ),
        _ => (None, None),
    };

    let action_text = match (&approve_url, &decline_url) {
        (Some(a), Some(d)) => format!("Approve: {}\nDecline: {}", a, d),
        _ => "Log in to your dashboard to confirm or decline this booking.".to_string(),
    };

    let plain = format!(
        "New booking request requiring your approval!\n\n\
         Event: {}\n\
         Date: {}\n\
         Time: {}\n\
         Guest: {} <{}>\n\
         {}{}\n\
         {}\n\n\
         \u{2014} calrs",
        details.event_title,
        date_display,
        time_display,
        details.guest_name,
        details.guest_email,
        details
            .location
            .as_ref()
            .map(|l| format!("Location: {}\n", l))
            .unwrap_or_default(),
        details
            .notes
            .as_ref()
            .map(|n| format!("Notes: {}\n", n))
            .unwrap_or_default(),
        action_text,
    );

    let mut rows = vec![
        EmailRow {
            label: "Event".to_string(),
            value: details.event_title.clone(),
        },
        EmailRow {
            label: "Date".to_string(),
            value: date_display.clone(),
        },
        EmailRow {
            label: "Time".to_string(),
            value: time_display,
        },
        EmailRow {
            label: "Guest".to_string(),
            value: format!("{} <{}>", details.guest_name, details.guest_email),
        },
    ];
    if let Some(loc) = &details.location {
        rows.push(EmailRow {
            label: "Location".to_string(),
            value: loc.clone(),
        });
    }
    if let Some(notes) = &details.notes {
        rows.push(EmailRow {
            label: "Notes".to_string(),
            value: notes.clone(),
        });
    }

    let actions: Vec<EmailAction> = match (approve_url, decline_url) {
        (Some(a), Some(d)) => vec![
            EmailAction {
                label: "Approve".to_string(),
                url: a,
                color: "#16a34a".to_string(),
            },
            EmailAction {
                label: "Decline".to_string(),
                url: d,
                color: "#dc2626".to_string(),
            },
        ],
        _ => vec![],
    };

    let html = render_html_email_with_actions(
        "Action required",
        &format!("{} wants to book a slot with you.", h(&details.guest_name)),
        "#f59e0b",
        &rows,
        Some("You can also manage this from your dashboard."),
        &actions,
    );

    let body = build_multipart_body(&plain, &html);

    let email = Message::builder()
        .from(config.mailbox_from()?)
        .to(to)
        .subject(format!(
            "Action required: {} \u{2014} {} ({})",
            details.event_title, details.guest_name, date_display
        ))
        .multipart(body)?;

    send_email(config, email).await
}

/// Send decline notification to the guest
pub async fn send_guest_decline_notice(
    config: &SmtpConfig,
    details: &CancellationDetails,
) -> Result<()> {
    let to = format!("{} <{}>", details.guest_name, details.guest_email).parse()?;

    let time_display = if details.guest_timezone.is_empty() {
        format!("{} \u{2013} {}", details.start_time, details.end_time)
    } else {
        format!(
            "{} \u{2013} {} ({})",
            details.start_time, details.end_time, details.guest_timezone
        )
    };
    let reason_text = details
        .reason
        .as_ref()
        .map(|r| format!("Reason: {}\n\n", r))
        .unwrap_or_default();

    let plain = format!(
        "Hi {},\n\n\
         Your booking request has been declined.\n\n\
         Event: {}\n\
         Date: {}\n\
         Time: {}\n\
         With: {}\n\n\
         {}\
         \u{2014} calrs",
        details.guest_name,
        details.event_title,
        details.date,
        time_display,
        details.host_name,
        reason_text,
    );

    let mut rows = vec![
        EmailRow {
            label: "Event".to_string(),
            value: details.event_title.clone(),
        },
        EmailRow {
            label: "Date".to_string(),
            value: details.date.clone(),
        },
        EmailRow {
            label: "Time".to_string(),
            value: time_display,
        },
        EmailRow {
            label: "With".to_string(),
            value: details.host_name.clone(),
        },
    ];
    if let Some(reason) = &details.reason {
        rows.push(EmailRow {
            label: "Reason".to_string(),
            value: reason.clone(),
        });
    }

    let html = render_html_email(
        &format!("Hi {},", h(&details.guest_name)),
        "Your booking request has been declined.",
        "#dc2626",
        &rows,
        None,
    );

    let body = build_multipart_body(&plain, &html);

    let email = Message::builder()
        .from(config.mailbox_from()?)
        .to(to)
        .subject(format!(
            "Declined: {} \u{2014} {}",
            details.event_title, details.date
        ))
        .multipart(body)?;

    send_email(config, email).await
}

// --- Utility ---

const SMTP_ENV_VARS: &[&str] = &[
    "CALRS_SMTP_HOST",
    "CALRS_SMTP_PORT",
    "CALRS_SMTP_TLS_MODE",
    "CALRS_SMTP_USERNAME",
    "CALRS_SMTP_PASSWORD",
    "CALRS_SMTP_FROM_EMAIL",
    "CALRS_SMTP_FROM_NAME",
];

fn required_smtp_env(name: &str) -> Result<String> {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => Ok(value),
        Ok(_) => bail!("{} must not be empty", name),
        Err(_) => bail!(
            "{} is required when SMTP is configured via environment",
            name
        ),
    }
}

fn load_smtp_config_from_env() -> Result<Option<SmtpConfig>> {
    if !SMTP_ENV_VARS
        .iter()
        .any(|name| std::env::var_os(name).is_some())
    {
        return Ok(None);
    }

    let host = required_smtp_env("CALRS_SMTP_HOST")?;
    let username = required_smtp_env("CALRS_SMTP_USERNAME")?;
    let password = required_smtp_env("CALRS_SMTP_PASSWORD")?;
    let from_email = required_smtp_env("CALRS_SMTP_FROM_EMAIL")?;
    let port = match std::env::var("CALRS_SMTP_PORT") {
        Ok(value) if value.trim().is_empty() => bail!("CALRS_SMTP_PORT must not be empty"),
        Ok(value) => value.trim().parse::<u16>().map_err(|_| {
            anyhow::anyhow!("CALRS_SMTP_PORT must be a valid TCP port (got '{}')", value)
        })?,
        Err(_) => 587u16,
    };
    let tls_mode = match std::env::var("CALRS_SMTP_TLS_MODE") {
        Ok(value) if value.trim().is_empty() => bail!("CALRS_SMTP_TLS_MODE must not be empty"),
        Ok(value) => SmtpTlsMode::parse(&value)?,
        Err(_) => SmtpTlsMode::StartTls,
    };
    let from_name = std::env::var("CALRS_SMTP_FROM_NAME")
        .ok()
        .filter(|value| !value.trim().is_empty());

    Ok(Some(SmtpConfig {
        host,
        port,
        username,
        password,
        from_email,
        from_name,
        tls_mode,
    }))
}

/// Load SMTP config from environment or database.
pub async fn load_smtp_config(pool: &SqlitePool, key: &[u8; 32]) -> Result<Option<SmtpConfig>> {
    if let Some(config) = load_smtp_config_from_env()? {
        return Ok(Some(config));
    }

    let row: Option<(String, i32, String, String, String, Option<String>, String)> =
        sqlx::query_as(
            "SELECT host, port, username, password_enc, from_email, from_name, tls_mode
         FROM smtp_config WHERE enabled = 1 LIMIT 1",
        )
        .fetch_optional(pool)
        .await?;

    match row {
        Some((host, port, username, password_enc, from_email, from_name, tls_mode)) => {
            let password = crate::crypto::decrypt_password(key, &password_enc)?;
            let tls_mode = SmtpTlsMode::parse(&tls_mode).unwrap_or(SmtpTlsMode::StartTls);
            Ok(Some(SmtpConfig {
                host,
                port: port as u16,
                username,
                password,
                from_email,
                from_name,
                tls_mode,
            }))
        }
        None => Ok(None),
    }
}

/// Load non-secret SMTP status for admin display.
///
/// Unlike [`load_smtp_config`] this does NOT filter by `enabled = 1` — the
/// admin panel needs to surface a disabled-but-configured row so the operator
/// can see that SMTP exists and re-enable it. `load_smtp_config` only returns
/// rows that are actually usable for sending, so it keeps the `WHERE enabled`
/// guard.
pub async fn load_smtp_status(pool: &SqlitePool) -> Result<Option<SmtpStatus>> {
    if let Some(config) = load_smtp_config_from_env()? {
        return Ok(Some(SmtpStatus {
            host: config.host,
            port: config.port,
            from_email: config.from_email,
            enabled: true,
            from_env: true,
        }));
    }

    let row: Option<(String, i32, String, bool)> =
        sqlx::query_as("SELECT host, port, from_email, enabled FROM smtp_config LIMIT 1")
            .fetch_optional(pool)
            .await?;

    Ok(row.map(|(host, port, from_email, enabled)| SmtpStatus {
        host,
        port: port as u16,
        from_email,
        enabled,
        from_env: false,
    }))
}

/// Send a test email
pub async fn send_test_email(config: &SmtpConfig, to_email: &str) -> Result<()> {
    let to = to_email.parse()?;

    let plain = "This is a test email from calrs. SMTP is working!".to_string();

    let html = render_html_email(
        "SMTP test",
        "This is a test email from calrs. SMTP is working!",
        "#6366f1",
        &[],
        None,
    );

    let body = build_multipart_body(&plain, &html);

    let email = Message::builder()
        .from(config.mailbox_from()?)
        .to(to)
        .subject("calrs \u{2014} SMTP test")
        .multipart(body)?;

    // Debug is only useful when sending a test email
    tracing::debug!("Sending: {:?}", email);
    send_email(config, email).await
}

/// Send a booking invite email to a guest
pub async fn send_invite_email(
    config: &SmtpConfig,
    guest_name: &str,
    guest_email: &str,
    event_title: &str,
    host_name: &str,
    message: Option<&str>,
    invite_url: &str,
    expires_at: Option<&str>,
) -> Result<()> {
    let from = config.mailbox_from()?;
    let to = format!("{} <{}>", guest_name, guest_email).parse()?;

    let expiry_note = expires_at
        .map(|e| format!("\nThis invite expires on {}.", e))
        .unwrap_or_default();
    let message_note = message
        .filter(|m| !m.trim().is_empty())
        .map(|m| format!("\n\n\"{}\"\n", m))
        .unwrap_or_default();

    let plain = format!(
        "Hi {},\n\n\
         {} has invited you to book: {}\n\
         {}\
         Click the link below to choose a time:\n\
         {}\n\
         {}\n\
         \u{2014} calrs",
        guest_name, host_name, event_title, message_note, invite_url, expiry_note,
    );

    let mut rows = vec![
        EmailRow {
            label: "Event".to_string(),
            value: event_title.to_string(),
        },
        EmailRow {
            label: "Invited by".to_string(),
            value: host_name.to_string(),
        },
    ];
    if let Some(msg) = message.filter(|m| !m.trim().is_empty()) {
        rows.push(EmailRow {
            label: "Message".to_string(),
            value: msg.to_string(),
        });
    }
    if let Some(exp) = expires_at {
        rows.push(EmailRow {
            label: "Expires".to_string(),
            value: exp.to_string(),
        });
    }

    let actions = vec![EmailAction {
        label: "Choose a time".to_string(),
        url: invite_url.to_string(),
        color: "#6366f1".to_string(),
    }];

    let html = render_html_email_with_actions(
        &format!("Hi {},", h(guest_name)),
        &format!(
            "{} has invited you to book: {}",
            h(host_name),
            h(event_title)
        ),
        "#6366f1",
        &rows,
        None,
        &actions,
    );

    let body = build_multipart_body(&plain, &html);

    let email = Message::builder()
        .from(from)
        .to(to)
        .subject(format!(
            "{} invited you to book: {}",
            host_name, event_title
        ))
        .multipart(body)?;

    send_email(config, email).await
}

async fn send_email(config: &SmtpConfig, email: Message) -> Result<()> {
    let creds = Credentials::new(config.username.clone(), config.password.clone());

    let mailer = match config.tls_mode {
        SmtpTlsMode::Tls => AsyncSmtpTransport::<Tokio1Executor>::relay(&config.host)?
            .port(config.port)
            .credentials(creds)
            .build(),
        SmtpTlsMode::StartTls => {
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.host)?
                .port(config.port)
                .credentials(creds)
                .build()
        }
    };

    let to_addrs: Vec<String> = email
        .envelope()
        .to()
        .iter()
        .map(|a| a.to_string())
        .collect();
    let to_display = to_addrs.join(", ");
    match mailer.send(email).await {
        Ok(_) => {
            tracing::debug!(to = %to_display, "email delivered");
            Ok(())
        }
        Err(e) => {
            tracing::error!(to = %to_display, error = %e, "email delivery failed");
            Err(e.into())
        }
    }
}

// --- Reschedule emails ---

#[derive(Default)]
pub struct RescheduleDetails {
    pub event_title: String,
    pub old_date: String,
    pub old_start_time: String,
    pub old_end_time: String,
    pub new_date: String,
    pub new_start_time: String,
    pub new_end_time: String,
    pub guest_name: String,
    pub guest_email: String,
    pub guest_timezone: String,
    pub host_name: String,
    pub host_email: String,
    pub uid: String,
    pub location: Option<String>,
    /// Host's IANA timezone (from `users.timezone`). See `BookingDetails::host_timezone`.
    pub host_timezone: String,
}

/// Ask the guest to pick a new time (host-initiated reschedule).
/// The guest clicks the link to choose a slot — no time is pre-selected.
pub async fn send_guest_pick_new_time(
    config: &SmtpConfig,
    details: &BookingDetails,
    reschedule_url: &str,
    cancel_url: Option<&str>,
) -> Result<()> {
    let from = config.mailbox_from()?;
    let to = format!("{} <{}>", details.guest_name, details.guest_email).parse()?;

    let time_display = format!(
        "{} \u{2013} {} ({})",
        details.start_time, details.end_time, details.guest_timezone
    );

    let plain = format!(
        "Hi {},\n\n\
         {} needs to reschedule your booking.\n\n\
         Event: {}\n\
         Originally: {} at {}\n\n\
         Please pick a new time: {}\n\
         {}\n\
         \u{2014} calrs",
        details.guest_name,
        details.host_name,
        details.event_title,
        details.date,
        time_display,
        reschedule_url,
        cancel_url
            .map(|u| format!("\nOr cancel: {}\n", u))
            .unwrap_or_default(),
    );

    let rows = vec![
        EmailRow {
            label: "Event".to_string(),
            value: details.event_title.clone(),
        },
        EmailRow {
            label: "Originally".to_string(),
            value: format!("{} at {}", details.date, time_display),
        },
        EmailRow {
            label: "Host".to_string(),
            value: details.host_name.clone(),
        },
    ];

    let mut actions = vec![EmailAction {
        label: "Pick a new time".to_string(),
        url: reschedule_url.to_string(),
        color: "#d97706".to_string(),
    }];
    if let Some(u) = cancel_url {
        actions.push(EmailAction {
            label: "Cancel booking".to_string(),
            url: u.to_string(),
            color: "#dc2626".to_string(),
        });
    }

    let html = render_html_email_with_actions(
        &format!("Hi {},", h(&details.guest_name)),
        &format!(
            "{} needs to reschedule your booking. Please pick a new time.",
            h(&details.host_name)
        ),
        "#d97706",
        &rows,
        None,
        &actions,
    );

    let body = build_multipart_body(&plain, &html);

    let email = Message::builder()
        .from(from)
        .to(to)
        .subject(format!(
            "Reschedule: {} \u{2014} please pick a new time",
            details.event_title
        ))
        .multipart(body)?;

    send_email(config, email).await
}

/// Notify the guest that their booking was rescheduled by the host.
/// Includes updated ICS calendar invite.
pub async fn send_guest_reschedule_notification(
    config: &SmtpConfig,
    details: &RescheduleDetails,
    cancel_url: Option<&str>,
    reschedule_url: Option<&str>,
) -> Result<()> {
    let new_time_display = format!(
        "{} \u{2013} {} ({})",
        details.new_start_time, details.new_end_time, details.guest_timezone
    );

    let booking_details = BookingDetails {
        event_title: details.event_title.clone(),
        date: details.new_date.clone(),
        start_time: details.new_start_time.clone(),
        end_time: details.new_end_time.clone(),
        guest_name: details.guest_name.clone(),
        guest_email: details.guest_email.clone(),
        guest_timezone: details.guest_timezone.clone(),
        host_name: details.host_name.clone(),
        host_email: details.host_email.clone(),
        uid: details.uid.clone(),
        notes: None,
        location: details.location.clone(),
        reminder_minutes: None,
        additional_attendees: vec![],
        ..Default::default()
    };
    let ics = generate_ics(&booking_details, "REQUEST");

    let to = format!("{} <{}>", details.guest_name, details.guest_email).parse()?;

    let plain = format!(
        "Hi {},\n\n\
         Your booking has been rescheduled by {}.\n\n\
         Event: {}\n\
         Previous: {} at {} \u{2013} {}\n\
         New: {} at {}\n\
         {}\
         An updated calendar invite is attached.\n\
         {}{}\n\
         \u{2014} calrs",
        details.guest_name,
        details.host_name,
        details.event_title,
        details.old_date,
        details.old_start_time,
        details.old_end_time,
        details.new_date,
        new_time_display,
        details
            .location
            .as_ref()
            .map(|l| format!("Location: {}\n", l))
            .unwrap_or_default(),
        cancel_url
            .map(|u| format!("Need to cancel? {}\n", u))
            .unwrap_or_default(),
        reschedule_url
            .map(|u| format!("Need to reschedule? {}\n", u))
            .unwrap_or_default(),
    );

    let rows = vec![
        EmailRow {
            label: "Event".to_string(),
            value: details.event_title.clone(),
        },
        EmailRow {
            label: "Previous".to_string(),
            value: format!(
                "{} at {} \u{2013} {}",
                details.old_date, details.old_start_time, details.old_end_time
            ),
        },
        EmailRow {
            label: "New date".to_string(),
            value: details.new_date.clone(),
        },
        EmailRow {
            label: "New time".to_string(),
            value: new_time_display,
        },
        EmailRow {
            label: "With".to_string(),
            value: details.host_name.clone(),
        },
    ];

    let mut actions = Vec::new();
    if let Some(u) = reschedule_url {
        actions.push(EmailAction {
            label: "Reschedule".to_string(),
            url: u.to_string(),
            color: "#d97706".to_string(),
        });
    }
    if let Some(u) = cancel_url {
        actions.push(EmailAction {
            label: "Cancel booking".to_string(),
            url: u.to_string(),
            color: "#dc2626".to_string(),
        });
    }

    let html = render_html_email_with_actions(
        &format!("Hi {},", h(&details.guest_name)),
        &format!(
            "Your booking has been rescheduled by {}.",
            h(&details.host_name)
        ),
        "#d97706",
        &rows,
        Some("An updated calendar invite is attached to this email."),
        &actions,
    );

    let body = build_multipart_body(&plain, &html);

    let ics_attachment = Attachment::new("invite.ics".to_string()).body(
        ics,
        ContentType::parse("text/calendar; method=REQUEST; charset=UTF-8")?,
    );

    let email = Message::builder()
        .from(config.mailbox_from()?)
        .to(to)
        .subject(format!(
            "Rescheduled: {} \u{2014} {}",
            details.event_title, details.new_date
        ))
        .multipart(
            MultiPart::mixed()
                .multipart(body)
                .singlepart(ics_attachment),
        )?;

    send_email(config, email).await
}

/// Notify the host that a guest wants to reschedule — includes approve/decline buttons.
pub async fn send_host_reschedule_request(
    config: &SmtpConfig,
    details: &RescheduleDetails,
    confirm_token: Option<&str>,
    base_url: Option<&str>,
) -> Result<()> {
    let (old_date_display, old_time_display) = host_time_display(
        &details.old_date,
        &details.old_start_time,
        &details.old_end_time,
        &details.guest_timezone,
        &details.host_timezone,
    );
    let (new_date_display, new_time_display) = host_time_display(
        &details.new_date,
        &details.new_start_time,
        &details.new_end_time,
        &details.guest_timezone,
        &details.host_timezone,
    );

    let to = format!("{} <{}>", details.host_name, details.host_email).parse()?;

    let (approve_url, decline_url) = match (confirm_token, base_url) {
        (Some(token), Some(url)) => (
            Some(format!(
                "{}/booking/approve/{}",
                url.trim_end_matches('/'),
                token
            )),
            Some(format!(
                "{}/booking/decline/{}",
                url.trim_end_matches('/'),
                token
            )),
        ),
        _ => (None, None),
    };

    let action_text = match (&approve_url, &decline_url) {
        (Some(a), Some(d)) => format!("Approve: {}\nDecline: {}", a, d),
        _ => "Log in to your dashboard to confirm or decline.".to_string(),
    };

    let plain = format!(
        "{} wants to reschedule their booking.\n\n\
         Event: {}\n\
         Previous: {} at {}\n\
         Requested: {} at {}\n\
         Guest: {} <{}>\n\
         {}\n\n\
         {}\n\n\
         \u{2014} calrs",
        details.guest_name,
        details.event_title,
        old_date_display,
        old_time_display,
        new_date_display,
        new_time_display,
        details.guest_name,
        details.guest_email,
        details
            .location
            .as_ref()
            .map(|l| format!("Location: {}\n", l))
            .unwrap_or_default(),
        action_text,
    );

    let rows = vec![
        EmailRow {
            label: "Event".to_string(),
            value: details.event_title.clone(),
        },
        EmailRow {
            label: "Previous".to_string(),
            value: format!("{} at {}", old_date_display, old_time_display),
        },
        EmailRow {
            label: "Requested".to_string(),
            value: format!("{} at {}", new_date_display, new_time_display),
        },
        EmailRow {
            label: "Guest".to_string(),
            value: format!("{} <{}>", details.guest_name, details.guest_email),
        },
    ];

    let mut actions = Vec::new();
    if let Some(u) = &approve_url {
        actions.push(EmailAction {
            label: "Approve".to_string(),
            url: u.clone(),
            color: "#16a34a".to_string(),
        });
    }
    if let Some(u) = &decline_url {
        actions.push(EmailAction {
            label: "Decline".to_string(),
            url: u.clone(),
            color: "#dc2626".to_string(),
        });
    }

    let html = render_html_email_with_actions(
        &format!("Hi {},", h(&details.host_name)),
        &format!(
            "{} wants to reschedule their booking.",
            h(&details.guest_name)
        ),
        "#d97706",
        &rows,
        None,
        &actions,
    );

    let body = build_multipart_body(&plain, &html);

    let email = Message::builder()
        .from(config.mailbox_from()?)
        .to(to)
        .subject(format!(
            "Reschedule request: {} \u{2014} {} <{}>",
            details.event_title, details.guest_name, details.guest_email
        ))
        .multipart(body)?;

    send_email(config, email).await
}

// --- Watcher claim emails ---

pub async fn send_watcher_claim_notification(
    config: &SmtpConfig,
    details: &BookingDetails,
    watcher_name: &str,
    watcher_email: &str,
    assigned_to_name: &str,
    claim_url: &str,
) -> Result<()> {
    let to = format!("{} <{}>", watcher_name, watcher_email).parse()?;

    let time_display = format!("{} \u{2013} {}", details.start_time, details.end_time);

    let plain = format!(
        "New booking available to claim!\n\n\
         Event: {}\n\
         Date: {}\n\
         Time: {}\n\
         Guest: {} <{}>\n\
         Assigned to: {}\n\
         {}\
         Claim this booking: {}\n\n\
         \u{2014} calrs",
        details.event_title,
        details.date,
        time_display,
        details.guest_name,
        details.guest_email,
        assigned_to_name,
        details
            .location
            .as_ref()
            .map(|l| format!("Location: {}\n", l))
            .unwrap_or_default(),
        claim_url,
    );

    let mut rows = vec![
        EmailRow {
            label: "Event".to_string(),
            value: details.event_title.clone(),
        },
        EmailRow {
            label: "Date".to_string(),
            value: details.date.clone(),
        },
        EmailRow {
            label: "Time".to_string(),
            value: time_display,
        },
        EmailRow {
            label: "Guest".to_string(),
            value: format!("{} <{}>", details.guest_name, details.guest_email),
        },
        EmailRow {
            label: "Assigned to".to_string(),
            value: assigned_to_name.to_string(),
        },
    ];
    if let Some(loc) = &details.location {
        rows.push(EmailRow {
            label: "Location".to_string(),
            value: loc.clone(),
        });
    }

    let actions = vec![EmailAction {
        label: "Claim this booking".to_string(),
        url: claim_url.to_string(),
        color: "#3b82f6".to_string(),
    }];

    let html = render_html_email_with_actions(
        &format!("Hi {},", h(watcher_name)),
        "A new booking is available to claim. Click below to join as an attendee.",
        "#3b82f6",
        &rows,
        Some("You can also claim from your dashboard."),
        &actions,
    );

    let body = build_multipart_body(&plain, &html);

    let email = Message::builder()
        .from(config.mailbox_from()?)
        .to(to)
        .subject(format!(
            "Claim available: {} \u{2014} {} ({})",
            details.event_title, details.guest_name, details.date
        ))
        .multipart(body)?;

    send_email(config, email).await
}

pub async fn send_claim_confirmation(
    config: &SmtpConfig,
    details: &BookingDetails,
    claimant_name: &str,
    claimant_email: &str,
) -> Result<()> {
    let to = format!("{} <{}>", claimant_name, claimant_email).parse()?;

    let time_display = format!("{} \u{2013} {}", details.start_time, details.end_time);

    let plain = format!(
        "You claimed this booking!\n\n\
         Event: {}\n\
         Date: {}\n\
         Time: {}\n\
         Guest: {} <{}>\n\
         {}\
         A calendar invite has been sent.\n\n\
         \u{2014} calrs",
        details.event_title,
        details.date,
        time_display,
        details.guest_name,
        details.guest_email,
        details
            .location
            .as_ref()
            .map(|l| format!("Location: {}\n", l))
            .unwrap_or_default(),
    );

    let mut rows = vec![
        EmailRow {
            label: "Event".to_string(),
            value: details.event_title.clone(),
        },
        EmailRow {
            label: "Date".to_string(),
            value: details.date.clone(),
        },
        EmailRow {
            label: "Time".to_string(),
            value: time_display,
        },
        EmailRow {
            label: "Guest".to_string(),
            value: format!("{} <{}>", details.guest_name, details.guest_email),
        },
    ];
    if let Some(loc) = &details.location {
        rows.push(EmailRow {
            label: "Location".to_string(),
            value: loc.clone(),
        });
    }

    let html = render_html_email(
        &format!("Hi {},", h(claimant_name)),
        "You have successfully claimed this booking. A calendar invite is attached.",
        "#16a34a",
        &rows,
        Some("You will be added as an attendee on this meeting."),
    );

    let body = build_multipart_body(&plain, &html);

    let email = Message::builder()
        .from(config.mailbox_from()?)
        .to(to)
        .subject(format!(
            "Booking claimed: {} \u{2014} {} ({})",
            details.event_title, details.guest_name, details.date
        ))
        .multipart(body)?;

    send_email(config, email).await
}

#[cfg(test)]
mod tests;
