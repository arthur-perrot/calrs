use std::io::{self, Write};

use chrono::{NaiveDate, NaiveDateTime};
use chrono_tz::Tz;

/// Parse an iCal datetime string into a `NaiveDateTime`.
///
/// Accepts the four shapes calrs sees in the wild:
/// - compact `YYYYMMDDTHHMMSS`
/// - ISO `YYYY-MM-DDTHH:MM:SS`
/// - date-only `YYYYMMDD` / `YYYY-MM-DD` (returns 00:00:00)
///
/// A trailing `Z` (UTC marker) is stripped before parsing — the caller is
/// expected to carry the timezone separately (e.g. via the `events.timezone`
/// column populated from `extract_vevent_tzid`). Keeping a single helper for
/// every busy-time path means the next Exchange format quirk is fixed in one
/// spot.
pub fn parse_ical_datetime(s: &str) -> Option<NaiveDateTime> {
    let s = s.strip_suffix('Z').unwrap_or(s);
    NaiveDateTime::parse_from_str(s, "%Y%m%dT%H%M%S")
        .ok()
        .or_else(|| NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S").ok())
        .or_else(|| {
            NaiveDate::parse_from_str(s, "%Y%m%d")
                .ok()
                .and_then(|d| d.and_hms_opt(0, 0, 0))
        })
        .or_else(|| {
            NaiveDate::parse_from_str(s, "%Y-%m-%d")
                .ok()
                .and_then(|d| d.and_hms_opt(0, 0, 0))
        })
}

/// Split an iCal blob into individual VEVENT blocks.
/// A single CalDAV resource can contain multiple VEVENTs when a recurring
/// event has modified instances (RECURRENCE-ID).
pub fn split_vevents(ical: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut search_from = 0;
    while let Some(start) = ical[search_from..].find("BEGIN:VEVENT") {
        let abs_start = search_from + start;
        if let Some(end) = ical[abs_start..].find("END:VEVENT") {
            let abs_end = abs_start + end + "END:VEVENT".len();
            blocks.push(ical[abs_start..abs_end].to_string());
            search_from = abs_end;
        } else {
            break;
        }
    }
    if blocks.is_empty() {
        blocks.push(ical.to_string());
    }
    blocks
}

/// Extract a field value from a single VEVENT block.
pub fn extract_vevent_field(vevent: &str, field: &str) -> Option<String> {
    for line in vevent.lines() {
        if line.starts_with(field) {
            if let Some(colon_pos) = line.find(':') {
                let value = line[colon_pos + 1..].trim().to_string();
                if !value.is_empty() {
                    return Some(value);
                }
            }
        }
    }
    None
}

/// Extract the TZID from a DTSTART or DTEND line in a VEVENT block.
///
/// - `DTSTART;TZID=Europe/Paris:20260310T100000` → `Some("Europe/Paris")`
/// - `DTSTART:20260310T100000Z` → `Some("UTC")`
/// - `DTSTART:20260310T100000` (no TZID, no Z) → `None` (floating/local)
/// - `DTSTART;VALUE=DATE:20260310` → `None` (all-day)
pub fn extract_vevent_tzid(vevent: &str, field: &str) -> Option<String> {
    for line in vevent.lines() {
        if !line.starts_with(field) {
            continue;
        }
        // Ensure we match the exact field, not a prefix (e.g. DTSTART vs DTSTART-EXTRA)
        let rest = &line[field.len()..];
        if rest.is_empty() {
            continue;
        }
        let first = rest.as_bytes()[0];
        if first != b';' && first != b':' {
            continue;
        }

        // Check for VALUE=DATE (all-day) — no timezone
        if rest.contains("VALUE=DATE") {
            return None;
        }

        // Check for TZID= parameter
        if let Some(tzid_pos) = rest.find("TZID=") {
            let after_tzid = &rest[tzid_pos + 5..];
            // TZID value ends at ':' or ';'
            let end = after_tzid.find([':', ';']).unwrap_or(after_tzid.len());
            let tz = after_tzid[..end].trim();
            if !tz.is_empty() {
                return Some(tz.to_string());
            }
        }

        // Check for trailing Z (UTC)
        if let Some(colon_pos) = rest.find(':') {
            let value = rest[colon_pos + 1..].trim();
            if value.ends_with('Z') {
                return Some("UTC".to_string());
            }
        }

        // No TZID, no Z → floating
        return None;
    }
    None
}

/// Convert a NaiveDateTime from the event's timezone to the target timezone.
///
/// - If `event_tz` is `Some` and a valid IANA timezone → convert
/// - If `None` (floating) → return as-is (backward-compatible)
/// - If IANA parse fails → return as-is (graceful degradation)
pub fn convert_event_to_tz(
    dt: NaiveDateTime,
    event_tz: Option<&str>,
    target_tz: Tz,
) -> NaiveDateTime {
    let etz: Tz = match event_tz {
        Some(tz_str) => match tz_str.parse::<Tz>() {
            Ok(tz) => tz,
            Err(_) => return dt,
        },
        None => return dt,
    };

    // Convert: event's local time → absolute instant → target TZ local time
    use chrono::TimeZone;
    match etz.from_local_datetime(&dt).earliest() {
        Some(zoned) => zoned.with_timezone(&target_tz).naive_local(),
        None => dt, // impossible time during DST transition
    }
}

/// Render a Markdown string to safe inline HTML.
///
/// Only allows inline elements: links, bold, italic, strikethrough, inline code.
/// Block-level elements (headings, lists, images, code blocks) are stripped.
/// All HTML tags in the input are escaped by pulldown-cmark.
/// Links get `target="_blank"` and `rel="noopener noreferrer"` for safety.
pub fn render_inline_markdown(text: &str) -> String {
    use pulldown_cmark::{Event, Options, Parser, Tag, TagEnd};

    let parser = Parser::new_ext(text, Options::ENABLE_STRIKETHROUGH);

    // Filter to inline-only elements
    let filtered = parser.filter(|event| {
        !matches!(
            event,
            Event::Start(
                Tag::Heading { .. }
                    | Tag::BlockQuote(_)
                    | Tag::CodeBlock(_)
                    | Tag::Image { .. }
                    | Tag::List(_)
                    | Tag::Item
                    | Tag::Table(_)
                    | Tag::TableHead
                    | Tag::TableRow
                    | Tag::TableCell
                    | Tag::HtmlBlock
            ) | Event::End(
                TagEnd::Heading(_)
                    | TagEnd::BlockQuote(_)
                    | TagEnd::CodeBlock
                    | TagEnd::Image
                    | TagEnd::List(_)
                    | TagEnd::Item
                    | TagEnd::Table
                    | TagEnd::TableHead
                    | TagEnd::TableRow
                    | TagEnd::TableCell
                    | TagEnd::HtmlBlock
            ) | Event::Html(_)
                | Event::InlineHtml(_)
        )
    });

    let mut html = String::new();
    pulldown_cmark::html::push_html(&mut html, filtered);

    // Add target="_blank" and rel="noopener noreferrer" to links
    html = html.replace(
        "<a href=",
        "<a target=\"_blank\" rel=\"noopener noreferrer\" href=",
    );

    // Strip wrapping <p> tags to keep it inline
    let trimmed = html.trim();
    if trimmed.starts_with("<p>") && trimmed.ends_with("</p>") {
        // Check if there's only one <p> block
        let inner = &trimmed[3..trimmed.len() - 4];
        if !inner.contains("<p>") {
            return inner.to_string();
        }
    }

    // Multiple paragraphs: replace </p><p> with <br> for compact display
    html.trim()
        .replace("</p>\n<p>", "<br>")
        .trim_start_matches("<p>")
        .trim_end_matches("</p>")
        .to_string()
}

pub fn prompt(label: &str) -> String {
    print!("{}: ", label);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}

pub fn prompt_password(label: &str) -> String {
    rpassword::prompt_password(format!("{}: ", label)).unwrap_or_default()
}

#[cfg(test)]
mod tests;
