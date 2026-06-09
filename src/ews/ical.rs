//! Convert EWS calendar items into iCalendar text.
//!
//! When sync responses ship MIME content we can extract the iCal block
//! verbatim (see [`super::parse::extract_vcalendar`]). For lighter `FindItem`
//! results we synthesise a minimal VEVENT from the structured fields. The
//! goal is feature parity with the CalDAV path: calrs only needs UID, start,
//! end, summary, location, status, and the all-day flag to compute slot
//! availability.

use super::parse::EwsCalendarItem;

/// Synthesise a minimal `BEGIN:VCALENDAR…END:VCALENDAR` block from a
/// `FindItem` result. Useful when the caller doesn't want a follow-up
/// `GetItem` round trip.
pub fn synth_vcalendar(item: &EwsCalendarItem) -> Option<String> {
    let uid = item
        .uid
        .clone()
        .or_else(|| Some(item.item_id.clone()))
        .filter(|s| !s.is_empty())?;
    let start = item.start.clone()?;
    let end = item.end.clone()?;

    let dtstart = format_dt(&start, item.is_all_day);
    let dtend = format_dt(&end, item.is_all_day);

    let summary = item
        .subject
        .as_deref()
        .map(escape_ical_text)
        .unwrap_or_default();
    let location = item
        .location
        .as_deref()
        .map(escape_ical_text)
        .unwrap_or_default();

    // calrs availability checks treat TRANSPARENT events as non-blocking. EWS
    // exposes that intent via LegacyFreeBusyStatus.
    let transp = match item.free_busy_status.as_deref() {
        Some("Free") | Some("Tentative") => "TRANSPARENT",
        _ => "OPAQUE",
    };

    let status = if item.is_cancelled {
        "CANCELLED"
    } else {
        "CONFIRMED"
    };

    // RFC 5545 requires DTSTAMP on every VEVENT. EWS doesn't expose a stable
    // "last modified" we can map to it, so we emit "now" — strict consumers
    // get a valid VEVENT, calrs availability code ignores DTSTAMP.
    let dtstamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();

    let mut buf = String::new();
    buf.push_str("BEGIN:VCALENDAR\r\n");
    buf.push_str("VERSION:2.0\r\n");
    buf.push_str("PRODID:-//calrs//ews-bridge//EN\r\n");
    buf.push_str("BEGIN:VEVENT\r\n");
    buf.push_str(&format!("UID:{uid}\r\n"));
    buf.push_str(&format!("DTSTAMP:{dtstamp}\r\n"));
    buf.push_str(&format!("DTSTART{dtstart}\r\n"));
    buf.push_str(&format!("DTEND{dtend}\r\n"));
    if item.has_recurrence {
        // CalendarView returns occurrences of a recurring series as separate
        // items sharing the master's UID. Without RECURRENCE-ID they would
        // collide on the `(calendar_id, uid, recurrence_id)` upsert key and
        // collapse into one row, dropping every occurrence but the last.
        // Using the occurrence's start as RECURRENCE-ID keeps each one
        // addressable.
        //
        // Caveat: canonically RECURRENCE-ID is the occurrence's *original*
        // start. Using the new start means a rescheduled exception that lands
        // exactly on a sibling occurrence's start collides on the upsert key
        // (one row wins). Busy-time semantics are unaffected — both rows block
        // the same instant — and retrieving the original start would cost an
        // extra per-item property fetch, so we accept the edge case.
        buf.push_str(&format!("RECURRENCE-ID{dtstart}\r\n"));
    }
    if !summary.is_empty() {
        buf.push_str(&format!("SUMMARY:{summary}\r\n"));
    }
    if !location.is_empty() {
        buf.push_str(&format!("LOCATION:{location}\r\n"));
    }
    buf.push_str(&format!("TRANSP:{transp}\r\n"));
    buf.push_str(&format!("STATUS:{status}\r\n"));
    buf.push_str("END:VEVENT\r\n");
    buf.push_str("END:VCALENDAR\r\n");
    Some(buf)
}

/// Format an EWS datetime (`2026-05-06T09:00:00Z` or
/// `2026-05-08T00:00:00`) as the iCal property value.
///
/// All-day items are emitted as timed UTC values, *not* `VALUE=DATE`: EWS
/// reports the boundaries in UTC (e.g. an all-day 13/06 in a Paris mailbox
/// arrives as `Start=2026-06-12T22:00:00Z`), and stripping to a `YYYYMMDD`
/// prefix here would shift the event to the previous local day. By keeping
/// the full UTC timestamp and emitting `timezone=UTC` (via the `Z` suffix),
/// downstream `convert_event_to_tz` resolves the right local date for any
/// host TZ — including DST transitions.
///
/// TODO: naive-local datetimes are currently emitted as floating values
/// (no `TZID` parameter). EWS normally returns UTC, but tenants with a
/// non-UTC default may surface naive locals, which would be misread as
/// the host's local time during availability checks. Recurring events
/// already escape via the MIME path; the gap is limited to non-recurring
/// naive-local items synthesised from `FindItem`. Tracking in the issue
/// tracker for a follow-up.
fn format_dt(value: &str, _all_day: bool) -> String {
    // EWS UTC is YYYY-MM-DDTHH:MM:SSZ → iCal UTC YYYYMMDDTHHMMSSZ.
    // Naive locals (no Z) pass through as floating; downstream handles both.
    let stripped = value.replace(['-', ':'], "");
    format!(":{}", stripped.trim())
}

/// Escape a string for embedding in an iCal TEXT property. Per RFC 5545:
/// backslash, comma, semicolon and newlines need escaping.
fn escape_ical_text(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            ',' => out.push_str("\\,"),
            ';' => out.push_str("\\;"),
            '\n' => out.push_str("\\n"),
            '\r' => {}
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests;
