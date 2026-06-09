use super::*;

fn item(start: &str, end: &str, all_day: bool) -> EwsCalendarItem {
    EwsCalendarItem {
        item_id: "ID".to_string(),
        change_key: None,
        uid: Some("uid-1".to_string()),
        subject: Some("Hello, world".to_string()),
        start: Some(start.to_string()),
        end: Some(end.to_string()),
        location: Some("Room 1".to_string()),
        is_all_day: all_day,
        is_cancelled: false,
        free_busy_status: Some("Busy".to_string()),
        has_recurrence: false,
    }
}

#[test]
fn synth_basic_event() {
    let it = item("2026-05-06T09:00:00Z", "2026-05-06T09:30:00Z", false);
    let ics = synth_vcalendar(&it).unwrap();
    assert!(ics.contains("UID:uid-1"));
    assert!(ics.contains("DTSTART:20260506T090000Z"));
    assert!(ics.contains("DTEND:20260506T093000Z"));
    // RFC 5545 escaping: comma must be backslash-escaped
    assert!(ics.contains("SUMMARY:Hello\\, world"));
    assert!(ics.contains("LOCATION:Room 1"));
    assert!(ics.contains("TRANSP:OPAQUE"));
    assert!(ics.contains("STATUS:CONFIRMED"));
}

#[test]
fn synth_all_day_naive_passes_through_floating() {
    let it = item("2026-05-08T00:00:00", "2026-05-09T00:00:00", true);
    let ics = synth_vcalendar(&it).unwrap();
    assert!(ics.contains("DTSTART:20260508T000000"));
    assert!(ics.contains("DTEND:20260509T000000"));
    // No VALUE=DATE: we treat all-day as timed so downstream UTC→local
    // conversion can produce the right host-TZ date.
    assert!(!ics.contains("VALUE=DATE"));
}

/// Regression: a Paris all-day event for 13/06 reaches us as
/// `Start=2026-06-12T22:00:00Z`. The previous `VALUE=DATE` path stripped
/// to `20260612` and silently shifted the event to the prior day.
/// Keeping the Z-suffixed UTC value lets downstream conversion land it on
/// 13/06 in `Europe/Paris`.
#[test]
fn synth_all_day_utc_keeps_z_suffix_for_local_conversion() {
    let it = item("2026-06-12T22:00:00Z", "2026-06-13T22:00:00Z", true);
    let ics = synth_vcalendar(&it).unwrap();
    assert!(ics.contains("DTSTART:20260612T220000Z"));
    assert!(ics.contains("DTEND:20260613T220000Z"));
    assert!(!ics.contains("VALUE=DATE"));
}

#[test]
fn synth_marks_free_as_transparent() {
    let mut it = item("2026-05-06T09:00:00Z", "2026-05-06T09:30:00Z", false);
    it.free_busy_status = Some("Free".to_string());
    let ics = synth_vcalendar(&it).unwrap();
    assert!(ics.contains("TRANSP:TRANSPARENT"));
}

#[test]
fn synth_marks_cancelled_status() {
    let mut it = item("2026-05-06T09:00:00Z", "2026-05-06T09:30:00Z", false);
    it.is_cancelled = true;
    let ics = synth_vcalendar(&it).unwrap();
    assert!(ics.contains("STATUS:CANCELLED"));
}

/// Regression: occurrences returned by `CalendarView` share their master's
/// UID. Without a RECURRENCE-ID they all collapsed into one DB row via the
/// `(uid, recurrence_id)` upsert key, dropping every occurrence but the
/// last. Emitting RECURRENCE-ID equal to the occurrence's start keeps each
/// one uniquely addressable.
#[test]
fn synth_emits_recurrence_id_for_recurring_occurrence() {
    let mut it = item("2026-06-10T07:45:00Z", "2026-06-10T08:15:00Z", false);
    it.has_recurrence = true;
    let ics = synth_vcalendar(&it).unwrap();
    assert!(ics.contains("DTSTART:20260610T074500Z"));
    assert!(ics.contains("RECURRENCE-ID:20260610T074500Z"));
}

#[test]
fn synth_omits_recurrence_id_for_non_recurring_event() {
    let it = item("2026-06-10T07:45:00Z", "2026-06-10T08:15:00Z", false);
    // has_recurrence defaults to false in the test helper.
    let ics = synth_vcalendar(&it).unwrap();
    assert!(!ics.contains("RECURRENCE-ID"));
}

#[test]
fn synth_uses_item_id_when_uid_missing() {
    let mut it = item("2026-05-06T09:00:00Z", "2026-05-06T09:30:00Z", false);
    it.uid = None;
    let ics = synth_vcalendar(&it).unwrap();
    assert!(ics.contains("UID:ID"));
}
