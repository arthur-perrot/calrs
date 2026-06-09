use super::*;

fn dt(y: i32, m: u32, d: u32, h: u32, min: u32) -> NaiveDateTime {
    NaiveDate::from_ymd_opt(y, m, d)
        .unwrap()
        .and_hms_opt(h, min, 0)
        .unwrap()
}

#[test]
fn test_weekly_monday() {
    let start = dt(2026, 2, 23, 16, 0);
    let end = dt(2026, 2, 23, 18, 0);
    let window_start = dt(2026, 3, 23, 0, 0);
    let window_end = dt(2026, 3, 24, 0, 0);

    let results = expand_rrule(
        start,
        end,
        "FREQ=WEEKLY;INTERVAL=1;BYDAY=MO",
        &[],
        window_start,
        window_end,
    );
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].0, dt(2026, 3, 23, 16, 0));
    assert_eq!(results[0].1, dt(2026, 3, 23, 18, 0));
}

#[test]
fn test_weekly_with_until() {
    let start = dt(2026, 1, 5, 10, 0);
    let end = dt(2026, 1, 5, 11, 0);
    let window_start = dt(2026, 2, 1, 0, 0);
    let window_end = dt(2026, 3, 1, 0, 0);

    let results = expand_rrule(
        start,
        end,
        "FREQ=WEEKLY;UNTIL=20260209T100000;BYDAY=MO",
        &[],
        window_start,
        window_end,
    );
    assert_eq!(results.len(), 2); // Feb 2 and Feb 9
    assert_eq!(
        results[0].0.date(),
        NaiveDate::from_ymd_opt(2026, 2, 2).unwrap()
    );
    assert_eq!(
        results[1].0.date(),
        NaiveDate::from_ymd_opt(2026, 2, 9).unwrap()
    );
}

#[test]
fn test_monthly_2nd_monday() {
    let start = dt(2026, 1, 12, 16, 0);
    let end = dt(2026, 1, 12, 17, 0);
    let window_start = dt(2026, 3, 1, 0, 0);
    let window_end = dt(2026, 4, 1, 0, 0);

    let results = expand_rrule(
        start,
        end,
        "FREQ=MONTHLY;INTERVAL=1;BYDAY=2MO",
        &[],
        window_start,
        window_end,
    );
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].0, dt(2026, 3, 9, 16, 0)); // 2nd Monday of March 2026
}

#[test]
fn test_exdate_exclusion() {
    let start = dt(2026, 3, 2, 10, 0);
    let end = dt(2026, 3, 2, 11, 0);
    let window_start = dt(2026, 3, 1, 0, 0);
    let window_end = dt(2026, 3, 31, 0, 0);
    let exdates = vec![dt(2026, 3, 9, 10, 0)]; // exclude March 9

    let results = expand_rrule(
        start,
        end,
        "FREQ=WEEKLY;BYDAY=MO",
        &exdates,
        window_start,
        window_end,
    );
    let dates: Vec<_> = results.iter().map(|(s, _)| s.date()).collect();
    assert!(dates.contains(&NaiveDate::from_ymd_opt(2026, 3, 2).unwrap()));
    assert!(!dates.contains(&NaiveDate::from_ymd_opt(2026, 3, 9).unwrap())); // excluded
    assert!(dates.contains(&NaiveDate::from_ymd_opt(2026, 3, 16).unwrap()));
    assert!(dates.contains(&NaiveDate::from_ymd_opt(2026, 3, 23).unwrap()));
    assert!(dates.contains(&NaiveDate::from_ymd_opt(2026, 3, 30).unwrap()));
}

#[test]
fn test_extract_exdates() {
    let ical = "BEGIN:VEVENT\nDTSTART:20260302T100000\nRRULE:FREQ=WEEKLY;BYDAY=MO\nEXDATE:20260309T100000\nEXDATE:20260316T100000\nEND:VEVENT";
    let exdates = extract_exdates(ical);
    assert_eq!(exdates.len(), 2);
    assert_eq!(exdates[0], dt(2026, 3, 9, 10, 0));
    assert_eq!(exdates[1], dt(2026, 3, 16, 10, 0));
}

#[test]
fn test_weekly_count() {
    let start = dt(2026, 3, 2, 9, 0);
    let end = dt(2026, 3, 2, 10, 0);
    let window_start = dt(2026, 3, 1, 0, 0);
    let window_end = dt(2026, 12, 31, 0, 0);

    let results = expand_rrule(
        start,
        end,
        "FREQ=WEEKLY;COUNT=3;BYDAY=MO",
        &[],
        window_start,
        window_end,
    );
    assert_eq!(results.len(), 3);
}

#[test]
fn test_recurrence_id_exclusion() {
    // A recurring event with a modified instance (RECURRENCE-ID)
    let ical = "BEGIN:VCALENDAR\n\
        BEGIN:VEVENT\n\
        UID:abc\n\
        DTSTART:20260302T100000\n\
        DTEND:20260302T110000\n\
        RRULE:FREQ=WEEKLY;BYDAY=MO\n\
        END:VEVENT\n\
        BEGIN:VEVENT\n\
        UID:abc\n\
        RECURRENCE-ID:20260309T100000\n\
        DTSTART:20260309T140000\n\
        DTEND:20260309T150000\n\
        END:VEVENT\n\
        END:VCALENDAR";
    let exdates = extract_exdates(ical);
    // The RECURRENCE-ID should be treated as an exclusion
    assert_eq!(exdates.len(), 1);
    assert_eq!(exdates[0], dt(2026, 3, 9, 10, 0));

    // The original March 9 occurrence should be excluded from expansion
    let start = dt(2026, 3, 2, 10, 0);
    let end = dt(2026, 3, 2, 11, 0);
    let window_start = dt(2026, 3, 1, 0, 0);
    let window_end = dt(2026, 3, 31, 0, 0);
    let results = expand_rrule(
        start,
        end,
        "FREQ=WEEKLY;BYDAY=MO",
        &exdates,
        window_start,
        window_end,
    );
    let dates: Vec<_> = results.iter().map(|(s, _)| s.date()).collect();
    assert!(dates.contains(&NaiveDate::from_ymd_opt(2026, 3, 2).unwrap()));
    assert!(!dates.contains(&NaiveDate::from_ymd_opt(2026, 3, 9).unwrap())); // excluded by RECURRENCE-ID
    assert!(dates.contains(&NaiveDate::from_ymd_opt(2026, 3, 16).unwrap()));
}

#[test]
fn test_weekly_multi_byday_devops() {
    // Real case: DevOps tools daily, WEEKLY on MO,TU,TH,FR
    // Starts 2025-10-20 (Monday), UNTIL 2026-03-15
    let start = dt(2025, 10, 20, 10, 30);
    let end = dt(2025, 10, 20, 11, 0);
    let window_start = dt(2026, 3, 10, 0, 0);
    let window_end = dt(2026, 3, 10, 23, 59);

    let results = expand_rrule(
        start,
        end,
        "FREQ=WEEKLY;UNTIL=20260315T093000;INTERVAL=1;BYDAY=MO,TU,TH,FR",
        &[],
        window_start,
        window_end,
    );
    // March 10 is a Tuesday — should have one occurrence at 10:30
    assert!(
        !results.is_empty(),
        "Expected occurrence on Tuesday March 10"
    );
    assert_eq!(results[0].0, dt(2026, 3, 10, 10, 30));
    assert_eq!(results[0].1, dt(2026, 3, 10, 11, 0));
}

#[test]
fn test_daily_count_pre_window() {
    // Daily event with COUNT=3 starting before the window
    let start = dt(2026, 3, 1, 9, 0);
    let end = dt(2026, 3, 1, 10, 0);
    let window_start = dt(2026, 3, 3, 0, 0); // window starts after 2 occurrences
    let window_end = dt(2026, 3, 10, 0, 0);

    let results = expand_rrule(
        start,
        end,
        "FREQ=DAILY;COUNT=3",
        &[],
        window_start,
        window_end,
    );
    // COUNT=3: Mar 1, Mar 2, Mar 3 — only Mar 3 is in window
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].0, dt(2026, 3, 3, 9, 0));
}

// --- Additional edge case tests ---

#[test]
fn test_daily_interval_2() {
    let start = dt(2026, 3, 1, 9, 0);
    let end = dt(2026, 3, 1, 10, 0);
    let window_start = dt(2026, 3, 1, 0, 0);
    let window_end = dt(2026, 3, 8, 0, 0);

    let results = expand_rrule(
        start,
        end,
        "FREQ=DAILY;INTERVAL=2",
        &[],
        window_start,
        window_end,
    );
    // Mar 1, 3, 5, 7
    assert_eq!(results.len(), 4);
    assert_eq!(
        results[0].0.date(),
        NaiveDate::from_ymd_opt(2026, 3, 1).unwrap()
    );
    assert_eq!(
        results[1].0.date(),
        NaiveDate::from_ymd_opt(2026, 3, 3).unwrap()
    );
    assert_eq!(
        results[2].0.date(),
        NaiveDate::from_ymd_opt(2026, 3, 5).unwrap()
    );
    assert_eq!(
        results[3].0.date(),
        NaiveDate::from_ymd_opt(2026, 3, 7).unwrap()
    );
}

#[test]
fn test_weekly_interval_2() {
    let start = dt(2026, 3, 2, 10, 0); // Monday
    let end = dt(2026, 3, 2, 11, 0);
    let window_start = dt(2026, 3, 1, 0, 0);
    let window_end = dt(2026, 4, 1, 0, 0);

    let results = expand_rrule(
        start,
        end,
        "FREQ=WEEKLY;INTERVAL=2;BYDAY=MO",
        &[],
        window_start,
        window_end,
    );
    // Mar 2, Mar 16, Mar 30
    assert_eq!(results.len(), 3);
    assert_eq!(
        results[0].0.date(),
        NaiveDate::from_ymd_opt(2026, 3, 2).unwrap()
    );
    assert_eq!(
        results[1].0.date(),
        NaiveDate::from_ymd_opt(2026, 3, 16).unwrap()
    );
    assert_eq!(
        results[2].0.date(),
        NaiveDate::from_ymd_opt(2026, 3, 30).unwrap()
    );
}

#[test]
fn test_monthly_last_friday() {
    let start = dt(2026, 1, 30, 15, 0); // Last Friday of Jan
    let end = dt(2026, 1, 30, 16, 0);
    let window_start = dt(2026, 2, 1, 0, 0);
    let window_end = dt(2026, 5, 1, 0, 0);

    let results = expand_rrule(
        start,
        end,
        "FREQ=MONTHLY;BYDAY=-1FR",
        &[],
        window_start,
        window_end,
    );
    // Last Friday: Feb 27, Mar 27, Apr 24
    assert_eq!(results.len(), 3);
    assert_eq!(
        results[0].0.date(),
        NaiveDate::from_ymd_opt(2026, 2, 27).unwrap()
    );
    assert_eq!(
        results[1].0.date(),
        NaiveDate::from_ymd_opt(2026, 3, 27).unwrap()
    );
    assert_eq!(
        results[2].0.date(),
        NaiveDate::from_ymd_opt(2026, 4, 24).unwrap()
    );
}

#[test]
fn test_monthly_same_day() {
    // Monthly on the 15th
    let start = dt(2026, 1, 15, 9, 0);
    let end = dt(2026, 1, 15, 10, 0);
    let window_start = dt(2026, 3, 1, 0, 0);
    let window_end = dt(2026, 6, 1, 0, 0);

    let results = expand_rrule(
        start,
        end,
        "FREQ=MONTHLY;INTERVAL=1",
        &[],
        window_start,
        window_end,
    );
    assert_eq!(results.len(), 3); // Mar 15, Apr 15, May 15
    assert_eq!(
        results[0].0.date(),
        NaiveDate::from_ymd_opt(2026, 3, 15).unwrap()
    );
    assert_eq!(
        results[1].0.date(),
        NaiveDate::from_ymd_opt(2026, 4, 15).unwrap()
    );
    assert_eq!(
        results[2].0.date(),
        NaiveDate::from_ymd_opt(2026, 5, 15).unwrap()
    );
}

#[test]
fn test_monthly_feb_30_skipped() {
    // Monthly on the 31st — Feb has no 31st
    let start = dt(2026, 1, 31, 9, 0);
    let end = dt(2026, 1, 31, 10, 0);
    let window_start = dt(2026, 2, 1, 0, 0);
    let window_end = dt(2026, 4, 1, 0, 0);

    let results = expand_rrule(
        start,
        end,
        "FREQ=MONTHLY;INTERVAL=1",
        &[],
        window_start,
        window_end,
    );
    // Feb 31 doesn't exist → skipped; Mar 31 exists
    assert_eq!(results.len(), 1);
    assert_eq!(
        results[0].0.date(),
        NaiveDate::from_ymd_opt(2026, 3, 31).unwrap()
    );
}

#[test]
fn test_invalid_rrule() {
    let start = dt(2026, 3, 1, 9, 0);
    let end = dt(2026, 3, 1, 10, 0);
    let results = expand_rrule(start, end, "FREQ=YEARLY", &[], start, end);
    assert!(results.is_empty()); // YEARLY not supported
}

#[test]
fn test_empty_rrule() {
    let start = dt(2026, 3, 1, 9, 0);
    let end = dt(2026, 3, 1, 10, 0);
    let results = expand_rrule(start, end, "", &[], start, end);
    assert!(results.is_empty());
}

// --- nth_weekday_of_month ---

#[test]
fn test_first_monday_march_2026() {
    assert_eq!(
        nth_weekday_of_month(2026, 3, Weekday::Mon, 1),
        Some(NaiveDate::from_ymd_opt(2026, 3, 2).unwrap())
    );
}

#[test]
fn test_second_monday_march_2026() {
    assert_eq!(
        nth_weekday_of_month(2026, 3, Weekday::Mon, 2),
        Some(NaiveDate::from_ymd_opt(2026, 3, 9).unwrap())
    );
}

#[test]
fn test_last_friday_march_2026() {
    assert_eq!(
        nth_weekday_of_month(2026, 3, Weekday::Fri, -1),
        Some(NaiveDate::from_ymd_opt(2026, 3, 27).unwrap())
    );
}

#[test]
fn test_fifth_monday_march_2026_none() {
    // March 2026 has 5 Mondays (2,9,16,23,30) so 5th exists
    assert_eq!(
        nth_weekday_of_month(2026, 3, Weekday::Mon, 5),
        Some(NaiveDate::from_ymd_opt(2026, 3, 30).unwrap())
    );
    // But 6th doesn't
    assert_eq!(nth_weekday_of_month(2026, 3, Weekday::Mon, 6), None);
}

// --- extract_exdates with multiple formats ---

#[test]
fn test_extract_exdates_with_timezone() {
    let ical = "BEGIN:VEVENT\nDTSTART:20260302T100000\nRRULE:FREQ=WEEKLY\nEXDATE;TZID=Europe/Paris:20260309T100000\nEND:VEVENT";
    let exdates = extract_exdates(ical);
    assert_eq!(exdates.len(), 1);
    assert_eq!(exdates[0], dt(2026, 3, 9, 10, 0));
}

#[test]
fn test_extract_exdates_comma_separated() {
    let ical = "BEGIN:VEVENT\nEXDATE:20260309T100000,20260316T100000,20260323T100000\nEND:VEVENT";
    let exdates = extract_exdates(ical);
    assert_eq!(exdates.len(), 3);
}

// --- week_start ---

#[test]
fn test_week_start_monday() {
    let monday = NaiveDate::from_ymd_opt(2026, 3, 9).unwrap(); // Monday
    assert_eq!(week_start(monday), monday);
}

#[test]
fn test_week_start_sunday() {
    let sunday = NaiveDate::from_ymd_opt(2026, 3, 15).unwrap(); // Sunday
    assert_eq!(
        week_start(sunday),
        NaiveDate::from_ymd_opt(2026, 3, 9).unwrap()
    );
}

#[test]
fn test_week_start_wednesday() {
    let wed = NaiveDate::from_ymd_opt(2026, 3, 11).unwrap(); // Wednesday
    assert_eq!(
        week_start(wed),
        NaiveDate::from_ymd_opt(2026, 3, 9).unwrap()
    );
}
