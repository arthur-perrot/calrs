// --- Slot computation (shared with CLI) ---

/// Pick an available team member for a booking slot.
/// Returns (user_id, name, email) of the member with fewest recent bookings.
async fn pick_group_member(
    pool: &SqlitePool,
    team_id: &str,
    event_type_id: &str,
    slot_start: NaiveDateTime,
    slot_end: NaiveDateTime,
    buffer_before: i32,
    buffer_after: i32,
    host_tz: Tz,
) -> Option<(String, String, String)> {
    let buf_start = slot_start - Duration::minutes(buffer_before as i64);
    let buf_end = slot_end + Duration::minutes(buffer_after as i64);

    // Fetch members with per-event-type weight (fallback to default 1)
    // weight=0 means excluded from this event type
    let members: Vec<(String, String, String, i64)> = sqlx::query_as(
        "SELECT u.id, u.name, COALESCE(u.booking_email, u.email), \
         COALESCE(etw.weight, 1) \
         FROM users u JOIN team_members tm ON tm.user_id = u.id \
         LEFT JOIN event_type_member_weights etw ON etw.user_id = u.id AND etw.event_type_id = ? \
         WHERE tm.team_id = ? AND u.enabled = 1 \
         AND COALESCE(etw.weight, 1) > 0",
    )
    .bind(event_type_id)
    .bind(team_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    // Per-member booking-frequency caps. We exclude any member already at
    // (or over) their per-period cap so the picker doesn't pick them just to
    // have the submit-time check reject the booking.
    let per_member_limits: Vec<(i32, String)> = sqlx::query_as(
        "SELECT max_bookings, period FROM booking_frequency_limits \
         WHERE event_type_id = ? AND per_member = 1",
    )
    .bind(event_type_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let mut available_members = Vec::new();

    for (user_id, name, email, weight) in &members {
        let mut busy = fetch_busy_times_for_user(
            pool,
            user_id,
            buf_start,
            buf_end,
            host_tz,
            Some(event_type_id),
        )
        .await;
        // Also exclude members who are outside their own working hours for
        // this slot. Members without explicit user_availability_rules are
        // returned unconstrained by user_avail_as_busy, matching the slot
        // grid semantics in show_group_slots.
        busy.extend(user_avail_as_busy(pool, user_id, buf_start, buf_end, host_tz).await);
        if has_conflict(&busy, buf_start, buf_end) {
            continue;
        }

        let mut at_per_member_cap = false;
        for (max, period) in &per_member_limits {
            let (rs, re) = frequency_period_range(slot_start, period);
            let rs_str = rs.format("%Y-%m-%dT%H:%M:%S").to_string();
            let re_str = re.format("%Y-%m-%dT%H:%M:%S").to_string();
            let count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM bookings \
                 WHERE event_type_id = ? AND assigned_user_id = ? \
                 AND status IN ('confirmed', 'pending') \
                 AND start_at >= ? AND start_at < ?",
            )
            .bind(event_type_id)
            .bind(user_id)
            .bind(&rs_str)
            .bind(&re_str)
            .fetch_one(pool)
            .await
            .unwrap_or(0);
            if count >= *max as i64 {
                at_per_member_cap = true;
                break;
            }
        }
        if at_per_member_cap {
            continue;
        }

        available_members.push((user_id.clone(), name.clone(), email.clone(), *weight));
    }

    if available_members.is_empty() {
        return None;
    }

    // Among available members, pick by highest weight first, then fewest bookings in last 30 days
    let thirty_days_ago = (Utc::now() - Duration::days(30))
        .format("%Y-%m-%dT%H:%M:%S")
        .to_string();
    let mut best: Option<(String, String, String, i64, i64)> = None;

    for (user_id, name, email, weight) in &available_members {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM bookings WHERE assigned_user_id = ? AND created_at >= ?",
        )
        .bind(user_id)
        .bind(&thirty_days_ago)
        .fetch_one(pool)
        .await
        .unwrap_or(0);

        let is_better = match &best {
            None => true,
            Some((_, _, _, bw, bc)) => *weight > *bw || (*weight == *bw && count < *bc),
        };
        if is_better {
            best = Some((user_id.clone(), name.clone(), email.clone(), *weight, count));
        }
    }

    best.map(|(uid, name, email, _, _)| (uid, name, email))
}

struct SlotDay {
    date: String,
    label: String,
    slots: Vec<SlotTime>,
}

struct SlotTime {
    start: String,      // guest TZ display
    end: String,        // guest TZ display
    host_date: String,  // YYYY-MM-DD in host TZ (for booking)
    host_time: String,  // HH:MM in host TZ (for booking)
    guest_date: String, // YYYY-MM-DD in guest TZ (for grouping by day)
}

// --- Shared busy-time helpers ---

/// Expand recurring events into (start, end) pairs within a time window.
/// Tuples are (start_at, end_at, rrule, raw_ical, timezone).
fn expand_recurring_into_busy(
    recurring: &[(String, String, String, Option<String>, Option<String>)],
    window_start: NaiveDateTime,
    window_end: NaiveDateTime,
    host_tz: Tz,
) -> Vec<(NaiveDateTime, NaiveDateTime)> {
    let mut result = Vec::new();
    for (s, e, rrule_str, raw_ical, event_tz) in recurring {
        if let (Some(ev_start), Some(ev_end)) = (parse_ical_datetime(s), parse_ical_datetime(e)) {
            let exdates = raw_ical
                .as_deref()
                .map(crate::rrule::extract_exdates)
                .unwrap_or_default();
            // Expand RRULE in the event's own timezone (correct for DST)
            let occurrences = crate::rrule::expand_rrule(
                ev_start,
                ev_end,
                rrule_str,
                &exdates,
                window_start,
                window_end,
            );
            // Convert each occurrence to host timezone
            for (os, oe) in occurrences {
                let cs = convert_event_to_tz(os, event_tz.as_deref(), host_tz);
                let ce = convert_event_to_tz(oe, event_tz.as_deref(), host_tz);
                result.push((cs, ce));
            }
        }
    }
    result
}

/// Fetch busy times for a specific user (events from their calendars + their bookings).
/// Event times are converted from their stored timezone to `host_tz`.
async fn fetch_busy_times_for_user(
    pool: &SqlitePool,
    user_id: &str,
    window_start: NaiveDateTime,
    window_end: NaiveDateTime,
    host_tz: Tz,
    event_type_id: Option<&str>,
) -> Vec<(NaiveDateTime, NaiveDateTime)> {
    fetch_busy_times_for_user_ex(
        pool,
        user_id,
        window_start,
        window_end,
        host_tz,
        event_type_id,
        None,
    )
    .await
}

async fn fetch_busy_times_for_user_ex(
    pool: &SqlitePool,
    user_id: &str,
    window_start: NaiveDateTime,
    window_end: NaiveDateTime,
    host_tz: Tz,
    event_type_id: Option<&str>,
    exclude_booking_id: Option<&str>,
) -> Vec<(NaiveDateTime, NaiveDateTime)> {
    let end_compact = window_end.format("%Y%m%d").to_string();
    let start_compact = window_start.format("%Y%m%dT%H%M%S").to_string();
    let end_iso = window_end.format("%Y-%m-%dT%H:%M:%S").to_string();
    let start_iso = window_start.format("%Y-%m-%dT%H:%M:%S").to_string();

    // Empty string means NOT EXISTS is always true (no rows match), so all calendars pass
    let et_id_for_filter = event_type_id.unwrap_or("");

    let events: Vec<(String, String, Option<String>)> = sqlx::query_as(
        "SELECT e.start_at, e.end_at, e.timezone FROM events e
         JOIN calendars c ON c.id = e.calendar_id
         JOIN caldav_sources cs ON cs.id = c.source_id
         JOIN accounts a ON a.id = cs.account_id
         WHERE a.user_id = ? AND c.is_busy = 1
           AND (NOT EXISTS (SELECT 1 FROM event_type_calendars WHERE event_type_id = ?)
                OR c.id IN (SELECT calendar_id FROM event_type_calendars WHERE event_type_id = ?))
           AND (e.rrule IS NULL OR e.rrule = '')
           AND (e.status IS NULL OR e.status != 'CANCELLED')
           AND (e.transp IS NULL OR e.transp != 'TRANSPARENT')
           AND ((e.start_at <= ? AND e.end_at >= ?) OR (e.start_at <= ? AND e.end_at >= ?))",
    )
    .bind(user_id)
    .bind(et_id_for_filter)
    .bind(et_id_for_filter)
    .bind(&end_compact)
    .bind(&start_compact)
    .bind(&end_iso)
    .bind(&start_iso)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let mut busy: Vec<(NaiveDateTime, NaiveDateTime)> = events
        .iter()
        .filter_map(|(s, e, tz)| {
            let start = convert_event_to_tz(parse_ical_datetime(s)?, tz.as_deref(), host_tz);
            let end = convert_event_to_tz(parse_ical_datetime(e)?, tz.as_deref(), host_tz);
            Some((start, end))
        })
        .collect();

    let end_compact_rrule = window_end.format("%Y%m%dT235959").to_string();
    let recurring: Vec<(String, String, String, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT e.start_at, e.end_at, e.rrule, e.raw_ical, e.timezone FROM events e
         JOIN calendars c ON c.id = e.calendar_id
         JOIN caldav_sources cs ON cs.id = c.source_id
         JOIN accounts a ON a.id = cs.account_id
         WHERE a.user_id = ? AND c.is_busy = 1
           AND (NOT EXISTS (SELECT 1 FROM event_type_calendars WHERE event_type_id = ?)
                OR c.id IN (SELECT calendar_id FROM event_type_calendars WHERE event_type_id = ?))
           AND (e.status IS NULL OR e.status != 'CANCELLED')
           AND (e.transp IS NULL OR e.transp != 'TRANSPARENT')
           AND e.rrule IS NOT NULL AND e.rrule != '' AND (e.start_at <= ? OR e.start_at <= ?)",
    )
    .bind(user_id)
    .bind(et_id_for_filter)
    .bind(et_id_for_filter)
    .bind(&end_iso)
    .bind(&end_compact_rrule)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    busy.extend(expand_recurring_into_busy(
        &recurring,
        window_start,
        window_end,
        host_tz,
    ));

    let exclude_id = exclude_booking_id.unwrap_or("");
    let bookings: Vec<(String, String)> = sqlx::query_as(
        "SELECT b.start_at, b.end_at FROM bookings b
         JOIN event_types et ON et.id = b.event_type_id
         JOIN accounts a ON a.id = et.account_id
         WHERE (a.user_id = ? OR b.assigned_user_id = ?) AND b.status = 'confirmed'
           AND b.start_at <= ? AND b.end_at >= ?
           AND (? = '' OR b.id != ?)",
    )
    .bind(user_id)
    .bind(user_id)
    .bind(&end_iso)
    .bind(&start_iso)
    .bind(exclude_id)
    .bind(exclude_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    for (s, e) in &bookings {
        if let (Some(start), Some(end)) = (parse_ical_datetime(s), parse_ical_datetime(e)) {
            busy.push((start, end));
        }
    }

    busy
}

/// Check if any busy period overlaps with [buf_start, buf_end).
fn has_conflict(
    busy: &[(NaiveDateTime, NaiveDateTime)],
    buf_start: NaiveDateTime,
    buf_end: NaiveDateTime,
) -> bool {
    busy.iter().any(|(s, e)| *s < buf_end && *e > buf_start)
}

// --- Busy source for unified slot computation ---

enum BusySource {
    /// Flat list of busy times (individual event type)
    Individual(Vec<(NaiveDateTime, NaiveDateTime)>),
    /// Per-member busy times; slot is available if ANY member is free
    Group(HashMap<String, Vec<(NaiveDateTime, NaiveDateTime)>>),
    /// Per-member busy times; slot is available only if ALL members are free
    Team(HashMap<String, Vec<(NaiveDateTime, NaiveDateTime)>>),
}

/// Compute available slots for an event type.
/// Caller provides pre-fetched busy times via BusySource.
async fn compute_slots(
    pool: &SqlitePool,
    et_id: &str,
    duration: i32,
    buffer_before: i32,
    buffer_after: i32,
    min_notice: i32,
    start_offset: i32,
    days_ahead: i32,
    host_tz: Tz,
    guest_tz: Tz,
    busy: BusySource,
) -> Vec<SlotDay> {
    let rules: Vec<(i32, String, String)> = sqlx::query_as(
        "SELECT day_of_week, start_time, end_time FROM availability_rules WHERE event_type_id = ?",
    )
    .bind(et_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    // Fetch availability overrides for this event type
    let overrides: Vec<(String, Option<String>, Option<String>, i32)> = sqlx::query_as(
        "SELECT date, start_time, end_time, is_blocked FROM availability_overrides WHERE event_type_id = ? ORDER BY date, start_time",
    )
    .bind(et_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    // slot_interval_min overrides the cursor step. NULL = use duration (legacy behavior).
    let slot_interval: Option<i32> =
        sqlx::query_scalar("SELECT slot_interval_min FROM event_types WHERE id = ?")
            .bind(et_id)
            .fetch_one(pool)
            .await
            .unwrap_or(None);
    let interval = slot_interval.filter(|v| *v > 0).unwrap_or(duration);

    let mut result = compute_slots_from_rules(
        &rules,
        duration,
        interval,
        buffer_before,
        buffer_after,
        min_notice,
        start_offset,
        days_ahead,
        host_tz,
        guest_tz,
        busy,
        &overrides,
    );

    // Drop slots whose host-local period already meets/exceeds a configured
    // frequency cap. The submit-time check (would_exceed_frequency_limit)
    // stays as a backstop for the race where two guests grab the last slot
    // at the same instant.
    apply_frequency_limit_filter(pool, et_id, &mut result).await;

    // If first_slot_only is enabled, keep only the earliest slot per day
    let first_only: i32 =
        sqlx::query_scalar("SELECT first_slot_only FROM event_types WHERE id = ?")
            .bind(et_id)
            .fetch_one(pool)
            .await
            .unwrap_or(0);

    if first_only != 0 {
        for day in &mut result {
            day.slots.truncate(1);
        }
    }

    result
}

/// Remove slots that fall inside a host-local period already at/over a
/// configured booking-frequency cap, so the picker doesn't surface times
/// that the submit-time check would reject.
///
/// Per-member limits hide a slot only when *every* eligible team member is
/// already at their cap for the slot's period; if any one of them still has
/// headroom, the slot stays available and the round-robin picker will route
/// to that member. On personal event types (no team), per-member limits
/// degrade to event-type-wide behaviour.
async fn apply_frequency_limit_filter(pool: &SqlitePool, et_id: &str, days: &mut [SlotDay]) {
    let limits: Vec<(i32, String, i32)> = sqlx::query_as(
        "SELECT max_bookings, period, per_member FROM booking_frequency_limits WHERE event_type_id = ?",
    )
    .bind(et_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    if limits.is_empty() {
        return;
    }

    let has_per_member = limits.iter().any(|(_, _, m)| *m != 0);
    let team_members: Vec<String> = if has_per_member {
        sqlx::query_scalar(
            "SELECT u.id FROM users u \
             JOIN team_members tm ON tm.user_id = u.id \
             JOIN event_types et ON et.team_id = tm.team_id \
             LEFT JOIN event_type_member_weights etw ON etw.user_id = u.id AND etw.event_type_id = et.id \
             WHERE et.id = ? AND u.enabled = 1 AND COALESCE(etw.weight, 1) > 0",
        )
        .bind(et_id)
        .fetch_all(pool)
        .await
        .unwrap_or_default()
    } else {
        Vec::new()
    };

    // Gather unique (period, period_start) pairs the visible slots touch, and
    // resolve each one to (event-type-wide count, per-member counts).
    let mut wide_counts: HashMap<(String, NaiveDateTime), i64> = HashMap::new();
    let mut member_counts: HashMap<(String, NaiveDateTime, String), i64> = HashMap::new();

    for day in days.iter() {
        for slot in &day.slots {
            let Ok(d) = NaiveDate::parse_from_str(&slot.host_date, "%Y-%m-%d") else {
                continue;
            };
            let dt = d.and_hms_opt(12, 0, 0).unwrap();
            for (_, period, _) in &limits {
                let (ps, _) = frequency_period_range(dt, period);
                wide_counts.entry((period.clone(), ps)).or_insert(0);
            }
        }
    }

    for ((period, ps), wide) in wide_counts.iter_mut() {
        let (rs, re) = frequency_period_range(*ps, period);
        let rs_str = rs.format("%Y-%m-%dT%H:%M:%S").to_string();
        let re_str = re.format("%Y-%m-%dT%H:%M:%S").to_string();

        let c: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM bookings WHERE event_type_id = ? AND status IN ('confirmed', 'pending') AND start_at >= ? AND start_at < ?",
        )
        .bind(et_id)
        .bind(&rs_str)
        .bind(&re_str)
        .fetch_one(pool)
        .await
        .unwrap_or((0,));
        *wide = c.0;

        if has_per_member && !team_members.is_empty() {
            let rows: Vec<(String, i64)> = sqlx::query_as(
                "SELECT assigned_user_id, COUNT(*) FROM bookings \
                 WHERE event_type_id = ? AND assigned_user_id IS NOT NULL \
                 AND status IN ('confirmed', 'pending') \
                 AND start_at >= ? AND start_at < ? \
                 GROUP BY assigned_user_id",
            )
            .bind(et_id)
            .bind(&rs_str)
            .bind(&re_str)
            .fetch_all(pool)
            .await
            .unwrap_or_default();
            for (uid, n) in rows {
                member_counts.insert((period.clone(), *ps, uid), n);
            }
        }
    }

    for day in days.iter_mut() {
        day.slots.retain(|slot| {
            let Ok(d) = NaiveDate::parse_from_str(&slot.host_date, "%Y-%m-%d") else {
                return true;
            };
            let dt = d.and_hms_opt(12, 0, 0).unwrap();
            for (max, period, per_member) in &limits {
                let (ps, _) = frequency_period_range(dt, period);
                let max_i64 = *max as i64;
                if *per_member != 0 && !team_members.is_empty() {
                    // Hide only if every eligible member is at cap.
                    let all_capped = team_members.iter().all(|uid| {
                        let count = member_counts
                            .get(&(period.clone(), ps, uid.clone()))
                            .copied()
                            .unwrap_or(0);
                        count >= max_i64
                    });
                    if all_capped {
                        return false;
                    }
                } else {
                    let count = wide_counts.get(&(period.clone(), ps)).copied().unwrap_or(0);
                    if count >= max_i64 {
                        return false;
                    }
                }
            }
            true
        });
    }
}

/// Save booking frequency limits from the serialized form field.
/// Format per row: "count:period" or "count:period:m" (the trailing ":m"
/// marks the row as per-member; absence means event-type-wide). Rows are
/// comma-separated.
async fn save_frequency_limits(pool: &SqlitePool, event_type_id: &str, limits_str: &str) {
    if limits_str.is_empty() {
        return;
    }
    for part in limits_str.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let mut bits = part.splitn(3, ':');
        let Some(count_str) = bits.next() else {
            continue;
        };
        let Some(period) = bits.next() else {
            continue;
        };
        let per_member = matches!(bits.next(), Some("m"));
        let count: i32 = count_str.parse().unwrap_or(0);
        if count > 0 && ["day", "week", "month", "year"].contains(&period) {
            let limit_id = uuid::Uuid::new_v4().to_string();
            let _ = sqlx::query(
                "INSERT INTO booking_frequency_limits (id, event_type_id, max_bookings, period, per_member) VALUES (?, ?, ?, ?, ?)",
            )
            .bind(&limit_id)
            .bind(event_type_id)
            .bind(count)
            .bind(period)
            .bind(per_member as i32)
            .execute(pool)
            .await;
        }
    }
}

/// Compute the start/end of a calendar period containing the given datetime.
fn frequency_period_range(dt: NaiveDateTime, period: &str) -> (NaiveDateTime, NaiveDateTime) {
    let date = dt.date();
    match period {
        "day" => {
            let start = date.and_hms_opt(0, 0, 0).unwrap();
            let end = (date + Duration::days(1)).and_hms_opt(0, 0, 0).unwrap();
            (start, end)
        }
        "week" => {
            let weekday = date.weekday().num_days_from_monday();
            let week_start = date - Duration::days(weekday as i64);
            let start = week_start.and_hms_opt(0, 0, 0).unwrap();
            let end = (week_start + Duration::days(7))
                .and_hms_opt(0, 0, 0)
                .unwrap();
            (start, end)
        }
        "month" => {
            let start = NaiveDate::from_ymd_opt(date.year(), date.month(), 1)
                .unwrap()
                .and_hms_opt(0, 0, 0)
                .unwrap();
            let end = if date.month() == 12 {
                NaiveDate::from_ymd_opt(date.year() + 1, 1, 1).unwrap()
            } else {
                NaiveDate::from_ymd_opt(date.year(), date.month() + 1, 1).unwrap()
            }
            .and_hms_opt(0, 0, 0)
            .unwrap();
            (start, end)
        }
        "year" => {
            let start = NaiveDate::from_ymd_opt(date.year(), 1, 1)
                .unwrap()
                .and_hms_opt(0, 0, 0)
                .unwrap();
            let end = NaiveDate::from_ymd_opt(date.year() + 1, 1, 1)
                .unwrap()
                .and_hms_opt(0, 0, 0)
                .unwrap();
            (start, end)
        }
        _ => (dt, dt),
    }
}

/// Check if a booking at the given datetime would exceed any frequency limit
/// configured on the event type. `assigned_user_id` is the team member the
/// booking would land on — required for per-member caps; ignored by
/// event-type-wide caps. Pass `None` for personal event types (no assignee).
async fn would_exceed_frequency_limit(
    pool: &SqlitePool,
    event_type_id: &str,
    proposed_start: NaiveDateTime,
    assigned_user_id: Option<&str>,
) -> bool {
    let limits: Vec<(i32, String, i32)> = sqlx::query_as(
        "SELECT max_bookings, period, per_member FROM booking_frequency_limits WHERE event_type_id = ?",
    )
    .bind(event_type_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    if limits.is_empty() {
        return false;
    }

    for (max_bookings, period, per_member) in &limits {
        let (range_start, range_end) = frequency_period_range(proposed_start, period);
        let range_start_str = range_start.format("%Y-%m-%dT%H:%M:%S").to_string();
        let range_end_str = range_end.format("%Y-%m-%dT%H:%M:%S").to_string();

        let count: (i64,) = if *per_member != 0 {
            // A per-member cap on a personal event type (no assignee) is
            // meaningless — treat it as event-type-wide for those cases.
            match assigned_user_id {
                Some(uid) => sqlx::query_as(
                    "SELECT COUNT(*) FROM bookings WHERE event_type_id = ? AND assigned_user_id = ? AND status IN ('confirmed', 'pending') AND start_at >= ? AND start_at < ?",
                )
                .bind(event_type_id)
                .bind(uid)
                .bind(&range_start_str)
                .bind(&range_end_str)
                .fetch_one(pool)
                .await
                .unwrap_or((0,)),
                None => sqlx::query_as(
                    "SELECT COUNT(*) FROM bookings WHERE event_type_id = ? AND status IN ('confirmed', 'pending') AND start_at >= ? AND start_at < ?",
                )
                .bind(event_type_id)
                .bind(&range_start_str)
                .bind(&range_end_str)
                .fetch_one(pool)
                .await
                .unwrap_or((0,)),
            }
        } else {
            sqlx::query_as(
                "SELECT COUNT(*) FROM bookings WHERE event_type_id = ? AND status IN ('confirmed', 'pending') AND start_at >= ? AND start_at < ?",
            )
            .bind(event_type_id)
            .bind(&range_start_str)
            .bind(&range_end_str)
            .fetch_one(pool)
            .await
            .unwrap_or((0,))
        };

        if count.0 >= *max_bookings as i64 {
            return true;
        }
    }
    false
}

/// Core slot computation from pre-fetched rules.
fn compute_slots_from_rules(
    rules: &[(i32, String, String)],
    duration: i32,
    interval: i32,
    buffer_before: i32,
    buffer_after: i32,
    min_notice: i32,
    start_offset: i32,
    days_ahead: i32,
    host_tz: Tz,
    guest_tz: Tz,
    busy: BusySource,
    overrides: &[(String, Option<String>, Option<String>, i32)],
) -> Vec<SlotDay> {
    let now_host = Utc::now().with_timezone(&host_tz).naive_local();
    let min_start = now_host + Duration::minutes(min_notice as i64);

    let slot_duration = Duration::minutes(duration as i64);
    let slot_step = Duration::minutes(interval.max(1) as i64);
    let mut result = Vec::new();

    for day_offset in start_offset..(start_offset + days_ahead) {
        let date = now_host.date() + Duration::days(day_offset as i64);
        let date_str = date.format("%Y-%m-%d").to_string();

        // Check availability overrides for this date
        let day_overrides: Vec<&(String, Option<String>, Option<String>, i32)> = overrides
            .iter()
            .filter(|(d, _, _, _)| *d == date_str)
            .collect();

        // If any override blocks this day, skip entirely
        if day_overrides.iter().any(|(_, _, _, blocked)| *blocked != 0) {
            continue;
        }

        // Build time windows: use custom hours if overrides exist, else weekly rules
        let windows: Vec<(String, String)> = if !day_overrides.is_empty() {
            // Custom hours overrides replace weekly rules
            day_overrides
                .iter()
                .filter_map(|(_, s, e, _)| match (s, e) {
                    (Some(start), Some(end)) => Some((start.clone(), end.clone())),
                    _ => None,
                })
                .collect()
        } else {
            let weekday = date.weekday().num_days_from_sunday() as i32;
            rules
                .iter()
                .filter(|(d, _, _)| *d == weekday)
                .map(|(_, s, e)| (s.clone(), e.clone()))
                .collect()
        };

        if windows.is_empty() {
            continue;
        }

        let mut day_slots = Vec::new();

        for (start_str, end_str) in &windows {
            let window_start_time = match NaiveTime::parse_from_str(start_str, "%H:%M") {
                Ok(t) => t,
                Err(_) => continue,
            };
            let window_end_time = match NaiveTime::parse_from_str(end_str, "%H:%M") {
                Ok(t) => t,
                Err(_) => continue,
            };

            // Walk the cursor as a NaiveDateTime, not a NaiveTime: NaiveTime +
            // Duration wraps at 24h, which turned a window ending at 23:00 with
            // a 60-minute slot duration into an infinite loop (23:00 + 60m =
            // 00:00, still <= 23:00 as a time-of-day, so the loop emitted a
            // slot every step forever until OOM).
            let window_end = date.and_time(window_end_time);
            let mut cursor = date.and_time(window_start_time);
            while cursor + slot_duration <= window_end {
                let slot_start = cursor;
                let slot_end = slot_start + slot_duration;

                if slot_start < min_start {
                    cursor += slot_step;
                    continue;
                }

                let buf_start = slot_start - Duration::minutes(buffer_before as i64);
                let buf_end = slot_end + Duration::minutes(buffer_after as i64);

                let is_free = match &busy {
                    BusySource::Individual(times) => !has_conflict(times, buf_start, buf_end),
                    BusySource::Group(member_busy) => member_busy
                        .values()
                        .any(|times| !has_conflict(times, buf_start, buf_end)),
                    BusySource::Team(member_busy) => {
                        !member_busy.is_empty()
                            && member_busy
                                .values()
                                .all(|times| !has_conflict(times, buf_start, buf_end))
                    }
                };

                if is_free {
                    let slot_start_utc = host_tz
                        .from_local_datetime(&slot_start)
                        .earliest()
                        .unwrap_or_else(|| host_tz.from_utc_datetime(&slot_start))
                        .with_timezone(&Utc);
                    let slot_end_utc = host_tz
                        .from_local_datetime(&slot_end)
                        .earliest()
                        .unwrap_or_else(|| host_tz.from_utc_datetime(&slot_end))
                        .with_timezone(&Utc);
                    let guest_start = slot_start_utc.with_timezone(&guest_tz);
                    let guest_end = slot_end_utc.with_timezone(&guest_tz);

                    day_slots.push(SlotTime {
                        start: guest_start.format("%H:%M").to_string(),
                        end: guest_end.format("%H:%M").to_string(),
                        host_date: date.format("%Y-%m-%d").to_string(),
                        host_time: cursor.format("%H:%M").to_string(),
                        guest_date: guest_start.format("%Y-%m-%d").to_string(),
                    });
                }

                cursor += slot_step;
            }
        }

        if !day_slots.is_empty() {
            let mut guest_days: std::collections::BTreeMap<String, Vec<SlotTime>> =
                std::collections::BTreeMap::new();
            for slot in day_slots {
                guest_days
                    .entry(slot.guest_date.clone())
                    .or_default()
                    .push(slot);
            }
            for (guest_date_str, slots) in guest_days {
                if let Ok(gd) = NaiveDate::parse_from_str(&guest_date_str, "%Y-%m-%d") {
                    if !result.iter().any(|d: &SlotDay| d.date == guest_date_str) {
                        result.push(SlotDay {
                            date: guest_date_str,
                            label: gd.format("%A, %B %-d").to_string(),
                            slots,
                        });
                    } else if let Some(existing) =
                        result.iter_mut().find(|d| d.date == guest_date_str)
                    {
                        existing.slots.extend(slots);
                    }
                }
            }
        }
    }

    result.sort_by(|a, b| a.date.cmp(&b.date));
    for day in &mut result {
        day.slots.sort_by(|a, b| a.start.cmp(&b.start));
    }
    result
}
