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

