// --- Group event type handlers ---

async fn new_group_event_type_form(
    State(state): State<Arc<AppState>>,
    auth_user: crate::auth::AuthUser,
) -> impl IntoResponse {
    let user = &auth_user.user;
    let is_admin = user.role == "admin";

    let groups: Vec<(String, String)> = if is_admin {
        sqlx::query_as("SELECT t.id, t.name FROM teams t ORDER BY t.name")
            .fetch_all(&state.pool)
            .await
            .unwrap_or_default()
    } else {
        sqlx::query_as(
            "SELECT t.id, t.name FROM teams t JOIN team_members tm ON tm.team_id = t.id WHERE tm.user_id = ? AND tm.role = 'admin' ORDER BY t.name",
        )
        .bind(&user.id)
        .fetch_all(&state.pool)
        .await
        .unwrap_or_default()
    };

    if groups.is_empty() {
        return Html(if is_admin {
            "No teams exist yet.".to_string()
        } else {
            "You are not a team admin of any teams.".to_string()
        });
    }

    let groups_ctx: Vec<minijinja::Value> = groups
        .iter()
        .map(|(id, name)| context! { id => id, name => name })
        .collect();

    // Pre-fill availability from user's default schedule
    ensure_user_avail_seeded(&state.pool, &user.id).await;
    let user_avail = load_user_avail_schedule(&state.pool, &user.id).await;

    // Load all teams for watcher selection (exclude the selected team itself in template)
    let watcher_teams_ctx: Vec<minijinja::Value> = groups
        .iter()
        .map(|(id, name)| context! { id => id, name => name })
        .collect();

    let tmpl = match state.templates.get_template("event_type_form.html") {
        Ok(t) => t,
        Err(e) => return internal_error_html("template render", &e),
    };

    let (impersonating, impersonating_name, _) = impersonation_ctx(&auth_user);
    Html(
        tmpl.render(context! {
            editing => false,
            is_group => true,
            teams => groups_ctx,
            form_team_id => groups.first().map(|(id, _)| id.as_str()).unwrap_or(""),
            form_title => "",
            form_slug => "",
            form_description => "",
            form_duration => 30,
            form_slot_interval => 0,
            form_buffer_before => 0,
            form_buffer_after => 0,
            form_min_notice => 60,
            form_requires_confirmation => false,
            form_location_type => "link",
            form_location_value => "",
            form_meeting_pattern_override => "",
            form_avail_schedule => user_avail,
            form_default_calendar_view => "month",
            form_first_slot_only => false,
            form_frequency_limits => "",
            form_timezone => &user.timezone,
            tz_options => common_timezones_with(&user.timezone)
                .iter()
                .map(|(iana, label)| context! { value => iana, label => label })
                .collect::<Vec<_>>(),
            watcher_teams => watcher_teams_ctx,
            selected_watcher_team_ids => "",
            error => "",
            sidebar => sidebar_context(&auth_user, "event-types"),
            impersonating => impersonating,
            impersonating_name => impersonating_name,
        })
        .unwrap_or_else(|e| internal_error_body("template render", &e)),
    )
}

async fn create_group_event_type(
    State(state): State<Arc<AppState>>,
    auth_user: crate::auth::AuthUser,
    headers: HeaderMap,
    Form(form): Form<EventTypeForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }
    let user = &auth_user.user;

    let team_id = match form.team_id.as_deref().filter(|s| !s.trim().is_empty()) {
        Some(tid) => tid.to_string(),
        None => return Redirect::to("/dashboard/event-types").into_response(),
    };

    let is_admin = user.role == "admin";

    // Only team admins (and global admins) can create team event types
    if !is_admin && !is_team_admin(&state.pool, &user.id, &team_id).await {
        return Html("You are not a team admin of this team.".to_string()).into_response();
    }

    // Find the user's account
    let account_id: Option<String> =
        sqlx::query_scalar("SELECT id FROM accounts WHERE user_id = ? LIMIT 1")
            .bind(&user.id)
            .fetch_optional(&state.pool)
            .await
            .unwrap_or(None);

    let account_id = match account_id {
        Some(id) => id,
        None => return Redirect::to("/dashboard/event-types").into_response(),
    };

    let mut slug = form.slug.trim().to_lowercase().replace(' ', "-");
    slug = slug
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .collect();
    if slug.is_empty() {
        slug = form
            .title
            .trim()
            .to_lowercase()
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .collect::<String>();
        while slug.contains("--") {
            slug = slug.replace("--", "-");
        }
        slug = slug.trim_matches('-').to_string();
    }
    if slug.is_empty() {
        return Html("Title is required to generate a slug.".to_string()).into_response();
    }

    // Check uniqueness within the team
    let existing: Option<(String,)> =
        sqlx::query_as("SELECT id FROM event_types WHERE team_id = ? AND slug = ?")
            .bind(&team_id)
            .bind(&slug)
            .fetch_optional(&state.pool)
            .await
            .unwrap_or(None);

    if existing.is_some() {
        return Html("An event type with this slug already exists in this team.".to_string())
            .into_response();
    }

    let et_id = uuid::Uuid::new_v4().to_string();
    let requires_confirmation = form.requires_confirmation.as_deref() == Some("on");
    let location_type = form.location_type.as_deref().unwrap_or("link");
    let location_value = form
        .location_value
        .as_deref()
        .filter(|s| !s.trim().is_empty());

    // Auto-meeting providers compute their own URL per booking; the static
    // location_value field is not used and may be empty.
    let location_required = !matches!(
        location_type,
        meeting::LOCATION_TYPE_JITSI | meeting::LOCATION_TYPE_WEBHOOK
    );
    if location_required && location_value.is_none() {
        return render_event_type_form_error(
            &state,
            &auth_user,
            "Location details are required (e.g. a video call link, phone number, or address).",
            &form,
            false,
        )
        .into_response();
    }

    let default_calendar_view = match form.default_calendar_view.as_deref().unwrap_or("month") {
        v @ ("month" | "week" | "column") => v.to_string(),
        _ => "month".to_string(),
    };

    let first_slot_only = form.first_slot_only.as_deref() == Some("on");
    let timezone = normalize_event_type_tz(form.timezone.as_deref(), &user.timezone);
    let cancel_notice_min =
        parse_notice_to_minutes(&form.cancel_notice_value, &form.cancel_notice_unit);
    let reschedule_notice_min =
        parse_notice_to_minutes(&form.reschedule_notice_value, &form.reschedule_notice_unit);

    let meeting_pattern_override = form
        .meeting_pattern_override
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    let _ = sqlx::query(
        "INSERT INTO event_types (id, account_id, slug, title, description, duration_min, slot_interval_min, buffer_before, buffer_after, min_notice_min, requires_confirmation, location_type, location_value, team_id, created_by_user_id, default_calendar_view, first_slot_only, timezone, cancel_notice_min, reschedule_notice_min, meeting_pattern_override)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&et_id)
    .bind(&account_id)
    .bind(&slug)
    .bind(form.title.trim())
    .bind(form.description.as_deref().filter(|s| !s.trim().is_empty()))
    .bind(parse_int_field(&form.duration_min, 30))
    .bind(parse_optional_positive_int(&form.slot_interval_min))
    .bind(parse_int_field(&form.buffer_before, 0))
    .bind(parse_int_field(&form.buffer_after, 0))
    .bind(parse_int_field(&form.min_notice_min, 60))
    .bind(requires_confirmation as i32)
    .bind(location_type)
    .bind(location_value)
    .bind(&team_id)
    .bind(&user.id)
    .bind(&default_calendar_view)
    .bind(first_slot_only as i32)
    .bind(&timezone)
    .bind(cancel_notice_min)
    .bind(reschedule_notice_min)
    .bind(&meeting_pattern_override)
    .execute(&state.pool)
    .await;

    // Create availability rules. Pass the creating user's profile-default
    // schedule as a fallback so an empty submission falls back to it instead
    // of hardcoded Mon-Fri 09:00-17:00.
    ensure_user_avail_seeded(&state.pool, &user.id).await;
    let user_default = load_user_avail_schedule(&state.pool, &user.id).await;
    let schedule = parse_avail_schedule(
        form.avail_schedule.as_deref(),
        form.avail_days.as_deref(),
        form.avail_windows.as_deref(),
        form.avail_start.as_deref(),
        form.avail_end.as_deref(),
        Some(&user_default),
    );

    for (day, windows) in &schedule {
        for (ws, we) in windows {
            let rule_id = uuid::Uuid::new_v4().to_string();
            let _ = sqlx::query(
                "INSERT INTO availability_rules (id, event_type_id, day_of_week, start_time, end_time) VALUES (?, ?, ?, ?, ?)",
            )
            .bind(&rule_id)
            .bind(&et_id)
            .bind(day)
            .bind(ws)
            .bind(we)
            .execute(&state.pool)
            .await;
        }
    }

    // Save watcher teams
    if let Some(ref watcher_ids) = form.watcher_team_ids {
        for wid in watcher_ids.split(',') {
            let wid = wid.trim();
            if !wid.is_empty() {
                let _ = sqlx::query(
                    "INSERT INTO event_type_watchers (event_type_id, team_id) VALUES (?, ?)",
                )
                .bind(&et_id)
                .bind(wid)
                .execute(&state.pool)
                .await;
            }
        }
    }

    // Save booking frequency limits
    save_frequency_limits(&state.pool, &et_id, &form.frequency_limits).await;

    Redirect::to("/dashboard/event-types").into_response()
}

async fn edit_group_event_type_form(
    State(state): State<Arc<AppState>>,
    auth_user: crate::auth::AuthUser,
    Path((team_id, slug)): Path<(String, String)>,
) -> impl IntoResponse {
    let user = &auth_user.user;

    let is_admin = user.role == "admin";

    let et: Option<(
        String,
        String,
        String,
        Option<String>,
        i32,
        i32,
        i32,
        i32,
        i32,
        String,
        Option<String>,
        Option<i32>,
        String,
        String,
        i32,
        String,
    )> = if is_admin {
        sqlx::query_as(
            "SELECT et.id, et.slug, et.title, et.description, et.duration_min, et.buffer_before, et.buffer_after, et.min_notice_min, et.requires_confirmation, et.location_type, et.location_value, et.reminder_minutes, et.team_id, et.visibility, et.max_additional_guests, et.scheduling_mode
             FROM event_types et
             WHERE et.team_id = ? AND et.slug = ?",
        )
        .bind(&team_id)
        .bind(&slug)
        .fetch_optional(&state.pool)
        .await
        .unwrap_or(None)
    } else {
        sqlx::query_as(
            "SELECT et.id, et.slug, et.title, et.description, et.duration_min, et.buffer_before, et.buffer_after, et.min_notice_min, et.requires_confirmation, et.location_type, et.location_value, et.reminder_minutes, et.team_id, et.visibility, et.max_additional_guests, et.scheduling_mode
             FROM event_types et
             JOIN team_members tm ON tm.team_id = et.team_id
             WHERE tm.user_id = ? AND tm.role = 'admin' AND et.team_id = ? AND et.slug = ?",
        )
        .bind(&user.id)
        .bind(&team_id)
        .bind(&slug)
        .fetch_optional(&state.pool)
        .await
        .unwrap_or(None)
    };

    let (
        et_id,
        et_slug,
        et_title,
        et_desc,
        duration,
        buf_before,
        buf_after,
        min_notice,
        requires_conf,
        loc_type,
        loc_value,
        reminder_min,
        team_id,
        visibility,
        max_additional_guests,
        scheduling_mode,
    ) = match et {
        Some(e) => e,
        None => return Html("Event type not found.".to_string()),
    };

    let slot_interval: Option<i32> =
        sqlx::query_scalar("SELECT slot_interval_min FROM event_types WHERE id = ?")
            .bind(&et_id)
            .fetch_one(&state.pool)
            .await
            .unwrap_or(None);

    let default_calendar_view: String =
        sqlx::query_scalar("SELECT default_calendar_view FROM event_types WHERE id = ?")
            .bind(&et_id)
            .fetch_one(&state.pool)
            .await
            .unwrap_or_else(|_| "month".to_string());

    let first_slot_only: i32 =
        sqlx::query_scalar("SELECT first_slot_only FROM event_types WHERE id = ?")
            .bind(&et_id)
            .fetch_one(&state.pool)
            .await
            .unwrap_or(0);

    let form_timezone: String =
        sqlx::query_scalar::<_, Option<String>>("SELECT timezone FROM event_types WHERE id = ?")
            .bind(&et_id)
            .fetch_optional(&state.pool)
            .await
            .unwrap_or(None)
            .flatten()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| user.timezone.clone());

    // Min-notice for guest-initiated cancel and reschedule (NULL = no
    // restriction). Pulled separately to keep the existing tuple compact.
    let cancel_notice_min: Option<i32> = sqlx::query_scalar::<_, Option<i32>>(
        "SELECT cancel_notice_min FROM event_types WHERE id = ?",
    )
    .bind(&et_id)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None)
    .flatten();
    let reschedule_notice_min: Option<i32> = sqlx::query_scalar::<_, Option<i32>>(
        "SELECT reschedule_notice_min FROM event_types WHERE id = ?",
    )
    .bind(&et_id)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None)
    .flatten();
    let (form_cancel_notice_value, form_cancel_notice_unit) =
        minutes_to_notice_form(cancel_notice_min);
    let (form_reschedule_notice_value, form_reschedule_notice_unit) =
        minutes_to_notice_form(reschedule_notice_min);

    let meeting_pattern_override: Option<String> = sqlx::query_scalar::<_, Option<String>>(
        "SELECT meeting_pattern_override FROM event_types WHERE id = ?",
    )
    .bind(&et_id)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None)
    .flatten();

    // Get current availability rules
    let all_rules: Vec<(i32, String, String)> = sqlx::query_as(
        "SELECT day_of_week, start_time, end_time FROM availability_rules WHERE event_type_id = ? ORDER BY day_of_week, start_time",
    )
    .bind(&et_id)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    let avail_days: String = {
        let mut days: Vec<i32> = all_rules.iter().map(|(d, _, _)| *d).collect();
        days.sort();
        days.dedup();
        days.iter()
            .map(|d| d.to_string())
            .collect::<Vec<_>>()
            .join(",")
    };

    let mut windows: Vec<(String, String)> = Vec::new();
    for (_, s, e) in &all_rules {
        let pair = (s.clone(), e.clone());
        if !windows.contains(&pair) {
            windows.push(pair);
        }
    }
    let avail_windows: String = windows
        .iter()
        .map(|(s, e)| format!("{}-{}", s, e))
        .collect::<Vec<_>>()
        .join(",");
    let (avail_start, avail_end) = windows
        .first()
        .cloned()
        .unwrap_or_else(|| ("09:00".to_string(), "17:00".to_string()));

    // Build per-day schedule string
    let avail_schedule = build_avail_schedule(&all_rules);

    // Fetch team members with per-ET weights (round-robin priority OR collective exclusion)
    let is_round_robin_group = scheduling_mode == "round_robin";
    let is_collective_team = scheduling_mode == "collective";
    let members_ctx: Vec<minijinja::Value> = if is_round_robin_group || is_collective_team {
        // See the note on the personal-ET edit path: pulling `timezone` makes
        // wrong-TZ users visible on the Member priority list.
        let members: Vec<(String, String, Option<String>, String)> = sqlx::query_as(
            "SELECT u.id, u.name, u.avatar_path, u.timezone \
             FROM users u JOIN team_members tm ON tm.user_id = u.id \
             WHERE tm.team_id = ? AND u.enabled = 1 \
             ORDER BY u.name",
        )
        .bind(&team_id)
        .fetch_all(&state.pool)
        .await
        .unwrap_or_default();

        let et_weights: Vec<(String, i64)> = sqlx::query_as(
            "SELECT user_id, weight FROM event_type_member_weights WHERE event_type_id = ?",
        )
        .bind(&et_id)
        .fetch_all(&state.pool)
        .await
        .unwrap_or_default();
        let wmap: std::collections::HashMap<String, i64> = et_weights.into_iter().collect();

        members
            .iter()
            .map(|(uid, name, avatar_path, timezone)| {
                let w = wmap.get(uid).copied().unwrap_or(1);
                context! {
                    user_id => uid,
                    name => name,
                    has_avatar => avatar_path.is_some(),
                    initials => compute_initials(name),
                    weight => w,
                    timezone => timezone,
                }
            })
            .collect()
    } else {
        Vec::new()
    };

    // Load all teams for watcher selection
    let all_teams: Vec<(String, String)> = if is_admin {
        sqlx::query_as("SELECT id, name FROM teams ORDER BY name")
            .fetch_all(&state.pool)
            .await
            .unwrap_or_default()
    } else {
        sqlx::query_as(
            "SELECT t.id, t.name FROM teams t JOIN team_members tm ON tm.team_id = t.id WHERE tm.user_id = ? ORDER BY t.name",
        )
        .bind(&user.id)
        .fetch_all(&state.pool)
        .await
        .unwrap_or_default()
    };
    let watcher_teams_ctx: Vec<minijinja::Value> = all_teams
        .iter()
        .map(|(id, name)| context! { id => id, name => name })
        .collect();

    // Load selected watcher team IDs
    let selected_watchers: Vec<(String,)> =
        sqlx::query_as("SELECT team_id FROM event_type_watchers WHERE event_type_id = ?")
            .bind(&et_id)
            .fetch_all(&state.pool)
            .await
            .unwrap_or_default();
    let selected_watcher_team_ids: String = selected_watchers
        .iter()
        .map(|(id,)| id.as_str())
        .collect::<Vec<_>>()
        .join(",");

    // Fetch booking frequency limits
    let freq_limits: Vec<(i32, String, i32)> = sqlx::query_as(
        "SELECT max_bookings, period, per_member FROM booking_frequency_limits WHERE event_type_id = ?",
    )
    .bind(&et_id)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    let form_frequency_limits = freq_limits
        .iter()
        .map(|(c, p, m)| {
            if *m != 0 {
                format!("{}:{}:m", c, p)
            } else {
                format!("{}:{}", c, p)
            }
        })
        .collect::<Vec<_>>()
        .join(",");

    let tmpl = match state.templates.get_template("event_type_form.html") {
        Ok(t) => t,
        Err(e) => return internal_error_html("template render", &e),
    };

    let (impersonating, impersonating_name, _) = impersonation_ctx(&auth_user);
    Html(
        tmpl.render(context! {
            editing => true,
            is_group => true,
            form_team_id => team_id,
            original_slug => et_slug,
            form_title => et_title,
            form_slug => et_slug,
            form_description => et_desc.unwrap_or_default(),
            form_duration => duration,
            form_slot_interval => slot_interval.unwrap_or(0),
            form_buffer_before => buf_before,
            form_buffer_after => buf_after,
            form_min_notice => min_notice,
            form_requires_confirmation => requires_conf != 0,
            form_visibility => visibility,
            form_location_type => loc_type,
            form_location_value => loc_value.unwrap_or_default(),
            form_meeting_pattern_override => meeting_pattern_override.clone().unwrap_or_default(),
            form_avail_days => avail_days,
            form_avail_start => avail_start,
            form_avail_end => avail_end,
            form_avail_windows => avail_windows,
            form_avail_schedule => avail_schedule,
            form_reminder_minutes => reminder_min.unwrap_or(0),
            form_max_additional_guests => max_additional_guests,
            form_scheduling_mode => scheduling_mode,
            form_default_calendar_view => default_calendar_view,
            form_first_slot_only => first_slot_only != 0,
            form_frequency_limits => form_frequency_limits,
            form_timezone => &form_timezone,
            form_cancel_notice_value => form_cancel_notice_value,
            form_cancel_notice_unit => form_cancel_notice_unit,
            form_reschedule_notice_value => form_reschedule_notice_value,
            form_reschedule_notice_unit => form_reschedule_notice_unit,
            tz_options => common_timezones_with(&form_timezone)
                .iter()
                .map(|(iana, label)| context! { value => iana, label => label })
                .collect::<Vec<_>>(),
            is_round_robin_group => is_round_robin_group,
            is_collective_team => is_collective_team,
            priority_members => members_ctx,
            watcher_teams => watcher_teams_ctx,
            selected_watcher_team_ids => selected_watcher_team_ids,
            error => "",
            sidebar => sidebar_context(&auth_user, "event-types"),
            impersonating => impersonating,
            impersonating_name => impersonating_name,
        })
        .unwrap_or_else(|e| internal_error_body("template render", &e)),
    )
}

async fn update_group_event_type(
    State(state): State<Arc<AppState>>,
    auth_user: crate::auth::AuthUser,
    headers: HeaderMap,
    Path((team_id, slug)): Path<(String, String)>,
    Form(form): Form<EventTypeForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }
    let user = &auth_user.user;

    let is_admin = user.role == "admin";

    let et: Option<(String, String)> = if is_admin {
        sqlx::query_as(
            "SELECT et.id, et.team_id
             FROM event_types et
             WHERE et.team_id = ? AND et.slug = ?",
        )
        .bind(&team_id)
        .bind(&slug)
        .fetch_optional(&state.pool)
        .await
        .unwrap_or(None)
    } else {
        sqlx::query_as(
            "SELECT et.id, et.team_id
             FROM event_types et
             JOIN team_members tm ON tm.team_id = et.team_id
             WHERE tm.user_id = ? AND tm.role = 'admin' AND et.team_id = ? AND et.slug = ?",
        )
        .bind(&user.id)
        .bind(&team_id)
        .bind(&slug)
        .fetch_optional(&state.pool)
        .await
        .unwrap_or(None)
    };

    let (et_id, team_id) = match et {
        Some(e) => e,
        None => return Redirect::to("/dashboard/event-types").into_response(),
    };

    let new_slug = form.slug.trim().to_lowercase().replace(' ', "-");
    let requires_confirmation = form.requires_confirmation.as_deref() == Some("on");
    let visibility = form.visibility.as_deref().unwrap_or("public").to_string();

    // Check slug uniqueness within the team if changed
    if new_slug != slug {
        let existing: Option<(String,)> =
            sqlx::query_as("SELECT id FROM event_types WHERE team_id = ? AND slug = ?")
                .bind(&team_id)
                .bind(&new_slug)
                .fetch_optional(&state.pool)
                .await
                .unwrap_or(None);

        if existing.is_some() {
            return render_event_type_form_error(
                &state,
                &auth_user,
                "An event type with this slug already exists in this team.",
                &form,
                true,
            )
            .into_response();
        }
    }

    let location_type = form.location_type.as_deref().unwrap_or("link");
    let location_value = form
        .location_value
        .as_deref()
        .filter(|s| !s.trim().is_empty());

    let location_required = !matches!(
        location_type,
        meeting::LOCATION_TYPE_JITSI | meeting::LOCATION_TYPE_WEBHOOK
    );
    if location_required && location_value.is_none() {
        return render_event_type_form_error(
            &state,
            &auth_user,
            "Location details are required (e.g. a video call link, phone number, or address).",
            &form,
            true,
        )
        .into_response();
    }

    let reminder_minutes = {
        let v = parse_int_field(&form.reminder_minutes, 0);
        if v > 0 {
            Some(v)
        } else {
            None
        }
    };

    let default_calendar_view = match form.default_calendar_view.as_deref().unwrap_or("month") {
        v @ ("month" | "week" | "column") => v.to_string(),
        _ => "month".to_string(),
    };

    let timezone = normalize_event_type_tz(form.timezone.as_deref(), &user.timezone);
    let cancel_notice_min =
        parse_notice_to_minutes(&form.cancel_notice_value, &form.cancel_notice_unit);
    let reschedule_notice_min =
        parse_notice_to_minutes(&form.reschedule_notice_value, &form.reschedule_notice_unit);

    let meeting_pattern_override = form
        .meeting_pattern_override
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    let _ = sqlx::query(
        "UPDATE event_types SET slug = ?, title = ?, description = ?, duration_min = ?, slot_interval_min = ?, buffer_before = ?, buffer_after = ?, min_notice_min = ?, requires_confirmation = ?, location_type = ?, location_value = ?, reminder_minutes = ?, visibility = ?, max_additional_guests = ?, scheduling_mode = ?, default_calendar_view = ?, first_slot_only = ?, timezone = ?, cancel_notice_min = ?, reschedule_notice_min = ?, meeting_pattern_override = ? WHERE id = ?",
    )
    .bind(&new_slug)
    .bind(form.title.trim())
    .bind(form.description.as_deref().filter(|s| !s.trim().is_empty()))
    .bind(parse_int_field(&form.duration_min, 30))
    .bind(parse_optional_positive_int(&form.slot_interval_min))
    .bind(parse_int_field(&form.buffer_before, 0))
    .bind(parse_int_field(&form.buffer_after, 0))
    .bind(parse_int_field(&form.min_notice_min, 60))
    .bind(requires_confirmation as i32)
    .bind(location_type)
    .bind(location_value)
    .bind(reminder_minutes)
    .bind(&visibility)
    .bind(parse_int_field(&form.max_additional_guests, 0))
    .bind(form.scheduling_mode.as_deref().unwrap_or("round_robin"))
    .bind(&default_calendar_view)
    .bind(if form.first_slot_only.as_deref() == Some("on") { 1 } else { 0 })
    .bind(&timezone)
    .bind(cancel_notice_min)
    .bind(reschedule_notice_min)
    .bind(&meeting_pattern_override)
    .bind(&et_id)
    .execute(&state.pool)
    .await;

    // Update availability rules. Pass the editing user's profile-default
    // schedule as a fallback so an empty submission falls back to it instead
    // of hardcoded Mon-Fri 09:00-17:00.
    let _ = sqlx::query("DELETE FROM availability_rules WHERE event_type_id = ?")
        .bind(&et_id)
        .execute(&state.pool)
        .await;

    ensure_user_avail_seeded(&state.pool, &user.id).await;
    let user_default = load_user_avail_schedule(&state.pool, &user.id).await;
    let schedule = parse_avail_schedule(
        form.avail_schedule.as_deref(),
        form.avail_days.as_deref(),
        form.avail_windows.as_deref(),
        form.avail_start.as_deref(),
        form.avail_end.as_deref(),
        Some(&user_default),
    );

    for (day, windows) in &schedule {
        for (ws, we) in windows {
            let rule_id = uuid::Uuid::new_v4().to_string();
            let _ = sqlx::query(
                "INSERT INTO availability_rules (id, event_type_id, day_of_week, start_time, end_time) VALUES (?, ?, ?, ?, ?)",
            )
            .bind(&rule_id)
            .bind(&et_id)
            .bind(day)
            .bind(ws)
            .bind(we)
            .execute(&state.pool)
            .await;
        }
    }

    // Update watcher teams: delete old, insert new
    let _ = sqlx::query("DELETE FROM event_type_watchers WHERE event_type_id = ?")
        .bind(&et_id)
        .execute(&state.pool)
        .await;

    if let Some(ref watcher_ids) = form.watcher_team_ids {
        for wid in watcher_ids.split(',') {
            let wid = wid.trim();
            if !wid.is_empty() {
                let _ = sqlx::query(
                    "INSERT INTO event_type_watchers (event_type_id, team_id) VALUES (?, ?)",
                )
                .bind(&et_id)
                .bind(wid)
                .execute(&state.pool)
                .await;
            }
        }
    }

    // Update booking frequency limits: delete old, insert new
    let _ = sqlx::query("DELETE FROM booking_frequency_limits WHERE event_type_id = ?")
        .bind(&et_id)
        .execute(&state.pool)
        .await;
    save_frequency_limits(&state.pool, &et_id, &form.frequency_limits).await;

    Redirect::to("/dashboard/event-types").into_response()
}

async fn toggle_group_event_type(
    State(state): State<Arc<AppState>>,
    auth_user: crate::auth::AuthUser,
    headers: HeaderMap,
    Path((team_id, slug)): Path<(String, String)>,
    Form(csrf): Form<CsrfForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &csrf._csrf) {
        return resp;
    }
    let user = &auth_user.user;

    let is_admin = user.role == "admin";

    // Scope by team_id from the route to disambiguate slugs shared across teams.
    let et: Option<(String,)> = if is_admin {
        sqlx::query_as("SELECT id FROM event_types WHERE team_id = ? AND slug = ?")
            .bind(&team_id)
            .bind(&slug)
            .fetch_optional(&state.pool)
            .await
            .unwrap_or(None)
    } else {
        sqlx::query_as(
            "SELECT et.id FROM event_types et \
             JOIN team_members tm ON tm.team_id = et.team_id \
             WHERE et.team_id = ? AND et.slug = ? AND tm.user_id = ? AND tm.role = 'admin' \
             LIMIT 1",
        )
        .bind(&team_id)
        .bind(&slug)
        .bind(&user.id)
        .fetch_optional(&state.pool)
        .await
        .unwrap_or(None)
    };

    if let Some((et_id,)) = et {
        let _ = sqlx::query(
            "UPDATE event_types SET enabled = CASE WHEN enabled = 1 THEN 0 ELSE 1 END WHERE id = ?",
        )
        .bind(&et_id)
        .execute(&state.pool)
        .await;

        tracing::debug!(event_type_id = %et_id, event_type_slug = %slug, "group event type toggled");
    }

    Redirect::to("/dashboard/event-types").into_response()
}

async fn delete_group_event_type(
    State(state): State<Arc<AppState>>,
    auth_user: crate::auth::AuthUser,
    headers: HeaderMap,
    Path((team_id, slug)): Path<(String, String)>,
    Form(csrf): Form<CsrfForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &csrf._csrf) {
        return resp;
    }
    let user = &auth_user.user;

    let is_admin = user.role == "admin";

    let et: Option<(String,)> = if is_admin {
        sqlx::query_as(
            "SELECT et.id FROM event_types et
             WHERE et.team_id = ? AND et.slug = ?",
        )
        .bind(&team_id)
        .bind(&slug)
        .fetch_optional(&state.pool)
        .await
        .unwrap_or(None)
    } else {
        sqlx::query_as(
            "SELECT et.id FROM event_types et
             JOIN team_members tm ON tm.team_id = et.team_id
             WHERE et.team_id = ? AND et.slug = ? AND tm.user_id = ? AND tm.role = 'admin' LIMIT 1",
        )
        .bind(&team_id)
        .bind(&slug)
        .bind(&user.id)
        .fetch_optional(&state.pool)
        .await
        .unwrap_or(None)
    };

    let et_id = match et {
        Some((id,)) => id,
        None => return Redirect::to("/dashboard/event-types").into_response(),
    };

    // Check for active bookings
    let active_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM bookings WHERE event_type_id = ? AND status IN ('confirmed', 'pending')",
    )
    .bind(&et_id)
    .fetch_one(&state.pool)
    .await
    .unwrap_or(0);

    if active_count > 0 {
        return Redirect::to("/dashboard/event-types").into_response();
    }

    // Delete in order: availability_rules, availability_overrides, event_type_calendars, bookings, event_type
    let _ = sqlx::query("DELETE FROM availability_rules WHERE event_type_id = ?")
        .bind(&et_id)
        .execute(&state.pool)
        .await;
    let _ = sqlx::query("DELETE FROM availability_overrides WHERE event_type_id = ?")
        .bind(&et_id)
        .execute(&state.pool)
        .await;
    let _ = sqlx::query("DELETE FROM event_type_calendars WHERE event_type_id = ?")
        .bind(&et_id)
        .execute(&state.pool)
        .await;
    let _ = sqlx::query("DELETE FROM bookings WHERE event_type_id = ?")
        .bind(&et_id)
        .execute(&state.pool)
        .await;
    let _ = sqlx::query("DELETE FROM event_types WHERE id = ?")
        .bind(&et_id)
        .execute(&state.pool)
        .await;

    tracing::info!(event_type_id = %et_id, user = %auth_user.user.email, "group event type deleted");

    Redirect::to("/dashboard/event-types").into_response()
}

// --- Legacy /g/ redirects ---

async fn redirect_g_to_team(Path(team_slug): Path<String>) -> impl IntoResponse {
    Redirect::permanent(&format!("/team/{}", team_slug))
}

async fn redirect_g_to_team_slug(
    Path((team_slug, slug)): Path<(String, String)>,
    Query(query): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let qs = if query.is_empty() {
        String::new()
    } else {
        format!(
            "?{}",
            query
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join("&")
        )
    };
    Redirect::permanent(&format!("/team/{}/{}{}", team_slug, slug, qs))
}

async fn redirect_g_to_team_slug_book(
    Path((team_slug, slug)): Path<(String, String)>,
) -> impl IntoResponse {
    Redirect::permanent(&format!("/team/{}/{}/book", team_slug, slug))
}

// --- Legacy /t/ team link redirects ---

async fn redirect_team_link_to_team(
    State(state): State<Arc<AppState>>,
    Path(token): Path<String>,
) -> impl IntoResponse {
    // Look up the team by invite_token (team links were migrated to teams)
    let team: Option<(Option<String>,)> =
        sqlx::query_as("SELECT slug FROM teams WHERE invite_token = ?")
            .bind(&token)
            .fetch_optional(&state.pool)
            .await
            .unwrap_or(None);

    match team {
        Some((Some(slug),)) => {
            Redirect::permanent(&format!("/team/{}?invite={}", slug, token)).into_response()
        }
        Some((None,)) => {
            // Team exists but has no slug — should not happen after migration fix,
            // but handle gracefully
            Html("Team not found.".to_string()).into_response()
        }
        None => Html("Team not found.".to_string()).into_response(),
    }
}

// --- Group public pages ---

async fn team_profile_page(
    State(state): State<Arc<AppState>>,
    optional_auth: crate::auth::OptionalAuthUser,
    Path(team_slug): Path<String>,
    Query(query): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let team: Option<(String, String, Option<String>, Option<String>, String, Option<String>)> =
        sqlx::query_as("SELECT id, name, description, avatar_path, visibility, invite_token FROM teams WHERE slug = ?")
            .bind(&team_slug)
            .fetch_optional(&state.pool)
            .await
            .unwrap_or(None);

    let (
        team_id,
        team_name,
        team_description,
        team_avatar_path,
        team_visibility,
        team_invite_token,
    ) = match team {
        Some(t) => t,
        None => return Html("Team not found.".to_string()),
    };

    // Logged-in team members (and global admins) bypass the private-team
    // invite token gate — their membership is the access. Compute once and
    // reuse for both the gate below and the event-type filter further down.
    let viewer_is_member_or_admin = match &optional_auth.user {
        Some(u) if u.role == "admin" => true,
        Some(u) => is_team_member(&state.pool, &u.id, &team_id).await,
        None => false,
    };

    let passed_invite = query.get("invite").cloned().unwrap_or_default();
    if team_visibility == "private" && !viewer_is_member_or_admin {
        match &team_invite_token {
            Some(expected) if !passed_invite.is_empty() && passed_invite == *expected => {
                // valid — continue
            }
            _ => {
                return Html("Team not found.".to_string());
            }
        }
    }

    // Logged-in team members (and global admins) see all enabled event types,
    // including private/internal — they have view access via the slot pages
    // anyway, so showing them on the profile makes them discoverable. Anonymous
    // visitors and non-members continue to see only public event types.
    let event_types: Vec<(String, String, Option<String>, i32, String)> =
        if viewer_is_member_or_admin {
            sqlx::query_as(
                "SELECT et.slug, et.title, et.description, et.duration_min, et.visibility
             FROM event_types et
             WHERE et.team_id = ? AND et.enabled = 1
             ORDER BY et.created_at",
            )
            .bind(&team_id)
            .fetch_all(&state.pool)
            .await
            .unwrap_or_default()
        } else {
            sqlx::query_as(
                "SELECT et.slug, et.title, et.description, et.duration_min, et.visibility
             FROM event_types et
             WHERE et.team_id = ? AND et.enabled = 1 AND et.visibility = 'public'
             ORDER BY et.created_at",
            )
            .bind(&team_id)
            .fetch_all(&state.pool)
            .await
            .unwrap_or_default()
        };

    let members: Vec<(String, String, Option<String>)> = sqlx::query_as(
        "SELECT u.id, u.name, u.avatar_path FROM users u \
         JOIN team_members tm ON tm.user_id = u.id \
         WHERE tm.team_id = ? AND u.enabled = 1 \
         ORDER BY u.name",
    )
    .bind(&team_id)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    let members_ctx: Vec<minijinja::Value> = members
        .iter()
        .map(|(id, name, ap)| {
            context! {
                id => id,
                name => name,
                has_avatar => ap.is_some(),
                initials => compute_initials(name),
            }
        })
        .collect();

    let tmpl = match state.templates.get_template("team_profile.html") {
        Ok(t) => t,
        Err(e) => return internal_error_html("template render", &e),
    };

    let et_ctx: Vec<minijinja::Value> = event_types
        .iter()
        .map(|(slug, title, desc, duration, visibility)| {
            context! {
                slug => slug,
                title => title,
                description => desc.as_deref().map(crate::utils::render_inline_markdown),
                duration_min => duration,
                visibility => visibility,
            }
        })
        .collect();

    // Pass invite token through if team is private (so links include it)
    let invite_token_for_template = if team_visibility == "private" && !passed_invite.is_empty() {
        passed_invite
    } else {
        String::new()
    };

    Html(
        tmpl.render(context! {
            team_id => team_id,
            team_name => team_name,
            team_slug => team_slug,
            team_description => team_description.as_deref().map(crate::utils::render_inline_markdown),
            team_has_avatar => team_avatar_path.is_some(),
            team_initials => compute_initials(&team_name),
            members => members_ctx,
            event_types => et_ctx,
            invite_token => invite_token_for_template,
            company_link => state.company_link.read().await.clone(),
        })
        .unwrap_or_else(|e| internal_error_body("template render", &e)),
    )
}

async fn show_group_slots(
    State(state): State<Arc<AppState>>,
    optional_auth: crate::auth::OptionalAuthUser,
    headers: HeaderMap,
    Path((team_slug, slug)): Path<(String, String)>,
    Query(query): Query<SlotsQuery>,
) -> Response {
    let embed = query.embed_params();
    let lang = crate::i18n::detect_from_headers(&headers);
    let et: Option<(String, String, String, Option<String>, i32, i32, i32, i32, String, Option<String>, String, String, String, String, Option<String>, String)> = sqlx::query_as(
        "SELECT et.id, et.slug, et.title, et.description, et.duration_min, et.buffer_before, et.buffer_after, et.min_notice_min, et.location_type, et.location_value, t.name, et.visibility, et.scheduling_mode, t.visibility, t.invite_token, et.default_calendar_view
         FROM event_types et
         JOIN teams t ON t.id = et.team_id
         WHERE t.slug = ? AND et.slug = ? AND et.enabled = 1",
    )
    .bind(&team_slug)
    .bind(&slug)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    let (
        et_id,
        et_slug,
        et_title,
        et_desc,
        duration,
        buf_before,
        buf_after,
        min_notice,
        loc_type,
        loc_value,
        team_name,
        visibility,
        scheduling_mode,
        team_visibility,
        team_invite_token,
        default_calendar_view,
    ) = match et {
        Some(e) => e,
        None => return Html("Event type not found.".to_string()).into_response(),
    };

    // Resolve the team id once and reuse for membership checks and downstream
    // queries. Can't fold this into the event-type SELECT above because sqlx
    // tuples cap at 16 columns and we're already at the limit.
    let team_id: String = match sqlx::query_scalar::<_, String>(
        "SELECT team_id FROM event_types WHERE id = ? AND team_id IS NOT NULL",
    )
    .bind(&et_id)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None)
    {
        Some(tid) => tid,
        None => return Html("Event type not found.".to_string()).into_response(),
    };

    // Global admins can view any team event type (matches their management
    // surface). Booking is still invite-gated for private/internal events;
    // global admins do not auto-bypass the booking gate.
    let is_logged_in_team_member = match &optional_auth.user {
        Some(u) if u.role == "admin" => true,
        Some(u) => is_team_member(&state.pool, &u.id, &team_id).await,
        None => false,
    };

    // Validate booking invite token if one was provided (used both for direct
    // booking-invite access and to mark the request as "can_book").
    let has_valid_booking_invite = if let Some(token) = query.invite.as_deref() {
        if token.is_empty() {
            false
        } else {
            let invite: Option<(Option<String>, i32, i32)> = sqlx::query_as(
                "SELECT expires_at, max_uses, used_count FROM booking_invites WHERE token = ? AND event_type_id = ?",
            )
            .bind(token)
            .bind(&et_id)
            .fetch_optional(&state.pool)
            .await
            .unwrap_or(None);
            match invite {
                Some((expires_at, max_uses, used_count)) => {
                    let not_expired = expires_at.as_deref().is_none_or(|exp| {
                        exp >= chrono::Utc::now()
                            .format("%Y-%m-%d %H:%M:%S")
                            .to_string()
                            .as_str()
                    });
                    not_expired && used_count < max_uses
                }
                None => false,
            }
        }
    } else {
        false
    };

    // Did the request supply a valid team-level invite token? Used for private
    // teams hosting public event types (legacy behavior preserved).
    let has_valid_team_invite = matches!(
        (&team_invite_token, &query.invite),
        (Some(expected), Some(provided)) if !provided.is_empty() && provided == expected
    );

    // Access matrix:
    //   public team + public event       → anyone
    //   private team + public event      → team invite OR logged-in team member
    //   any team + private/internal event → booking invite OR logged-in team member (view only)
    let can_view = match (team_visibility.as_str(), visibility.as_str()) {
        (_, "private") | (_, "internal") => has_valid_booking_invite || is_logged_in_team_member,
        ("private", _) => has_valid_team_invite || is_logged_in_team_member,
        _ => true,
    };

    if !can_view {
        let msg = if visibility == "private" || visibility == "internal" {
            "This event type requires an invite link."
        } else {
            // Public event on private team without team invite — preserve legacy
            // "Event type not found" response so we don't leak existence.
            "Event type not found."
        };
        return Html(msg.to_string()).into_response();
    }

    // can_book: only with a valid booking invite for private/internal events.
    // Public events: anyone who can view can also book.
    let can_book = match visibility.as_str() {
        "private" | "internal" => has_valid_booking_invite,
        _ => can_view,
    };

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

    // Build team busy source: fetch busy times per member
    let now_host = Utc::now().with_timezone(&host_tz).naive_local();
    let end_date = now_host.date() + Duration::days((start_offset + days_ahead) as i64);
    let window_end = end_date.and_hms_opt(23, 59, 59).unwrap_or(now_host);

    let busy = {
        let tid = &team_id;
        let members: Vec<(String,)> = sqlx::query_as(
            "SELECT u.id FROM users u JOIN team_members tm ON tm.user_id = u.id \
             LEFT JOIN event_type_member_weights etw ON etw.user_id = u.id AND etw.event_type_id = ? \
             WHERE tm.team_id = ? AND u.enabled = 1 \
             AND COALESCE(etw.weight, 1) > 0",
        ).bind(&et_id).bind(tid).fetch_all(&state.pool).await.unwrap_or_default();
        // Sync all group members' calendars if stale. sync_if_stale holds
        // a per-source mutex and re-checks staleness inside the lock, so
        // even with this fan-out at most one CalDAV fetch per source is in
        // flight at a time.
        let mut sync_tasks = tokio::task::JoinSet::new();
        for (uid,) in &members {
            let pool = state.pool.clone();
            let key = state.secret_key;
            let uid = uid.clone();
            sync_tasks.spawn(async move {
                crate::commands::sync::sync_if_stale(&pool, &key, &uid).await;
            });
        }
        while sync_tasks.join_next().await.is_some() {}
        let mut member_busy = HashMap::new();
        for (uid,) in &members {
            let mut busy = fetch_busy_times_for_user(
                &state.pool,
                uid,
                now_host,
                window_end,
                host_tz,
                Some(&et_id),
            )
            .await;
            // Constrain each member to their personal working hours, converted
            // from their own timezone into host_tz. Members without explicit
            // hours in user_availability_rules are returned unconstrained
            // (user_avail_as_busy short-circuits to an empty Vec), so we never
            // plant surprise 9-17 defaults — only respect hours users actually
            // set on the settings page.
            busy.extend(user_avail_as_busy(&state.pool, uid, now_host, window_end, host_tz).await);
            member_busy.insert(uid.clone(), busy);
        }
        if scheduling_mode == "collective" {
            BusySource::Team(member_busy)
        } else {
            BusySource::Group(member_busy)
        }
    };

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

    let days_ctx: Vec<minijinja::Value> = slot_days
        .iter()
        .map(|d| {
            let slots: Vec<minijinja::Value> = d
                .slots
                .iter()
                .map(|s| context! { start => s.start, end => s.end, host_date => s.host_date, host_time => s.host_time, guest_date => s.guest_date })
                .collect();
            context! { date => d.date, label => d.label, slots => slots }
        })
        .collect();

    let available_dates: Vec<String> = slot_days.iter().map(|d| d.date.clone()).collect();

    let tz_options: Vec<minijinja::Value> = common_timezones_with(&guest_tz_name)
        .iter()
        .map(|(iana, label)| context! { value => iana, label => label, selected => (*iana == guest_tz_name) })
        .collect();

    // Fetch team avatar for sidebar display (team_id is already in scope from
    // the initial event-type lookup).
    let team_avatar_path: Option<String> =
        sqlx::query_scalar("SELECT avatar_path FROM teams WHERE id = ?")
            .bind(&team_id)
            .fetch_optional(&state.pool)
            .await
            .unwrap_or(None)
            .flatten();

    // Fetch active team members for sidebar display (exclude members with weight=0)
    let team_members_rows: Vec<(String, String, Option<String>)> = sqlx::query_as(
        "SELECT u.id, u.name, u.avatar_path FROM users u \
         JOIN team_members tm ON tm.user_id = u.id \
         LEFT JOIN event_type_member_weights etw ON etw.user_id = u.id AND etw.event_type_id = ? \
         WHERE tm.team_id = ? AND u.enabled = 1 AND COALESCE(etw.weight, 1) > 0 \
         ORDER BY u.name",
    )
    .bind(&et_id)
    .bind(&team_id)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    let team_members_ctx: Vec<minijinja::Value> = team_members_rows
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

    let (meeting_jitsi_label, meeting_webhook_label) = meeting_provider_labels(&state).await;
    let tmpl = match state.templates.get_template("slots.html") {
        Ok(t) => t,
        Err(e) => return internal_error_html("internal", &e).into_response(),
    };
    let rendered = tmpl
        .render(context! {
            meeting_jitsi_label => meeting_jitsi_label,
            meeting_webhook_label => meeting_webhook_label,
            event_type => context! {
                slug => et_slug,
                title => et_title,
                description => et_desc.as_deref().map(crate::utils::render_inline_markdown),
                duration_min => duration,
                location_type => loc_type,
                location_value => loc_value,
            },
            host_name => team_name,
            team_slug => team_slug,
            team_id => team_id,
            team_has_avatar => team_avatar_path.is_some(),
            team_initials => compute_initials(&team_name),
            team_members => team_members_ctx,
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
            invite_token => query.invite.as_deref().unwrap_or(""),
            default_calendar_view => embed.layout.as_deref().filter(|s| !s.is_empty()).unwrap_or(default_calendar_view.as_str()),
            company_link => state.company_link.read().await.clone(),
            lang => lang,
            can_book => can_book,
            embed => embed.is_embedded(),
            embed_brand => embed.brand_css().unwrap_or_default(),
            embed_theme => embed.theme.as_deref().unwrap_or(""),
            embed_qs_amp => embed.query_suffix(true),
            embed_qs_q => embed.query_suffix(false),
        })
        .unwrap_or_else(|e| internal_error_body("template render", &e));

    html_response(rendered, &embed)
}

async fn show_group_book_form(
    State(state): State<Arc<AppState>>,
    optional_auth: crate::auth::OptionalAuthUser,
    headers: HeaderMap,
    Path((team_slug, slug)): Path<(String, String)>,
    Query(query): Query<BookQuery>,
) -> Response {
    let embed = query.embed_params();
    let lang = crate::i18n::detect_from_headers(&headers);
    let et: Option<(String, String, String, Option<String>, i32, String, Option<String>, String, String, i32, String, Option<String>, String)> = sqlx::query_as(
        "SELECT et.id, et.slug, et.title, et.description, et.duration_min, et.location_type, et.location_value, t.name, et.visibility, et.max_additional_guests, t.visibility, t.invite_token, t.id
         FROM event_types et
         JOIN teams t ON t.id = et.team_id
         WHERE t.slug = ? AND et.slug = ? AND et.enabled = 1",
    )
    .bind(&team_slug)
    .bind(&slug)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    let (
        et_id,
        et_slug,
        et_title,
        et_desc,
        duration,
        loc_type,
        loc_value,
        team_name,
        visibility,
        max_additional_guests,
        team_visibility,
        team_invite_token,
        team_id,
    ) = match et {
        Some(e) => e,
        None => return Html("Event type not found.".to_string()).into_response(),
    };

    // Logged-in team members (and global admins) substitute for the team
    // invite token on public events of private teams. Private/internal events
    // still require a valid booking-invite token regardless of team membership.
    let viewer_is_member_or_admin = match &optional_auth.user {
        Some(u) if u.role == "admin" => true,
        Some(u) => is_team_member(&state.pool, &u.id, &team_id).await,
        None => false,
    };

    let invite_guest_name;
    let invite_guest_email;
    if visibility == "private" || visibility == "internal" {
        let token = match &query.invite {
            Some(t) => t,
            None => {
                return Html("This event type requires an invite link.".to_string()).into_response()
            }
        };
        let invite: Option<(String, String, Option<String>, i32, i32)> = sqlx::query_as(
            "SELECT guest_name, guest_email, expires_at, max_uses, used_count FROM booking_invites WHERE token = ? AND event_type_id = ?",
        )
        .bind(token)
        .bind(&et_id)
        .fetch_optional(&state.pool)
        .await
        .unwrap_or(None);

        match invite {
            None => return Html("Invalid invite link.".to_string()).into_response(),
            Some((name, email, expires_at, max_uses, used_count)) => {
                if let Some(exp) = &expires_at {
                    if exp < &chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string() {
                        return Html("This invite link has expired.".to_string()).into_response();
                    }
                }
                if used_count >= max_uses {
                    return Html("This invite link has already been used.".to_string())
                        .into_response();
                }
                invite_guest_name = Some(name);
                invite_guest_email = Some(email);
            }
        }
    } else if team_visibility == "private" && !viewer_is_member_or_admin {
        // Public event type on a private team — needs the team invite token
        // unless the viewer is a logged-in team member or global admin.
        let valid = matches!((&team_invite_token, &query.invite), (Some(expected), Some(provided)) if !provided.is_empty() && provided == expected);
        if !valid {
            return Html("Event type not found.".to_string()).into_response();
        }
        invite_guest_name = None;
        invite_guest_email = None;
    } else {
        invite_guest_name = None;
        invite_guest_email = None;
    }

    let guest_tz = parse_guest_tz(query.tz.as_deref());
    let guest_tz_name = guest_tz.name().to_string();

    let date = match NaiveDate::parse_from_str(&query.date, "%Y-%m-%d") {
        Ok(d) => d,
        Err(_) => return Html("Invalid date format.".to_string()).into_response(),
    };
    let time = match NaiveTime::parse_from_str(&query.time, "%H:%M") {
        Ok(t) => t,
        Err(_) => return Html("Invalid time format.".to_string()).into_response(),
    };
    let end_time = (date.and_time(time) + Duration::minutes(duration as i64))
        .time()
        .format("%H:%M")
        .to_string();
    let date_label = crate::i18n::format_long_date(date, lang);

    let (meeting_jitsi_label, meeting_webhook_label) = meeting_provider_labels(&state).await;
    let tmpl = match state.templates.get_template("book.html") {
        Ok(t) => t,
        Err(e) => return internal_error_html("internal", &e).into_response(),
    };
    let captcha = captcha::CaptchaVars::from_config(&*state.captcha_config.read().await);
    let rendered = tmpl
        .render(context! {
            meeting_jitsi_label => meeting_jitsi_label,
            meeting_webhook_label => meeting_webhook_label,
            event_type => context! {
                slug => et_slug,
                title => et_title,
                description => et_desc.as_deref().map(crate::utils::render_inline_markdown),
                duration_min => duration,
                location_type => loc_type,
                location_value => loc_value,
            },
            host_name => team_name,
            team_slug => team_slug,
            date => query.date,
            date_label => date_label,
            time_start => query.time,
            time_end => end_time,
            guest_tz => guest_tz_name,
            error => "",
            form_name => invite_guest_name.as_deref().unwrap_or(""),
            form_email => invite_guest_email.as_deref().unwrap_or(""),
            form_notes => "",
            invite_token => query.invite.as_deref().unwrap_or(""),
            max_additional_guests => max_additional_guests,
            company_link => state.company_link.read().await.clone(),
            captcha_enabled => captcha.enabled,
            captcha_api_endpoint => captcha.api_endpoint,
            captcha_widget_url => captcha.widget_url,
            lang => lang,
            embed => embed.is_embedded(),
            embed_brand => embed.brand_css().unwrap_or_default(),
            embed_theme => embed.theme.as_deref().unwrap_or(""),
            embed_qs_amp => embed.query_suffix(true),
            embed_qs_q => embed.query_suffix(false),
        })
        .unwrap_or_else(|e| internal_error_body("template render", &e));

    html_response(rendered, &embed)
}

async fn handle_group_booking(
    State(state): State<Arc<AppState>>,
    optional_auth: crate::auth::OptionalAuthUser,
    headers: axum::http::HeaderMap,
    Path((team_slug, slug)): Path<(String, String)>,
    Query(embed): Query<EmbedParams>,
    Form(form): Form<BookForm>,
) -> Response {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }
    let lang = crate::i18n::detect_from_headers(&headers);
    let captcha_cfg = state.captcha_config.read().await;
    if captcha::verify(&captcha_cfg, form.captcha_token.as_deref())
        .await
        .is_err()
    {
        tracing::warn!("captcha failed on group booking");
        return render_booking_action_error(
            &state,
            &headers,
            "Captcha verification failed",
            "Please go back and try again.",
        );
    }
    drop(captcha_cfg);
    // Rate limit by IP
    let client_ip = client_ip_for_rate_limit(&headers);
    if state.booking_limiter.check_limited(&client_ip).await {
        tracing::warn!(ip = %client_ip, "rate limited");
        return Html("Too many booking attempts. Please try again in a few minutes.".to_string())
            .into_response();
    }

    if let Err(e) = validate_booking_input(&form.name, &form.email, &form.notes) {
        return render_booking_action_error(&state, &headers, "Invalid booking details", &e);
    }

    let et: Option<(String, String, String, i32, i32, i32, i32, i32, String, Option<String>, String, Option<i32>, String, i32, String, Option<String>)> = sqlx::query_as(
        "SELECT et.id, et.slug, et.title, et.duration_min, et.buffer_before, et.buffer_after, et.min_notice_min, et.requires_confirmation, et.location_type, et.location_value, et.team_id, et.reminder_minutes, et.visibility, et.max_additional_guests, t.visibility, t.invite_token
         FROM event_types et
         JOIN teams t ON t.id = et.team_id
         WHERE t.slug = ? AND et.slug = ? AND et.enabled = 1",
    )
    .bind(&team_slug)
    .bind(&slug)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    let (
        et_id,
        _et_slug,
        et_title,
        duration,
        buffer_before,
        buffer_after,
        min_notice,
        requires_confirmation,
        loc_type,
        loc_value,
        team_id,
        reminder_min,
        visibility,
        max_additional_guests,
        team_visibility,
        team_invite_token,
    ) = match et {
        Some(e) => e,
        None => return Html("Event type not found.".to_string()).into_response(),
    };
    let needs_approval = requires_confirmation != 0;

    // Parse additional guests
    let additional_attendees = match parse_additional_guests(
        &form.additional_guests,
        max_additional_guests,
        &form.email,
    ) {
        Ok(emails) => emails,
        Err(e) => return Html(e).into_response(),
    };

    // Validate access
    if visibility == "private" || visibility == "internal" {
        let token = match &form.invite_token {
            Some(t) if !t.is_empty() => t,
            _ => {
                return Html("This event type requires an invite link.".to_string()).into_response()
            }
        };
        let invite: Option<(Option<String>, i32, i32)> = sqlx::query_as(
            "SELECT expires_at, max_uses, used_count FROM booking_invites WHERE token = ? AND event_type_id = ?",
        )
        .bind(token)
        .bind(&et_id)
        .fetch_optional(&state.pool)
        .await
        .unwrap_or(None);

        match invite {
            None => return Html("Invalid invite link.".to_string()).into_response(),
            Some((expires_at, max_uses, used_count)) => {
                if let Some(exp) = &expires_at {
                    if exp < &chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string() {
                        return Html("This invite link has expired.".to_string()).into_response();
                    }
                }
                if used_count >= max_uses {
                    return Html("This invite link has already been used.".to_string())
                        .into_response();
                }
            }
        }
    } else if team_visibility == "private" {
        // Public event on a private team: logged-in team members and global
        // admins bypass the team invite token requirement (their team
        // membership is the access). Private/internal events above already
        // returned, so this branch is public-only.
        let viewer_is_member_or_admin = match &optional_auth.user {
            Some(u) if u.role == "admin" => true,
            Some(u) => is_team_member(&state.pool, &u.id, &team_id).await,
            None => false,
        };
        if !viewer_is_member_or_admin {
            let valid = matches!((&team_invite_token, &form.invite_token), (Some(expected), Some(provided)) if !provided.is_empty() && provided == expected);
            if !valid {
                return Html("Event type not found.".to_string()).into_response();
            }
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
    let guest_timezone = guest_tz.name().to_string();
    let host_tz = get_host_tz(&state.pool, &et_id).await;

    // The URL carries the guest's local date/time. Convert to host-local
    // for availability checks and storage (existing semantics).
    let guest_local_start = date.and_time(start_time);
    let guest_local_end = guest_local_start + Duration::minutes(duration as i64);
    let slot_start = guest_to_host_local(guest_local_start, guest_tz, host_tz);
    let slot_end = slot_start + Duration::minutes(duration as i64);

    let now = Local::now().naive_local();
    if slot_start < now + Duration::minutes(min_notice as i64) {
        return Html("This slot is no longer available (too soon).".to_string()).into_response();
    }

    let id = uuid::Uuid::new_v4().to_string();
    let uid = format!("{}@calrs", uuid::Uuid::new_v4());
    let cancel_token = uuid::Uuid::new_v4().to_string();
    let reschedule_token = uuid::Uuid::new_v4().to_string();
    let start_at = slot_start.format("%Y-%m-%dT%H:%M:%S").to_string();
    let end_at = slot_end.format("%Y-%m-%dT%H:%M:%S").to_string();
    let guest_end_time = guest_local_end.time().format("%H:%M").to_string();

    let initial_status = if needs_approval {
        "pending"
    } else {
        "confirmed"
    };
    let confirm_token: Option<String> = if needs_approval {
        Some(uuid::Uuid::new_v4().to_string())
    } else {
        None
    };

    // Start a transaction to ensure atomicity of availability check + insert.
    let mut tx = match state.pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            return internal_error_response("database query", &e);
        }
    };

    // Pick an available group member
    let assigned = pick_group_member(
        &state.pool,
        &team_id,
        &et_id,
        slot_start,
        slot_end,
        buffer_before,
        buffer_after,
        host_tz,
    )
    .await;

    let (assigned_user_id, host_name, host_email) = match assigned {
        Some(a) => a,
        None => {
            let _ = tx.rollback().await;
            return Html("No team members are available for this slot.".to_string())
                .into_response();
        }
    };

    // Check booking frequency limits
    if would_exceed_frequency_limit(&state.pool, &et_id, slot_start, Some(&assigned_user_id)).await
    {
        let _ = tx.rollback().await;
        return render_booking_action_error(
            &state,
            &headers,
            "Not available right now",
            "The host isn't accepting more bookings for this date. Please pick a different date, or check back later.",
        );
    }

    let insert_result = sqlx::query(
        "INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, notes, start_at, end_at, status, cancel_token, reschedule_token, assigned_user_id, confirm_token, language)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&et_id)
    .bind(&uid)
    .bind(&form.name)
    .bind(&form.email)
    .bind(&guest_timezone)
    .bind(&form.notes)
    .bind(&start_at)
    .bind(&end_at)
    .bind(initial_status)
    .bind(&cancel_token)
    .bind(&reschedule_token)
    .bind(&assigned_user_id)
    .bind(&confirm_token)
    .bind(lang)
    .execute(&mut *tx)
    .await;

    match insert_result {
        Ok(_) => {}
        Err(e) => {
            let _ = tx.rollback().await;
            if e.to_string().contains("UNIQUE constraint failed") {
                return Html("This slot is no longer available.".to_string()).into_response();
            }
            return internal_error_response("database query", &e);
        }
    }

    // Insert additional attendees
    for attendee_email in &additional_attendees {
        let attendee_id = uuid::Uuid::new_v4().to_string();
        let _ =
            sqlx::query("INSERT INTO booking_attendees (id, booking_id, email) VALUES (?, ?, ?)")
                .bind(&attendee_id)
                .bind(&id)
                .bind(attendee_email)
                .execute(&mut *tx)
                .await;
    }

    if let Err(e) = tx.commit().await {
        if e.to_string().contains("UNIQUE constraint failed") {
            return Html("This slot is no longer available.".to_string()).into_response();
        }
        return internal_error_response("database query", &e);
    }

    tracing::info!(booking_id = %id, event_type = %slug, guest = %form.email, "booking created");

    // Increment invite used_count if this was an invite-based booking
    if visibility == "private" || visibility == "internal" {
        if let Some(token) = &form.invite_token {
            let _ = sqlx::query("UPDATE booking_invites SET used_count = used_count + 1 WHERE token = ? AND event_type_id = ?")
                .bind(token)
                .bind(&et_id)
                .execute(&state.pool)
                .await;
        }
    }

    // Build BookingDetails once. CalDAV push, watcher notifications, and email
    // sends all need it, and CalDAV push must run independently of SMTP.
    let location_display = resolve_booking_location(
        &state,
        &id,
        &et_id,
        Some(&assigned_user_id),
        loc_value.as_deref(),
        &form.name,
        &form.email,
        !needs_approval,
    )
    .await;
    let details = crate::email::BookingDetails {
        event_title: et_title.clone(),
        date: form.date.clone(),
        start_time: form.time.clone(),
        end_time: guest_end_time.clone(),
        guest_name: form.name.clone(),
        guest_email: form.email.clone(),
        guest_timezone: guest_timezone.clone(),
        host_name: host_name.clone(),
        host_email: host_email.clone(),
        uid: uid.clone(),
        notes: form.notes.clone(),
        location: location_display.clone(),
        reminder_minutes: reminder_min,
        additional_attendees: additional_attendees.clone(),
        guest_language: Some(lang.to_string()),
        host_timezone: host_tz.name().to_string(),
        ..Default::default()
    };

    // For confirmed bookings, push to CalDAV and notify watchers regardless of
    // SMTP availability. notify_watchers self-gates on SMTP for the email part.
    if !needs_approval {
        caldav_push_booking(
            &state.pool,
            &state.secret_key,
            &assigned_user_id,
            &uid,
            &details,
        )
        .await;
        notify_watchers(
            &state.pool,
            &state.secret_key,
            &id,
            &et_id,
            &host_name,
            &details,
        )
        .await;
    }

    let (cancel_notice_min, reschedule_notice_min) =
        fetch_event_type_notice_minutes(&state.pool, &et_id).await;

    // Send emails if SMTP is configured.
    if let Ok(Some(smtp_config)) =
        crate::email::load_smtp_config(&state.pool, &state.secret_key).await
    {
        let base_url = std::env::var("CALRS_BASE_URL").ok();
        let guest_cancel_url = base_url.as_ref().map(|base| {
            format!(
                "{}/booking/cancel/{}",
                base.trim_end_matches('/'),
                cancel_token
            )
        });
        let guest_reschedule_url = base_url.as_ref().map(|base| {
            format!(
                "{}/booking/reschedule/{}",
                base.trim_end_matches('/'),
                reschedule_token
            )
        });

        if needs_approval {
            let _ = crate::email::send_host_approval_request(
                &smtp_config,
                &details,
                &id,
                confirm_token.as_deref(),
                base_url.as_deref(),
            )
            .await;
            let _ = crate::email::send_guest_pending_notice_ex(
                &smtp_config,
                &details,
                guest_cancel_url.as_deref(),
                guest_reschedule_url.as_deref(),
            )
            .await;
        } else {
            let _ = crate::email::send_guest_confirmation_ex(
                &smtp_config,
                &details,
                guest_cancel_url.as_deref(),
                guest_reschedule_url.as_deref(),
                cancel_notice_min,
                reschedule_notice_min,
            )
            .await;
            let _ = crate::email::send_host_notification(&smtp_config, &details).await;
        }
    }

    let date_label = crate::i18n::format_long_date(date, lang);

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
            guest_email => form.email,
            notes => form.notes,
            pending => needs_approval,
            location_type => loc_type,
            location_value => location_display,
            additional_attendees => additional_attendees,
            cancel_notice_min => cancel_notice_min,
            reschedule_notice_min => reschedule_notice_min,
            company_link => state.company_link.read().await.clone(),
            lang => lang,
            embed => embed.is_embedded(),
            embed_brand => embed.brand_css().unwrap_or_default(),
            embed_theme => embed.theme.as_deref().unwrap_or(""),
            embed_qs_amp => embed.query_suffix(true),
            embed_qs_q => embed.query_suffix(false),
        })
        .unwrap_or_else(|e| internal_error_body("template render", &e));

    html_response(rendered, &embed)
}

// --- Group slot computation ---

// --- User profile page ---

async fn user_profile(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(username): Path<String>,
) -> impl IntoResponse {
    let user: Option<(
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    )> = sqlx::query_as(
        "SELECT id, name, title, bio, avatar_path, language FROM users WHERE username = ? AND enabled = 1",
    )
    .bind(&username)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    let (user_id, user_name, user_title, user_bio, avatar_path, language) = match user {
        Some(u) => u,
        None => return Html("User not found.".to_string()),
    };
    let lang = crate::i18n::resolve(language.as_deref(), &headers);

    let event_types: Vec<(String, String, Option<String>, i32)> = sqlx::query_as(
        "SELECT et.slug, et.title, et.description, et.duration_min
         FROM event_types et
         JOIN accounts a ON a.id = et.account_id
         WHERE a.user_id = ? AND et.enabled = 1 AND et.visibility = 'public'
         AND et.team_id IS NULL
         ORDER BY et.created_at",
    )
    .bind(&user_id)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    let tmpl = match state.templates.get_template("profile.html") {
        Ok(t) => t,
        Err(e) => return internal_error_html("template render", &e),
    };

    let et_ctx: Vec<minijinja::Value> = event_types
        .iter()
        .map(|(slug, title, desc, duration)| {
            context! { slug => slug, title => title, description => desc.as_deref().map(crate::utils::render_inline_markdown), duration_min => duration }
        })
        .collect();

    Html(
        tmpl.render(context! {
            host_name => &user_name,
            host_initials => compute_initials(&user_name),
            host_title => user_title,
            host_bio => user_bio.as_deref().map(crate::utils::render_inline_markdown),
            host_user_id => user_id,
            host_has_avatar => avatar_path.is_some(),
            username => username,
            event_types => et_ctx,
            company_link => state.company_link.read().await.clone(),
            lang,
        })
        .unwrap_or_else(|e| internal_error_body("template render", &e)),
    )
}

// --- Dynamic group link handlers ---

async fn show_dynamic_group_slots(
    state: &AppState,
    headers: &HeaderMap,
    combined_username: &str,
    slug: &str,
    query: &SlotsQuery,
) -> Html<String> {
    let lang = crate::i18n::detect_from_headers(headers);
    let usernames = match parse_dynamic_group_usernames(combined_username) {
        Ok(u) => u,
        Err(e) => return Html(e),
    };
    let dg_users = match validate_dynamic_group_users(&state.pool, &usernames).await {
        Ok(u) => u,
        Err(e) => return Html(e),
    };

    // Load event type from first user (owner)
    let owner_username = &usernames[0];
    let et: Option<(String, String, String, Option<String>, i32, i32, i32, i32, String, Option<String>, String, String, Option<String>, Option<String>, String, String)> = sqlx::query_as(
        "SELECT et.id, et.slug, et.title, et.description, et.duration_min, et.buffer_before, et.buffer_after, et.min_notice_min, et.location_type, et.location_value, u.id, u.name, u.title, u.avatar_path, et.visibility, et.default_calendar_view
         FROM event_types et
         JOIN accounts a ON a.id = et.account_id
         JOIN users u ON u.id = a.user_id
         WHERE u.username = ? AND et.slug = ? AND et.enabled = 1 AND u.enabled = 1",
    )
    .bind(owner_username)
    .bind(slug)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    let (
        et_id,
        et_slug,
        et_title,
        et_desc,
        duration,
        buf_before,
        buf_after,
        min_notice,
        loc_type,
        loc_value,
        _owner_user_id,
        _owner_name,
        _owner_title,
        _owner_avatar_path,
        visibility,
        default_calendar_view,
    ) = match et {
        Some(e) => e,
        None => return Html("Event type not found.".to_string()),
    };

    // Dynamic group links only for public event types
    if visibility != "public" {
        return Html("Dynamic group links are only available for public event types.".to_string());
    }

    // Build combined host display name
    let host_name = dg_users
        .iter()
        .map(|(_, _, name, _, _)| name.as_str())
        .collect::<Vec<_>>()
        .join(" & ");

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

    // Deferred loading: on initial page load (no &deferred=1), skip sync + computation
    // and render the page shell immediately. JS will fetch with &deferred=1 to get real data.
    let is_deferred_callback = query.deferred.as_deref() == Some("1");

    let slot_days = if is_deferred_callback {
        // Full sync + computation (AJAX callback). Safe to parallelize:
        // sync_if_stale holds a per-source mutex and re-checks staleness,
        // so same-source fan-in collapses to one fetch.
        let mut sync_tasks = tokio::task::JoinSet::new();
        for (uid, _, _, _, _) in &dg_users {
            let pool = state.pool.clone();
            let key = state.secret_key;
            let uid = uid.clone();
            sync_tasks.spawn(async move {
                crate::commands::sync::sync_if_stale(&pool, &key, &uid).await;
            });
        }
        while sync_tasks.join_next().await.is_some() {}

        let now_host = Utc::now().with_timezone(&host_tz).naive_local();
        let end_date = now_host.date() + Duration::days((start_offset + days_ahead) as i64);
        let window_end = end_date.and_hms_opt(23, 59, 59).unwrap_or(now_host);

        let mut member_busy = HashMap::new();
        for (i, (uid, _, _, _, _)) in dg_users.iter().enumerate() {
            let et_filter = if i == 0 { Some(et_id.as_str()) } else { None };
            let mut busy_times = fetch_busy_times_for_user(
                &state.pool,
                uid,
                now_host,
                window_end,
                host_tz,
                et_filter,
            )
            .await;
            // For non-owner participants, apply their default availability as constraints
            if i > 0 {
                ensure_user_avail_seeded(&state.pool, uid).await;
                let avail_busy =
                    user_avail_as_busy(&state.pool, uid, now_host, window_end, host_tz).await;
                busy_times.extend(avail_busy);
            }
            member_busy.insert(uid.clone(), busy_times);
        }
        let busy = BusySource::Team(member_busy);

        compute_slots(
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
        .await
    } else {
        // Initial load: empty slots, page renders instantly
        vec![]
    };

    let days_ctx: Vec<minijinja::Value> = slot_days
        .iter()
        .map(|d| {
            let slots: Vec<minijinja::Value> = d
                .slots
                .iter()
                .map(|s| {
                    context! { start => s.start, end => s.end, host_date => s.host_date, host_time => s.host_time, guest_date => s.guest_date }
                })
                .collect();
            context! { date => d.date, label => d.label, slots => slots }
        })
        .collect();

    let available_dates: Vec<String> = slot_days.iter().map(|d| d.date.clone()).collect();

    let tz_options: Vec<minijinja::Value> = common_timezones_with(&guest_tz_name)
        .iter()
        .map(|(iana, label)| {
            context! { value => iana, label => label, selected => (*iana == guest_tz_name) }
        })
        .collect();

    let (meeting_jitsi_label, meeting_webhook_label) = meeting_provider_labels(state).await;
    let tmpl = match state.templates.get_template("slots.html") {
        Ok(t) => t,
        Err(e) => return internal_error_html("internal", &e),
    };
    Html(
        tmpl.render(context! {
            meeting_jitsi_label => meeting_jitsi_label,
            meeting_webhook_label => meeting_webhook_label,
            event_type => context! {
                slug => et_slug,
                title => et_title,
                description => et_desc.as_deref().map(crate::utils::render_inline_markdown),
                duration_min => duration,
                location_type => loc_type,
                location_value => loc_value,
            },
            host_name => host_name,
            dg_members => dg_users.iter().map(|(id, _, name, _, avatar_path)| {
                context! {
                    id => id,
                    name => name,
                    has_avatar => avatar_path.is_some(),
                    initials => compute_initials(name),
                }
            }).collect::<Vec<_>>(),
            username => combined_username,
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
            invite_token => "",
            invite_guest_name => "",
            invite_guest_email => "",
            default_calendar_view => default_calendar_view,
            deferred_load => !is_deferred_callback,
            company_link => state.company_link.read().await.clone(),
            lang => lang,
        })
        .unwrap_or_else(|e| internal_error_body("template render", &e)),
    )
}

async fn show_dynamic_group_book_form(
    state: &AppState,
    headers: &HeaderMap,
    combined_username: &str,
    slug: &str,
    query: &BookQuery,
) -> Html<String> {
    let lang = crate::i18n::detect_from_headers(headers);
    let usernames = match parse_dynamic_group_usernames(combined_username) {
        Ok(u) => u,
        Err(e) => return Html(e),
    };
    let dg_users = match validate_dynamic_group_users(&state.pool, &usernames).await {
        Ok(u) => u,
        Err(e) => return Html(e),
    };

    let owner_username = &usernames[0];
    let et: Option<(String, String, String, Option<String>, i32, String, Option<String>, String, i32)> = sqlx::query_as(
        "SELECT et.id, et.slug, et.title, et.description, et.duration_min, et.location_type, et.location_value, et.visibility, et.max_additional_guests
         FROM event_types et
         JOIN accounts a ON a.id = et.account_id
         JOIN users u ON u.id = a.user_id
         WHERE u.username = ? AND et.slug = ? AND et.enabled = 1 AND u.enabled = 1",
    )
    .bind(owner_username)
    .bind(slug)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    let (
        _,
        et_slug,
        et_title,
        et_desc,
        duration,
        loc_type,
        loc_value,
        visibility,
        max_additional_guests,
    ) = match et {
        Some(e) => e,
        None => return Html("Event type not found.".to_string()),
    };

    if visibility != "public" {
        return Html("Dynamic group links are only available for public event types.".to_string());
    }

    let host_name = dg_users
        .iter()
        .map(|(_, _, name, _, _)| name.as_str())
        .collect::<Vec<_>>()
        .join(" & ");

    let guest_tz = parse_guest_tz(query.tz.as_deref());
    let guest_tz_name = guest_tz.name().to_string();

    let date = match NaiveDate::parse_from_str(&query.date, "%Y-%m-%d") {
        Ok(d) => d,
        Err(_) => return Html("Invalid date format.".to_string()),
    };
    let time = match NaiveTime::parse_from_str(&query.time, "%H:%M") {
        Ok(t) => t,
        Err(_) => return Html("Invalid time format.".to_string()),
    };
    let end_time = (date.and_time(time) + Duration::minutes(duration as i64))
        .time()
        .format("%H:%M")
        .to_string();
    let date_label = crate::i18n::format_long_date(date, lang);

    let (meeting_jitsi_label, meeting_webhook_label) = meeting_provider_labels(state).await;
    let tmpl = match state.templates.get_template("book.html") {
        Ok(t) => t,
        Err(e) => return internal_error_html("internal", &e),
    };
    let captcha = captcha::CaptchaVars::from_config(&*state.captcha_config.read().await);
    Html(
        tmpl.render(context! {
            meeting_jitsi_label => meeting_jitsi_label,
            meeting_webhook_label => meeting_webhook_label,
            event_type => context! {
                slug => et_slug,
                title => et_title,
                description => et_desc.as_deref().map(crate::utils::render_inline_markdown),
                duration_min => duration,
                location_type => loc_type,
                location_value => loc_value,
            },
            host_name => host_name,
            username => combined_username,
            date => query.date,
            date_label => date_label,
            time_start => query.time,
            time_end => end_time,
            guest_tz => guest_tz_name,
            error => "",
            form_name => "",
            form_email => "",
            form_notes => "",
            invite_token => "",
            max_additional_guests => max_additional_guests,
            company_link => state.company_link.read().await.clone(),
            captcha_enabled => captcha.enabled,
            captcha_api_endpoint => captcha.api_endpoint,
            captcha_widget_url => captcha.widget_url,
            lang => lang,
        })
        .unwrap_or_else(|e| internal_error_body("template render", &e)),
    )
}

async fn handle_dynamic_group_booking(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    combined_username: &str,
    slug: &str,
    form: &BookForm,
) -> Response {
    let lang = crate::i18n::detect_from_headers(headers);
    // Rate limit by IP
    let client_ip = client_ip_for_rate_limit(headers);
    if state.booking_limiter.check_limited(&client_ip).await {
        tracing::warn!(ip = %client_ip, "rate limited");
        return Html("Too many booking attempts. Please try again in a few minutes.".to_string())
            .into_response();
    }

    if let Err(e) = validate_booking_input(&form.name, &form.email, &form.notes) {
        return render_booking_action_error(state, headers, "Invalid booking details", &e);
    }

    let usernames = match parse_dynamic_group_usernames(combined_username) {
        Ok(u) => u,
        Err(e) => return Html(e).into_response(),
    };
    let dg_users = match validate_dynamic_group_users(&state.pool, &usernames).await {
        Ok(u) => u,
        Err(e) => return Html(e).into_response(),
    };

    let owner_username = &usernames[0];
    let et: Option<(String, String, String, i32, i32, i32, i32, i32, String, Option<String>, String, Option<i32>, String, i32)> = sqlx::query_as(
        "SELECT et.id, et.slug, et.title, et.duration_min, et.buffer_before, et.buffer_after, et.min_notice_min, et.requires_confirmation, et.location_type, et.location_value, u.id, et.reminder_minutes, et.visibility, et.max_additional_guests
         FROM event_types et
         JOIN accounts a ON a.id = et.account_id
         JOIN users u ON u.id = a.user_id
         WHERE u.username = ? AND et.slug = ? AND et.enabled = 1 AND u.enabled = 1",
    )
    .bind(owner_username)
    .bind(slug)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    let (
        et_id,
        _et_slug,
        et_title,
        duration,
        buffer_before,
        buffer_after,
        min_notice,
        requires_confirmation,
        loc_type,
        loc_value,
        owner_user_id,
        reminder_min,
        visibility,
        max_additional_guests,
    ) = match et {
        Some(e) => e,
        None => return Html("Event type not found.".to_string()).into_response(),
    };

    if visibility != "public" {
        return Html("Dynamic group links are only available for public event types.".to_string())
            .into_response();
    }

    let needs_approval = requires_confirmation != 0;

    // Parse additional guests
    let additional_attendees = match parse_additional_guests(
        &form.additional_guests,
        max_additional_guests,
        &form.email,
    ) {
        Ok(emails) => emails,
        Err(e) => return Html(e).into_response(),
    };

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
    let guest_timezone = guest_tz.name().to_string();
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

    let buf_start = slot_start - Duration::minutes(buffer_before as i64);
    let buf_end = slot_end + Duration::minutes(buffer_after as i64);

    // Check availability for ALL participants
    for (i, (uid, uname, _, _, _)) in dg_users.iter().enumerate() {
        let et_filter = if i == 0 { Some(et_id.as_str()) } else { None };
        let mut busy =
            fetch_busy_times_for_user(&state.pool, uid, buf_start, buf_end, host_tz, et_filter)
                .await;
        if i > 0 {
            ensure_user_avail_seeded(&state.pool, uid).await;
            busy.extend(user_avail_as_busy(&state.pool, uid, buf_start, buf_end, host_tz).await);
        }
        if has_conflict(&busy, buf_start, buf_end) {
            return Html(format!(
                "This slot is no longer available ({} has a conflict).",
                uname
            ))
            .into_response();
        }
    }

    // Check booking frequency limits. The dynamic-group flow doesn't pin a
    // single assignee on the booking, so per-member caps fall back to
    // event-type-wide here.
    if would_exceed_frequency_limit(&state.pool, &et_id, slot_start, None).await {
        return render_booking_action_error(
            state,
            headers,
            "Not available right now",
            "The host isn't accepting more bookings for this date. Please pick a different date, or check back later.",
        );
    }

    let id = uuid::Uuid::new_v4().to_string();
    let uid = format!("{}@calrs", uuid::Uuid::new_v4());
    let cancel_token = uuid::Uuid::new_v4().to_string();
    let reschedule_token = uuid::Uuid::new_v4().to_string();
    let start_at = slot_start.format("%Y-%m-%dT%H:%M:%S").to_string();
    let end_at = slot_end.format("%Y-%m-%dT%H:%M:%S").to_string();

    let initial_status = if needs_approval {
        "pending"
    } else {
        "confirmed"
    };
    let confirm_token: Option<String> = if needs_approval {
        Some(uuid::Uuid::new_v4().to_string())
    } else {
        None
    };

    let mut tx = match state.pool.begin().await {
        Ok(tx) => tx,
        Err(e) => return internal_error_response("database query", &e),
    };

    let insert_result = sqlx::query(
        "INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, notes, start_at, end_at, status, cancel_token, reschedule_token, confirm_token, language)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&et_id)
    .bind(&uid)
    .bind(&form.name)
    .bind(&form.email)
    .bind(&guest_timezone)
    .bind(&form.notes)
    .bind(&start_at)
    .bind(&end_at)
    .bind(initial_status)
    .bind(&cancel_token)
    .bind(&reschedule_token)
    .bind(&confirm_token)
    .bind(lang)
    .execute(&mut *tx)
    .await;

    match insert_result {
        Ok(_) => {}
        Err(e) => {
            let _ = tx.rollback().await;
            if e.to_string().contains("UNIQUE constraint failed") {
                return Html("This slot is no longer available.".to_string()).into_response();
            }
            return internal_error_response("database query", &e);
        }
    }

    // Combine co-participant emails with guest-provided additional attendees
    let co_participant_emails: Vec<String> = dg_users
        .iter()
        .skip(1)
        .map(|(_, _, _, email, _)| email.clone())
        .collect();
    let all_additional: Vec<String> = co_participant_emails
        .iter()
        .chain(additional_attendees.iter())
        .cloned()
        .collect();

    // Insert all additional attendees (co-participants + guest-provided)
    for attendee_email in &all_additional {
        let attendee_id = uuid::Uuid::new_v4().to_string();
        let _ =
            sqlx::query("INSERT INTO booking_attendees (id, booking_id, email) VALUES (?, ?, ?)")
                .bind(&attendee_id)
                .bind(&id)
                .bind(attendee_email)
                .execute(&mut *tx)
                .await;
    }

    if let Err(e) = tx.commit().await {
        if e.to_string().contains("UNIQUE constraint failed") {
            return Html("This slot is no longer available.".to_string()).into_response();
        }
        return internal_error_response("database query", &e);
    }

    tracing::info!(booking_id = %id, event_type = %slug, guest = %form.email, dynamic_group = %combined_username, "dynamic group booking created");

    // Build BookingDetails once. CalDAV push and email send both need it,
    // and CalDAV push must run independently of whether SMTP is configured.
    let owner_email = dg_users[0].3.clone();
    let host_name = dg_users
        .iter()
        .map(|(_, _, name, _, _)| name.as_str())
        .collect::<Vec<_>>()
        .join(" & ");

    let location_display = resolve_booking_location(
        state,
        &id,
        &et_id,
        Some(&owner_user_id),
        loc_value.as_deref(),
        &form.name,
        &form.email,
        !needs_approval,
    )
    .await;
    let details = crate::email::BookingDetails {
        event_title: et_title.clone(),
        date: form.date.clone(),
        start_time: form.time.clone(),
        end_time: guest_end_time.clone(),
        guest_name: form.name.clone(),
        guest_email: form.email.clone(),
        guest_timezone: guest_timezone.clone(),
        host_name: host_name.clone(),
        host_email: owner_email,
        uid: uid.clone(),
        notes: form.notes.clone(),
        location: location_display.clone(),
        reminder_minutes: reminder_min,
        additional_attendees: all_additional.clone(),
        guest_language: Some(lang.to_string()),
        host_timezone: host_tz.name().to_string(),
        ..Default::default()
    };

    // Push confirmed bookings to the owner's CalDAV regardless of SMTP.
    // ICS includes co-participants as ATTENDEEs.
    if !needs_approval {
        caldav_push_booking(
            &state.pool,
            &state.secret_key,
            &owner_user_id,
            &uid,
            &details,
        )
        .await;
    }

    let (cancel_notice_min, reschedule_notice_min) =
        fetch_event_type_notice_minutes(&state.pool, &et_id).await;

    // Send emails if SMTP is configured.
    if let Ok(Some(smtp_config)) =
        crate::email::load_smtp_config(&state.pool, &state.secret_key).await
    {
        let base_url = std::env::var("CALRS_BASE_URL").ok();
        let guest_cancel_url = base_url.as_ref().map(|base| {
            format!(
                "{}/booking/cancel/{}",
                base.trim_end_matches('/'),
                cancel_token
            )
        });
        let guest_reschedule_url = base_url.as_ref().map(|base| {
            format!(
                "{}/booking/reschedule/{}",
                base.trim_end_matches('/'),
                reschedule_token
            )
        });

        if needs_approval {
            let _ = crate::email::send_host_approval_request(
                &smtp_config,
                &details,
                &id,
                confirm_token.as_deref(),
                base_url.as_deref(),
            )
            .await;
            let _ = crate::email::send_guest_pending_notice_ex(
                &smtp_config,
                &details,
                guest_cancel_url.as_deref(),
                guest_reschedule_url.as_deref(),
            )
            .await;
        } else {
            let _ = crate::email::send_guest_confirmation_ex(
                &smtp_config,
                &details,
                guest_cancel_url.as_deref(),
                guest_reschedule_url.as_deref(),
                cancel_notice_min,
                reschedule_notice_min,
            )
            .await;
            let _ = crate::email::send_host_notification(&smtp_config, &details).await;
        }
    }

    let host_display = dg_users
        .iter()
        .map(|(_, _, name, _, _)| name.as_str())
        .collect::<Vec<_>>()
        .join(" & ");
    let date_label = crate::i18n::format_long_date(date, lang);

    let tmpl = match state.templates.get_template("confirmed.html") {
        Ok(t) => t,
        Err(e) => return internal_error_response("internal", &e),
    };
    Html(
        tmpl.render(context! {
            event_title => et_title,
            date_label => date_label,
            time_start => form.time,
            time_end => guest_end_time,
            host_name => host_display,
            guest_email => form.email,
            notes => form.notes,
            pending => needs_approval,
            location_type => loc_type,
            location_value => location_display,
            additional_attendees => all_additional,
            cancel_notice_min => cancel_notice_min,
            reschedule_notice_min => reschedule_notice_min,
            company_link => state.company_link.read().await.clone(),
            lang => lang,
        })
        .unwrap_or_else(|e| internal_error_body("template render", &e)),
    )
    .into_response()
}

