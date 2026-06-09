// --- Event type CRUD ---

#[derive(Deserialize)]
struct EventTypeForm {
    _csrf: Option<String>,
    title: String,
    slug: String,
    description: Option<String>,
    #[serde(default)]
    duration_min: String,
    #[serde(default)]
    slot_interval_min: String,
    #[serde(default)]
    buffer_before: String,
    #[serde(default)]
    buffer_after: String,
    #[serde(default)]
    min_notice_min: String,
    requires_confirmation: Option<String>, // checkbox: "on" or absent
    visibility: Option<String>,            // "public", "internal", or "private"
    location_type: Option<String>, // "link", "phone", "in_person", "custom", "jitsi_auto", "webhook_auto"
    location_value: Option<String>,
    // Optional per-event-type pattern override for the jitsi_auto provider.
    // NULL/empty falls back to the org-wide default pattern from auth_config.
    meeting_pattern_override: Option<String>,
    // Availability schedule
    avail_days: Option<String>,     // comma-separated: "1,2,3,4,5"
    avail_start: Option<String>,    // legacy: "09:00"
    avail_end: Option<String>,      // legacy: "17:00"
    avail_windows: Option<String>,  // "09:00-12:00,13:00-17:00"
    avail_schedule: Option<String>, // "1:09:00-17:00;2:09:00-12:00,13:00-17:00"
    // Scheduling mode (round_robin / collective)
    scheduling_mode: Option<String>,
    // Team (optional)
    team_id: Option<String>,
    // Calendar selection (comma-separated IDs)
    calendar_ids: Option<String>,
    // Reminder
    #[serde(default)]
    reminder_minutes: String,
    // Additional guests
    #[serde(default)]
    max_additional_guests: String,
    // Member priorities for round-robin (creation flow): "uid1:3,uid2:1,uid3:2"
    #[serde(default)]
    member_priorities: String,
    // Default calendar view for guests (month / week / column)
    default_calendar_view: Option<String>,
    // Booking frequency limits: "1:day,5:week,10:month"
    #[serde(default)]
    frequency_limits: String,
    // Show only the earliest available slot per day
    first_slot_only: Option<String>, // checkbox: "on" or absent
    // Watcher teams (comma-separated team IDs)
    watcher_team_ids: Option<String>,
    // Timezone in which the availability rules are interpreted. IANA name
    // (e.g. "Europe/Paris"). Optional on submit — if blank, create falls back
    // to the submitting user's timezone.
    timezone: Option<String>,
    // Minimum notice required for guest-initiated cancel. The form posts a
    // numeric value plus a unit (minutes / hours / days); the handler
    // converts to minutes and stores NULL when the value is empty.
    #[serde(default)]
    cancel_notice_value: String,
    #[serde(default)]
    cancel_notice_unit: String,
    // Minimum notice required for guest-initiated reschedule. Same shape.
    #[serde(default)]
    reschedule_notice_value: String,
    #[serde(default)]
    reschedule_notice_unit: String,
}

async fn new_event_type_form(
    State(state): State<Arc<AppState>>,
    auth_user: crate::auth::AuthUser,
    Query(query): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let user = &auth_user.user;
    let preset = query.get("preset").map(|s| s.as_str()).unwrap_or("");

    // Get teams where the user is a team admin (global admins see all teams).
    // Only team admins can create team event types — regular members see no
    // teams in the dropdown.
    let groups: Vec<(String, String)> = if user.role == "admin" {
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

    // Fetch members for each team (for client-side priority card)
    let mut groups_ctx: Vec<minijinja::Value> = Vec::new();
    for (id, name) in &groups {
        let team_members: Vec<(String, String, Option<String>, String)> = sqlx::query_as(
            "SELECT u.id, u.name, u.avatar_path, u.timezone FROM users u \
             JOIN team_members tm ON tm.user_id = u.id \
             WHERE tm.team_id = ? AND u.enabled = 1 ORDER BY u.name",
        )
        .bind(id)
        .fetch_all(&state.pool)
        .await
        .unwrap_or_default();
        let members_ctx: Vec<minijinja::Value> = team_members
            .iter()
            .map(|(uid, uname, ap, tz)| {
                context! {
                    user_id => uid,
                    name => uname,
                    has_avatar => ap.is_some(),
                    initials => compute_initials(uname),
                    timezone => tz,
                }
            })
            .collect();
        groups_ctx.push(context! { id => id, name => name, members => members_ctx });
    }

    // Get user's calendars (is_busy=1) for calendar selection
    let calendars: Vec<(String, Option<String>, String)> = sqlx::query_as(
        "SELECT c.id, c.display_name, cs.name FROM calendars c
         JOIN caldav_sources cs ON cs.id = c.source_id
         JOIN accounts a ON a.id = cs.account_id
         WHERE a.user_id = ? AND c.is_busy = 1
         ORDER BY cs.name, c.display_name",
    )
    .bind(&user.id)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    let calendars_ctx: Vec<minijinja::Value> = calendars
        .iter()
        .map(|(id, display_name, source_name)| context! {
            id => id,
            name => format!("{} ({})", display_name.as_deref().unwrap_or("Unnamed"), source_name),
        })
        .collect();

    // Pre-fill availability from user's default schedule
    ensure_user_avail_seeded(&state.pool, &user.id).await;
    let user_avail = load_user_avail_schedule(&state.pool, &user.id).await;

    let tmpl = match state.templates.get_template("event_type_form.html") {
        Ok(t) => t,
        Err(e) => return internal_error_html("template render", &e),
    };

    let (impersonating, impersonating_name, _) = impersonation_ctx(&auth_user);
    Html(
        tmpl.render(context! {
            sidebar => sidebar_context(&auth_user, "event-types"),
            impersonating => impersonating,
            impersonating_name => impersonating_name,
            editing => false,
            preset => preset,
            teams => groups_ctx,
            calendars => calendars_ctx,
            selected_calendar_ids => "",
            form_title => "",
            form_slug => "",
            form_description => "",
            form_duration => 30,
            form_slot_interval => 0,
            form_buffer_before => 0,
            form_buffer_after => 0,
            form_min_notice => 60,
            form_requires_confirmation => matches!(preset, "private"),
            form_visibility => match preset { "private" => "private", "internal" => "internal", _ => "public" },
            form_location_type => "link",
            form_location_value => "",
            form_meeting_pattern_override => "",
            form_avail_schedule => user_avail,
            form_reminder_minutes => 1440,
            form_max_additional_guests => 0,
            form_default_calendar_view => "month",
            form_first_slot_only => false,
            form_frequency_limits => "",
            form_timezone => &user.timezone,
            form_cancel_notice_value => 0,
            form_cancel_notice_unit => "minutes",
            form_reschedule_notice_value => 0,
            form_reschedule_notice_unit => "minutes",
            tz_options => common_timezones_with(&user.timezone)
                .iter()
                .map(|(iana, label)| context! { value => iana, label => label })
                .collect::<Vec<_>>(),
            error => "",
        })
        .unwrap_or_else(|e| internal_error_body("template render", &e)),
    )
}

async fn create_event_type(
    State(state): State<Arc<AppState>>,
    auth_user: crate::auth::AuthUser,
    headers: HeaderMap,
    Form(form): Form<EventTypeForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }
    let user = &auth_user.user;

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

    // Generate slug from title if empty
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
        // Collapse multiple dashes and trim
        while slug.contains("--") {
            slug = slug.replace("--", "-");
        }
        slug = slug.trim_matches('-').to_string();
    }
    if slug.is_empty() {
        return render_event_type_form_error(
            &state,
            &auth_user,
            "Title is required to generate a slug.",
            &form,
            false,
        )
        .into_response();
    }

    // Check if a team_id was provided and it's non-empty
    let team_id = form.team_id.as_deref().filter(|s| !s.trim().is_empty());

    // Check uniqueness — scope to team_id when creating a team event type, otherwise to account_id
    let existing: Option<(String,)> = if let Some(tid) = team_id {
        sqlx::query_as("SELECT id FROM event_types WHERE team_id = ? AND slug = ?")
            .bind(tid)
            .bind(&slug)
            .fetch_optional(&state.pool)
            .await
            .unwrap_or(None)
    } else {
        sqlx::query_as(
            "SELECT id FROM event_types WHERE account_id = ? AND slug = ? AND team_id IS NULL",
        )
        .bind(&account_id)
        .bind(&slug)
        .fetch_optional(&state.pool)
        .await
        .unwrap_or(None)
    };

    if existing.is_some() {
        return render_event_type_form_error(
            &state,
            &auth_user,
            "An event type with this slug already exists.",
            &form,
            false,
        )
        .into_response();
    }

    let et_id = uuid::Uuid::new_v4().to_string();
    let requires_confirmation = form.requires_confirmation.as_deref() == Some("on");

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
            false,
        )
        .into_response();
    }

    // Only team admins (or global admins) can create team event types.
    if let Some(tid) = team_id {
        let is_global_admin = user.role == "admin";
        if !is_global_admin && !is_team_admin(&state.pool, &user.id, tid).await {
            return render_event_type_form_error(
                &state,
                &auth_user,
                "You are not a team admin of this team.",
                &form,
                false,
            )
            .into_response();
        }
    }

    let visibility = match form.visibility.as_deref().unwrap_or("public") {
        v @ ("public" | "internal" | "private") => v.to_string(),
        _ => "public".to_string(),
    };

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
        "INSERT INTO event_types (id, account_id, slug, title, description, duration_min, slot_interval_min, buffer_before, buffer_after, min_notice_min, requires_confirmation, location_type, location_value, team_id, created_by_user_id, reminder_minutes, visibility, max_additional_guests, default_calendar_view, first_slot_only, timezone, cancel_notice_min, reschedule_notice_min, meeting_pattern_override)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
    .bind(team_id)
    .bind(if team_id.is_some() { Some(&user.id) } else { None })
    .bind(reminder_minutes)
    .bind(&visibility)
    .bind(parse_int_field(&form.max_additional_guests, 0))
    .bind(&default_calendar_view)
    .bind(first_slot_only as i32)
    .bind(&timezone)
    .bind(cancel_notice_min)
    .bind(reschedule_notice_min)
    .bind(&meeting_pattern_override)
    .execute(&state.pool)
    .await;

    tracing::info!(slug = %slug, user = %auth_user.user.email, "event type created");

    // Create availability rules. Pass the user's profile-default schedule as a
    // fallback so an empty submission falls back to it instead of hardcoded
    // Mon-Fri 09:00-17:00.
    ensure_user_avail_seeded(&state.pool, &auth_user.user.id).await;
    let user_default = load_user_avail_schedule(&state.pool, &auth_user.user.id).await;
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

    // Save calendar selections
    if let Some(ref cal_ids_str) = form.calendar_ids {
        for cal_id in cal_ids_str.split(',') {
            let cal_id = cal_id.trim();
            if !cal_id.is_empty() {
                let _ = sqlx::query(
                    "INSERT INTO event_type_calendars (event_type_id, calendar_id) VALUES (?, ?)",
                )
                .bind(&et_id)
                .bind(cal_id)
                .execute(&state.pool)
                .await;
            }
        }
    }

    // Save member priorities (creation flow: "uid1:3,uid2:1,uid3:2")
    // Only insert weights for users who are actually team members.
    if let Some(tid) = team_id {
        if !form.member_priorities.is_empty() {
            let valid_members: Vec<(String,)> =
                sqlx::query_as("SELECT user_id FROM team_members WHERE team_id = ?")
                    .bind(tid)
                    .fetch_all(&state.pool)
                    .await
                    .unwrap_or_default();
            let valid_set: std::collections::HashSet<&str> =
                valid_members.iter().map(|(id,)| id.as_str()).collect();

            for entry in form.member_priorities.split(',') {
                let parts: Vec<&str> = entry.split(':').collect();
                if parts.len() == 2 {
                    let uid = parts[0].trim();
                    let weight: i64 = parts[1].trim().parse().unwrap_or(1);
                    if !uid.is_empty() && valid_set.contains(uid) {
                        let _ = sqlx::query(
                            "INSERT OR REPLACE INTO event_type_member_weights (event_type_id, user_id, weight) VALUES (?, ?, ?)",
                        )
                        .bind(&et_id)
                        .bind(uid)
                        .bind(weight)
                        .execute(&state.pool)
                        .await;
                    }
                }
            }
        }
    }

    // Save booking frequency limits
    save_frequency_limits(&state.pool, &et_id, &form.frequency_limits).await;

    Redirect::to("/dashboard/event-types").into_response()
}

async fn edit_event_type_form(
    State(state): State<Arc<AppState>>,
    auth_user: crate::auth::AuthUser,
    Path(slug): Path<String>,
) -> impl IntoResponse {
    let user = &auth_user.user;

    let et: Option<(String, String, String, Option<String>, i32, i32, i32, i32, i32, String, Option<String>, Option<i32>, String, i32, String, Option<String>)> = sqlx::query_as(
        "SELECT et.id, et.slug, et.title, et.description, et.duration_min, et.buffer_before, et.buffer_after, et.min_notice_min, et.requires_confirmation, et.location_type, et.location_value, et.reminder_minutes, et.visibility, et.max_additional_guests, et.scheduling_mode, et.team_id
         FROM event_types et
         JOIN accounts a ON a.id = et.account_id
         WHERE a.user_id = ? AND et.slug = ? AND et.team_id IS NULL",
    )
    .bind(&user.id)
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
        requires_conf,
        loc_type,
        loc_value,
        reminder_min,
        visibility,
        max_additional_guests,
        scheduling_mode,
        team_id,
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

    // Collect distinct time windows (preserving order)
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
    // Legacy fields for backward compat
    let (avail_start, avail_end) = windows
        .first()
        .cloned()
        .unwrap_or_else(|| ("09:00".to_string(), "17:00".to_string()));

    // Build per-day schedule string
    let avail_schedule = build_avail_schedule(&all_rules);

    // Get user's calendars (is_busy=1) for calendar selection
    let calendars: Vec<(String, Option<String>, String)> = sqlx::query_as(
        "SELECT c.id, c.display_name, cs.name FROM calendars c
         JOIN caldav_sources cs ON cs.id = c.source_id
         JOIN accounts a ON a.id = cs.account_id
         WHERE a.user_id = ? AND c.is_busy = 1
         ORDER BY cs.name, c.display_name",
    )
    .bind(&user.id)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    let calendars_ctx: Vec<minijinja::Value> = calendars
        .iter()
        .map(|(id, display_name, source_name)| context! {
            id => id,
            name => format!("{} ({})", display_name.as_deref().unwrap_or("Unnamed"), source_name),
        })
        .collect();

    // Get currently selected calendars for this event type
    let selected_cals: Vec<(String,)> =
        sqlx::query_as("SELECT calendar_id FROM event_type_calendars WHERE event_type_id = ?")
            .bind(&et_id)
            .fetch_all(&state.pool)
            .await
            .unwrap_or_default();

    let selected_calendar_ids: String = selected_cals
        .iter()
        .map(|(id,)| id.as_str())
        .collect::<Vec<_>>()
        .join(",");

    // Fetch team members with per-ET weights (round-robin priority OR collective exclusion)
    let is_round_robin_group = team_id.is_some() && scheduling_mode == "round_robin";
    let is_collective_team = team_id.is_some() && scheduling_mode == "collective";
    let members_ctx: Vec<minijinja::Value> = if is_round_robin_group || is_collective_team {
        let tid = team_id.as_deref().unwrap();
        // Also selects timezone so admins can spot mis-configured user TZs at
        // a glance when setting up a team event (e.g. a US member whose TZ
        // is still the server default — which silently makes their personal
        // working hours land in the wrong local time).
        let members: Vec<(String, String, Option<String>, String)> = sqlx::query_as(
            "SELECT u.id, u.name, u.avatar_path, u.timezone \
             FROM users u JOIN team_members tm ON tm.user_id = u.id \
             WHERE tm.team_id = ? AND u.enabled = 1 \
             ORDER BY u.name",
        )
        .bind(tid)
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

    // Eligible users for dynamic group link picker (excluding self)
    let dg_eligible: Vec<(String, String, String, Option<String>)> = sqlx::query_as(
        "SELECT id, username, name, avatar_path FROM users WHERE enabled = 1 AND allow_dynamic_group = 1 AND id != ? AND username IS NOT NULL ORDER BY name",
    )
    .bind(&user.id)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();
    let dg_eligible_ctx: Vec<minijinja::Value> = dg_eligible
        .iter()
        .map(|(id, username, name, avatar_path)| {
            context! {
                id => id,
                username => username,
                name => name,
                has_avatar => avatar_path.is_some(),
                initials => compute_initials(name),
            }
        })
        .collect();

    Html(
        tmpl.render(context! {
            editing => true,
            original_slug => et_slug,
            calendars => calendars_ctx,
            selected_calendar_ids => selected_calendar_ids,
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
            is_group => team_id.is_some(),
            is_round_robin_group => is_round_robin_group,
            is_collective_team => is_collective_team,
            priority_members => members_ctx,
            owner_username => auth_user.user.username.as_deref().unwrap_or(""),
            dg_eligible_users => dg_eligible_ctx,
            error => "",
            sidebar => sidebar_context(&auth_user, "event-types"),
            impersonating => impersonating,
            impersonating_name => impersonating_name,
        })
        .unwrap_or_else(|e| internal_error_body("template render", &e)),
    )
}

async fn update_event_type(
    State(state): State<Arc<AppState>>,
    auth_user: crate::auth::AuthUser,
    headers: HeaderMap,
    Path(slug): Path<String>,
    Form(form): Form<EventTypeForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }
    let user = &auth_user.user;

    let et: Option<(String, String)> = sqlx::query_as(
        "SELECT et.id, et.account_id
         FROM event_types et
         JOIN accounts a ON a.id = et.account_id
         WHERE a.user_id = ? AND et.slug = ? AND et.team_id IS NULL",
    )
    .bind(&user.id)
    .bind(&slug)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    let (et_id, account_id) = match et {
        Some(e) => e,
        None => return Redirect::to("/dashboard/event-types").into_response(),
    };

    let new_slug = form.slug.trim().to_lowercase().replace(' ', "-");
    let requires_confirmation = form.requires_confirmation.as_deref() == Some("on");
    let visibility = match form.visibility.as_deref().unwrap_or("public") {
        v @ ("public" | "internal" | "private") => v.to_string(),
        _ => "public".to_string(),
    };

    // Check slug uniqueness if changed
    if new_slug != slug {
        let existing: Option<(String,)> =
            sqlx::query_as("SELECT id FROM event_types WHERE account_id = ? AND slug = ?")
                .bind(&account_id)
                .bind(&new_slug)
                .fetch_optional(&state.pool)
                .await
                .unwrap_or(None);

        if existing.is_some() {
            return render_event_type_form_error(
                &state,
                &auth_user,
                "An event type with this slug already exists.",
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

    // Update availability rules: delete old, insert new. Pass the user's
    // profile-default schedule as a fallback so an empty submission falls back
    // to it instead of hardcoded Mon-Fri 09:00-17:00.
    let _ = sqlx::query("DELETE FROM availability_rules WHERE event_type_id = ?")
        .bind(&et_id)
        .execute(&state.pool)
        .await;

    ensure_user_avail_seeded(&state.pool, &auth_user.user.id).await;
    let user_default = load_user_avail_schedule(&state.pool, &auth_user.user.id).await;
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

    // Update calendar selections: delete old, insert new
    let _ = sqlx::query("DELETE FROM event_type_calendars WHERE event_type_id = ?")
        .bind(&et_id)
        .execute(&state.pool)
        .await;

    if let Some(ref cal_ids_str) = form.calendar_ids {
        for cal_id in cal_ids_str.split(',') {
            let cal_id = cal_id.trim();
            if !cal_id.is_empty() {
                let _ = sqlx::query(
                    "INSERT INTO event_type_calendars (event_type_id, calendar_id) VALUES (?, ?)",
                )
                .bind(&et_id)
                .bind(cal_id)
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

async fn update_event_type_member_priority(
    State(state): State<Arc<AppState>>,
    auth_user: crate::auth::AuthUser,
    headers: HeaderMap,
    Path((slug, target_user_id)): Path<(String, String)>,
    Form(form): Form<PriorityForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }
    let user = &auth_user.user;

    // Resolve a personal event type owned by this user (team priority is
    // handled by the group-scoped route).
    let et: Option<(String,)> = sqlx::query_as(
        "SELECT et.id FROM event_types et \
         JOIN accounts a ON a.id = et.account_id \
         WHERE a.user_id = ? AND et.slug = ? AND et.team_id IS NULL",
    )
    .bind(&user.id)
    .bind(&slug)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    let et_id = match et {
        Some((id,)) => id,
        None => return Redirect::to("/dashboard/event-types").into_response(),
    };

    let weight: i64 = match form.priority.as_str() {
        "high" => 3,
        "medium" => 2,
        "exclude" => 0,
        _ => 1,
    };

    let _ = sqlx::query(
        "INSERT INTO event_type_member_weights (event_type_id, user_id, weight) \
         VALUES (?, ?, ?) \
         ON CONFLICT(event_type_id, user_id) DO UPDATE SET weight = excluded.weight",
    )
    .bind(&et_id)
    .bind(&target_user_id)
    .bind(weight)
    .execute(&state.pool)
    .await;

    tracing::info!(
        slug,
        target_user_id,
        priority = form.priority.as_str(),
        "updated member priority for event type"
    );

    Redirect::to(&format!("/dashboard/event-types/{}/edit", slug)).into_response()
}

async fn update_group_event_type_member_priority(
    State(state): State<Arc<AppState>>,
    auth_user: crate::auth::AuthUser,
    headers: HeaderMap,
    Path((team_id, slug, target_user_id)): Path<(String, String, String)>,
    Form(form): Form<PriorityForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }
    let user = &auth_user.user;
    let is_admin = user.role == "admin";

    // Resolve event type within the addressed team. Two teams may share the
    // same slug, so the team_id from the route is required for the lookup
    // to be unambiguous.
    let et: Option<(String,)> = if is_admin {
        sqlx::query_as(
            "SELECT et.id FROM event_types et \
             WHERE et.team_id = ? AND et.slug = ?",
        )
        .bind(&team_id)
        .bind(&slug)
        .fetch_optional(&state.pool)
        .await
        .unwrap_or(None)
    } else {
        sqlx::query_as(
            "SELECT et.id FROM event_types et \
             JOIN team_members tm ON tm.team_id = et.team_id \
             WHERE tm.user_id = ? AND tm.role = 'admin' AND et.team_id = ? AND et.slug = ?",
        )
        .bind(&user.id)
        .bind(&team_id)
        .bind(&slug)
        .fetch_optional(&state.pool)
        .await
        .unwrap_or(None)
    };

    let et_id = match et {
        Some((id,)) => id,
        None => return Redirect::to("/dashboard/event-types").into_response(),
    };

    let weight: i64 = match form.priority.as_str() {
        "high" => 3,
        "medium" => 2,
        "exclude" => 0,
        _ => 1,
    };

    let _ = sqlx::query(
        "INSERT INTO event_type_member_weights (event_type_id, user_id, weight) \
         VALUES (?, ?, ?) \
         ON CONFLICT(event_type_id, user_id) DO UPDATE SET weight = excluded.weight",
    )
    .bind(&et_id)
    .bind(&target_user_id)
    .bind(weight)
    .execute(&state.pool)
    .await;

    tracing::info!(
        slug,
        target_user_id,
        priority = form.priority.as_str(),
        "updated member priority for group event type"
    );

    Redirect::to(&format!(
        "/dashboard/group-event-types/{}/{}/edit",
        team_id, slug
    ))
    .into_response()
}

async fn toggle_event_type(
    State(state): State<Arc<AppState>>,
    auth_user: crate::auth::AuthUser,
    headers: HeaderMap,
    Path(slug): Path<String>,
    Form(csrf): Form<CsrfForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &csrf._csrf) {
        return resp;
    }
    let user = &auth_user.user;

    let _ = sqlx::query(
        "UPDATE event_types SET enabled = CASE WHEN enabled = 1 THEN 0 ELSE 1 END
         WHERE slug = ? AND team_id IS NULL AND account_id IN (SELECT id FROM accounts WHERE user_id = ?)",
    )
    .bind(&slug)
    .bind(&user.id)
    .execute(&state.pool)
    .await;

    tracing::debug!(event_type_id = %slug, "event type toggled");

    Redirect::to("/dashboard/event-types").into_response()
}

async fn delete_event_type(
    State(state): State<Arc<AppState>>,
    auth_user: crate::auth::AuthUser,
    headers: HeaderMap,
    Path(slug): Path<String>,
    Form(csrf): Form<CsrfForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &csrf._csrf) {
        return resp;
    }
    let user = &auth_user.user;

    // Find the personal event type owned by this user (team event types are
    // managed via the team-scoped routes).
    let et: Option<(String,)> = sqlx::query_as(
        "SELECT et.id FROM event_types et
         JOIN accounts a ON a.id = et.account_id
         WHERE et.slug = ? AND a.user_id = ? AND et.team_id IS NULL",
    )
    .bind(&slug)
    .bind(&user.id)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    let et_id = match et {
        Some((id,)) => id,
        None => return Redirect::to("/dashboard/event-types").into_response(),
    };

    // Check for active bookings (confirmed or pending)
    let active_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM bookings WHERE event_type_id = ? AND status IN ('confirmed', 'pending')",
    )
    .bind(&et_id)
    .fetch_one(&state.pool)
    .await
    .unwrap_or(0);

    if active_count > 0 {
        // Can't delete — has active bookings. Just redirect back.
        return Redirect::to("/dashboard/event-types").into_response();
    }

    // Delete in order: availability_rules, availability_overrides, event_type_calendars, bookings (past/cancelled), then event_type
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

    tracing::info!(event_type_id = %et_id, user = %auth_user.user.email, "event type deleted");

    Redirect::to("/dashboard/event-types").into_response()
}

#[derive(Deserialize)]
struct SourceForm {
    _csrf: Option<String>,
    provider: Option<String>,
    /// Backend protocol: "caldav" (default) or "ews".
    #[serde(default)]
    provider_type: Option<String>,
    name: String,
    url: String,
    username: String,
    password: String,
    no_test: Option<String>,
}

/// Resolve and validate the provider type from a form input. Defaults to
/// `caldav` when the field is missing (older clients) and rejects unknown
/// values rather than silently coercing.
fn parse_provider_type(raw: Option<&str>) -> Result<String, String> {
    let value = raw
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("caldav");
    match value {
        crate::providers::factory::kinds::CALDAV => Ok("caldav".to_string()),
        crate::providers::factory::kinds::EWS => Ok("ews".to_string()),
        other => Err(format!("Unknown provider type '{}'", other)),
    }
}

/// Preset list shown in the source-add form. Tuple is
/// `(id, display name, default URL, backend)`, where `backend` is `caldav`
/// or `ews`. The template uses the backend tag to keep the Backend dropdown
/// in sync with the preset choice.
fn caldav_providers() -> Vec<(&'static str, &'static str, &'static str, &'static str)> {
    vec![
        (
            "bluemind",
            "BlueMind",
            "https://mail.example.com/dav/",
            "caldav",
        ),
        (
            "nextcloud",
            "Nextcloud",
            "https://cloud.example.com/remote.php/dav",
            "caldav",
        ),
        (
            "fastmail",
            "Fastmail",
            "https://caldav.fastmail.com/dav/calendars/user/you@fastmail.com/",
            "caldav",
        ),
        ("icloud", "iCloud", "https://caldav.icloud.com/", "caldav"),
        (
            "zimbra",
            "Zimbra",
            "https://mail.example.com/dav/",
            "caldav",
        ),
        (
            "sogo",
            "SOGo",
            "https://mail.example.com/SOGo/dav/",
            "caldav",
        ),
        ("radicale", "Radicale", "https://cal.example.com/", "caldav"),
        ("google", "Google Calendar", "", "caldav"),
        (
            "exchange",
            "Microsoft Exchange (EWS)",
            "https://mail.example.com/EWS/Exchange.asmx",
            "ews",
        ),
        ("other", "Other / Generic CalDAV", "", "caldav"),
    ]
}

async fn new_source_form(
    State(state): State<Arc<AppState>>,
    auth_user: crate::auth::AuthUser,
) -> impl IntoResponse {
    let tmpl = match state.templates.get_template("source_form.html") {
        Ok(t) => t,
        Err(e) => return internal_error_html("template render", &e),
    };

    let providers: Vec<minijinja::Value> = caldav_providers()
        .iter()
        .map(|(id, name, url, backend)| context! { id => id, name => name, url => url, backend => backend })
        .collect();

    let google_configured: bool = sqlx::query_scalar::<_, Option<String>>(
        "SELECT google_oauth2_client_id FROM auth_config LIMIT 1",
    )
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None)
    .flatten()
    .map(|s| !s.is_empty())
    .unwrap_or(false);

    let (impersonating, impersonating_name, _) = impersonation_ctx(&auth_user);
    Html(
        tmpl.render(context! {
            providers => providers,
            form_provider => "bluemind",
            form_provider_type => "caldav",
            form_name => "",
            form_url => "https://mail.example.com/dav/",
            form_username => "",
            error => "",
            google_oauth2_configured => google_configured,
            sidebar => sidebar_context(&auth_user, "sources"),
            impersonating => impersonating,
            impersonating_name => impersonating_name,
        })
        .unwrap_or_else(|e| internal_error_body("template render", &e)),
    )
}

async fn create_source(
    State(state): State<Arc<AppState>>,
    auth_user: crate::auth::AuthUser,
    headers: HeaderMap,
    Form(form): Form<SourceForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }
    let user = &auth_user.user;

    let account_id: Option<String> =
        sqlx::query_scalar("SELECT id FROM accounts WHERE user_id = ? LIMIT 1")
            .bind(&user.id)
            .fetch_optional(&state.pool)
            .await
            .unwrap_or(None);

    let account_id = match account_id {
        Some(id) => id,
        None => {
            return render_source_form_error(
                &state,
                &auth_user,
                "No scheduling account found. Please contact an administrator.",
                &form,
            )
            .into_response()
        }
    };

    let url = form.url.trim().to_string();
    let username = form.username.trim().to_string();
    let name = form.name.trim().to_string();

    if url.is_empty() || username.is_empty() || name.is_empty() || form.password.is_empty() {
        return render_source_form_error(&state, &auth_user, "All fields are required.", &form)
            .into_response();
    }

    let provider_type = match parse_provider_type(form.provider_type.as_deref()) {
        Ok(p) => p,
        Err(msg) => {
            return render_source_form_error(&state, &auth_user, &msg, &form).into_response();
        }
    };

    // Validate URL against SSRF (HTTPS-only, no private targets) for both
    // CalDAV and EWS — the validator is shared.
    if let Err(e) = crate::providers::factory::validate_url(&provider_type, &url) {
        return render_source_form_error(&state, &auth_user, &e.to_string(), &form).into_response();
    }

    // Test connection unless skip requested
    let skip_test = form.no_test.as_deref() == Some("on");
    if !skip_test {
        let client =
            match crate::providers::build_provider(&provider_type, &url, &username, &form.password)
            {
                Ok(c) => c,
                Err(e) => {
                    return render_source_form_error(&state, &auth_user, &e.to_string(), &form)
                        .into_response();
                }
            };
        match client.check_connection().await {
            Ok(_) => {} // fine, even if features not explicitly advertised
            Err(e) => {
                let msg = format!("Connection failed: {}. Check the URL and credentials, or check \"Skip connection test\" to save anyway.", e);
                return render_source_form_error(&state, &auth_user, &msg, &form).into_response();
            }
        }
    }

    let id = uuid::Uuid::new_v4().to_string();
    let password_enc = match crate::crypto::encrypt_password(&state.secret_key, &form.password) {
        Ok(enc) => enc,
        Err(_) => return Html("Encryption error.".to_string()).into_response(),
    };

    let _ = sqlx::query(
        "INSERT INTO caldav_sources (id, account_id, name, url, username, password_enc, provider_type) VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&account_id)
    .bind(&name)
    .bind(&url)
    .bind(&username)
    .bind(&password_enc)
    .bind(&provider_type)
    .execute(&state.pool)
    .await;

    tracing::info!(source_name = %name, provider = %provider_type, user = %auth_user.user.email, "calendar source added");

    // Auto-sync immediately after creating the source, then redirect to
    // write-back setup if calendars were found.
    let (messages, calendar_count) = run_sync(
        &state.pool,
        &state.secret_key,
        &id,
        &provider_type,
        &url,
        &username,
        &form.password,
    )
    .await;

    if calendar_count > 0 {
        let joined_messages = messages.join("\n");
        let encoded_messages = urlencoding::encode(&joined_messages);
        return Redirect::to(&format!(
            "/dashboard/sources/{}/setup-write?sync_messages={}",
            id, encoded_messages
        ))
        .into_response();
    }

    Redirect::to("/dashboard/sources").into_response()
}

fn render_source_form_error(
    state: &AppState,
    auth_user: &crate::auth::AuthUser,
    error: &str,
    form: &SourceForm,
) -> Html<String> {
    let tmpl = match state.templates.get_template("source_form.html") {
        Ok(t) => t,
        Err(e) => return internal_error_html("template render", &e),
    };

    let providers: Vec<minijinja::Value> = caldav_providers()
        .iter()
        .map(|(id, name, url, backend)| context! { id => id, name => name, url => url, backend => backend })
        .collect();

    let (impersonating, impersonating_name, _) = impersonation_ctx(auth_user);
    Html(
        tmpl.render(context! {
            providers => providers,
            form_provider => form.provider.as_deref().unwrap_or("other"),
            form_provider_type => form.provider_type.as_deref().unwrap_or("caldav"),
            form_name => form.name.as_str(),
            form_url => form.url.as_str(),
            form_username => form.username.as_str(),
            error => error,
            sidebar => sidebar_context(auth_user, "sources"),
            impersonating => impersonating,
            impersonating_name => impersonating_name,
        })
        .unwrap_or_else(|e| internal_error_body("template render", &e)),
    )
}

/// Render the source form in editing mode with the given values.
fn render_source_edit_form(
    state: &AppState,
    auth_user: &crate::auth::AuthUser,
    source_id: &str,
    name: &str,
    url: &str,
    username: &str,
    error: &str,
) -> Html<String> {
    let tmpl = match state.templates.get_template("source_form.html") {
        Ok(t) => t,
        Err(e) => return Html(format!("Template error: {}", e)),
    };

    let providers: Vec<minijinja::Value> = caldav_providers()
        .iter()
        .map(|(id, name, url, backend)| context! { id => id, name => name, url => url, backend => backend })
        .collect();

    let (impersonating, impersonating_name, _) = impersonation_ctx(auth_user);
    Html(
        tmpl.render(context! {
            editing => true,
            source_id => source_id,
            providers => providers,
            form_provider => "other",
            form_name => name,
            form_url => url,
            form_username => username,
            error => error,
            sidebar => sidebar_context(auth_user, "sources"),
            impersonating => impersonating,
            impersonating_name => impersonating_name,
        })
        .unwrap_or_else(|e| format!("Template error: {}", e)),
    )
}

async fn edit_source_form(
    State(state): State<Arc<AppState>>,
    auth_user: crate::auth::AuthUser,
    Path(source_id): Path<String>,
) -> impl IntoResponse {
    let user = &auth_user.user;
    // Verify ownership and load current values.
    let source: Option<(String, String, String)> = sqlx::query_as(
        "SELECT cs.name, cs.url, cs.username
         FROM caldav_sources cs
         JOIN accounts a ON a.id = cs.account_id
         WHERE cs.id = ? AND a.user_id = ?",
    )
    .bind(&source_id)
    .bind(&user.id)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    let (name, url, username) = match source {
        Some(s) => s,
        None => return Redirect::to("/dashboard/sources").into_response(),
    };

    render_source_edit_form(&state, &auth_user, &source_id, &name, &url, &username, "")
        .into_response()
}

async fn update_source(
    State(state): State<Arc<AppState>>,
    auth_user: crate::auth::AuthUser,
    headers: HeaderMap,
    Path(source_id): Path<String>,
    Form(form): Form<SourceForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }
    let user = &auth_user.user;

    // Confirm the source belongs to this user and grab the existing
    // password (used as fallback when the form leaves it blank).
    let existing: Option<(String,)> = sqlx::query_as(
        "SELECT cs.password_enc
         FROM caldav_sources cs
         JOIN accounts a ON a.id = cs.account_id
         WHERE cs.id = ? AND a.user_id = ?",
    )
    .bind(&source_id)
    .bind(&user.id)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    let existing_password_enc = match existing {
        Some((enc,)) => enc,
        None => return Redirect::to("/dashboard/sources").into_response(),
    };

    let url = form.url.trim().to_string();
    let username = form.username.trim().to_string();
    let name = form.name.trim().to_string();

    if url.is_empty() || username.is_empty() || name.is_empty() {
        return render_source_edit_form(
            &state,
            &auth_user,
            &source_id,
            &form.name,
            &form.url,
            &form.username,
            "Name, URL, and username are required.",
        )
        .into_response();
    }

    if let Err(e) = crate::caldav::validate_caldav_url(&url) {
        return render_source_edit_form(
            &state,
            &auth_user,
            &source_id,
            &name,
            &url,
            &username,
            &e.to_string(),
        )
        .into_response();
    }

    // Resolve the password we'll actually use for the test + storage.
    // Empty form password means "keep existing"; we decrypt the stored
    // blob so the connection test exercises the same credentials that
    // sync will use afterwards.
    let password_changed = !form.password.is_empty();
    let plaintext_password = if password_changed {
        form.password.clone()
    } else {
        match crate::crypto::decrypt_password(&state.secret_key, &existing_password_enc) {
            Ok(p) => p,
            Err(_) => {
                return Html("Failed to decrypt stored credentials.".to_string()).into_response()
            }
        }
    };

    let skip_test = form.no_test.as_deref() == Some("on");
    if !skip_test {
        let client = crate::caldav::CaldavClient::new(&url, &username, &plaintext_password);
        if let Err(e) = client.check_connection().await {
            let msg = format!("Connection failed: {}. Check the URL and credentials, or check \"Skip connection test\" to save anyway.", e);
            return render_source_edit_form(
                &state, &auth_user, &source_id, &name, &url, &username, &msg,
            )
            .into_response();
        }
    }

    if password_changed {
        let new_enc = match crate::crypto::encrypt_password(&state.secret_key, &plaintext_password)
        {
            Ok(enc) => enc,
            Err(_) => return Html("Encryption error.".to_string()).into_response(),
        };
        let _ = sqlx::query(
            "UPDATE caldav_sources SET name = ?, url = ?, username = ?, password_enc = ? WHERE id = ?",
        )
        .bind(&name)
        .bind(&url)
        .bind(&username)
        .bind(&new_enc)
        .bind(&source_id)
        .execute(&state.pool)
        .await;
    } else {
        let _ =
            sqlx::query("UPDATE caldav_sources SET name = ?, url = ?, username = ? WHERE id = ?")
                .bind(&name)
                .bind(&url)
                .bind(&username)
                .bind(&source_id)
                .execute(&state.pool)
                .await;
    }

    tracing::info!(
        source_id = %source_id,
        source_name = %name,
        password_changed = %password_changed,
        user = %auth_user.user.email,
        "CalDAV source updated"
    );

    Redirect::to("/dashboard/sources").into_response()
}

async fn remove_source(
    State(state): State<Arc<AppState>>,
    auth_user: crate::auth::AuthUser,
    headers: HeaderMap,
    Path(source_id): Path<String>,
    Form(csrf): Form<CsrfForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &csrf._csrf) {
        return resp;
    }
    let user = &auth_user.user;

    // Verify source belongs to this user before deleting
    let _ = sqlx::query(
        "DELETE FROM caldav_sources WHERE id = ? AND account_id IN (SELECT id FROM accounts WHERE user_id = ?)",
    )
    .bind(&source_id)
    .bind(&user.id)
    .execute(&state.pool)
    .await;

    tracing::info!(source_id = %source_id, user = %auth_user.user.email, "CalDAV source removed");

    Redirect::to("/dashboard/sources").into_response()
}

async fn test_source(
    State(state): State<Arc<AppState>>,
    auth_user: crate::auth::AuthUser,
    headers: HeaderMap,
    Path(source_id): Path<String>,
    Form(csrf): Form<CsrfForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &csrf._csrf) {
        return resp;
    }
    let user = &auth_user.user;

    let source: Option<(
        String,
        String,
        Option<String>,
        String,
        String,
        Option<String>,
        Option<String>,
        String,
    )> = sqlx::query_as(
        "SELECT cs.url, cs.username, cs.password_enc, cs.name, cs.auth_type, cs.access_token_enc, cs.token_expires_at, cs.provider_type
         FROM caldav_sources cs
         JOIN accounts a ON a.id = cs.account_id
         WHERE cs.id = ? AND a.user_id = ?",
    )
    .bind(&source_id)
    .bind(&user.id)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    let (
        url,
        username,
        password_enc,
        name,
        auth_type,
        access_token_enc,
        token_expires_at,
        provider_type,
    ) = match source {
        Some(s) => s,
        None => return Html("Source not found.".to_string()).into_response(),
    };

    let label = crate::providers::factory::label(&provider_type);

    // EWS sources go through the provider trait; CalDAV (basic or OAuth2) keeps
    // the existing CaldavClient path so OAuth2 refresh + ctag stay intact.
    let result = if provider_type == crate::providers::factory::kinds::EWS {
        let password = match password_enc.as_deref() {
            Some(enc) => match crate::crypto::decrypt_password(&state.secret_key, enc) {
                Ok(p) => p,
                Err(_) => {
                    return Html("Failed to decrypt stored credentials.".to_string())
                        .into_response()
                }
            },
            None => {
                return Html("Source has no stored password.".to_string()).into_response();
            }
        };
        match crate::providers::build_provider(&provider_type, &url, &username, &password) {
            Ok(client) => match client.check_connection().await {
                Ok(true) => format!("'{}' — connection OK ({}).", name, label),
                Ok(false) => format!(
                    "'{}' — connected but {} features not explicitly advertised. Sync may still work.",
                    name, label,
                ),
                Err(e) => format!("'{}' — connection failed: {}", name, e),
            },
            Err(e) => format!("'{}' — could not build provider: {}", name, e),
        }
    } else {
        let client = match crate::oauth2_caldav::build_client_for_source(
            &state.pool,
            &state.secret_key,
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
            Err(_) => {
                return Html("Failed to decrypt stored credentials.".to_string()).into_response()
            }
        };
        match client.check_connection().await {
            Ok(true) => format!("'{}' — connection OK, CalDAV supported.", name),
            Ok(false) => format!(
                "'{}' — connected but CalDAV not explicitly detected. Sync may still work.",
                name
            ),
            Err(e) => format!("'{}' — connection failed: {}", name, e),
        }
    };

    // Return a simple page with back link
    let tmpl = match state.templates.get_template("source_test.html") {
        Ok(t) => t,
        Err(_) => {
            return Html(format!(
                "<p>{}</p><p><a href=\"/dashboard\">Back to dashboard</a></p>",
                result
            ))
            .into_response()
        }
    };
    let (impersonating, impersonating_name, _) = impersonation_ctx(&auth_user);
    Html(
        tmpl.render(context! {
            result => result,
            sidebar => sidebar_context(&auth_user, "sources"),
            impersonating => impersonating,
            impersonating_name => impersonating_name,
        })
        .unwrap_or_else(|e| internal_error_body("template render", &e)),
    )
    .into_response()
}

/// Runs CalDAV sync using build_client_for_source (supports both basic and OAuth2).
async fn run_sync_for_source(
    pool: &SqlitePool,
    key: &[u8; 32],
    source_id: &str,
    url: &str,
    username: &str,
    password_enc: Option<&str>,
    auth_type: &str,
    access_token_enc: Option<&str>,
    token_expires_at: Option<&str>,
    provider_type: &str,
) -> (Vec<String>, usize) {
    // EWS sources go through the provider trait — no OAuth2 dispatch needed.
    if provider_type == crate::providers::factory::kinds::EWS {
        let enc = match password_enc {
            Some(e) => e,
            None => return (vec!["EWS source missing password".to_string()], 0),
        };
        let password = match crate::crypto::decrypt_password(key, enc) {
            Ok(p) => p,
            Err(e) => return (vec![format!("Decrypt failed: {}", e)], 0),
        };
        return run_sync(
            pool,
            key,
            source_id,
            provider_type,
            url,
            username,
            &password,
        )
        .await;
    }
    let client = match crate::oauth2_caldav::build_client_for_source(
        pool,
        key,
        source_id,
        url,
        auth_type,
        username,
        password_enc,
        access_token_enc,
        token_expires_at,
    )
    .await
    {
        Ok(c) => c,
        Err(e) => return (vec![format!("Failed to build client: {}", e)], 0),
    };

    match crate::commands::sync::sync_source(pool, key, &client, source_id).await {
        Ok(()) => {
            let cal_count: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM calendars WHERE source_id = ?")
                    .bind(source_id)
                    .fetch_one(pool)
                    .await
                    .unwrap_or(0);
            (vec!["Sync complete.".to_string()], cal_count as usize)
        }
        Err(e) => (vec![format!("Sync failed: {}", e)], 0),
    }
}

/// Run discovery + sync for a freshly-created source with plaintext password.
/// Dispatches on `provider_type`: EWS goes through the trait-based path,
/// CalDAV reuses the existing `CaldavClient` + `sync_source` flow.
async fn run_sync(
    pool: &SqlitePool,
    key: &[u8; 32],
    source_id: &str,
    provider_type: &str,
    url: &str,
    username: &str,
    password: &str,
) -> (Vec<String>, usize) {
    if provider_type == crate::providers::factory::kinds::EWS {
        let provider =
            match crate::providers::build_provider(provider_type, url, username, password) {
                Ok(p) => p,
                Err(e) => return (vec![format!("Could not build provider: {}", e)], 0),
            };
        match crate::commands::sync::sync_ews_source(pool, key, provider.as_ref(), source_id).await
        {
            Ok(()) => {
                let cal_count: i64 =
                    sqlx::query_scalar("SELECT COUNT(*) FROM calendars WHERE source_id = ?")
                        .bind(source_id)
                        .fetch_one(pool)
                        .await
                        .unwrap_or(0);
                (vec!["Sync complete.".to_string()], cal_count as usize)
            }
            Err(e) => (vec![format!("Sync failed: {}", e)], 0),
        }
    } else {
        let client = crate::caldav::CaldavClient::new(url, username, password);
        match crate::commands::sync::sync_source(pool, key, &client, source_id).await {
            Ok(()) => {
                let cal_count: i64 =
                    sqlx::query_scalar("SELECT COUNT(*) FROM calendars WHERE source_id = ?")
                        .bind(source_id)
                        .fetch_one(pool)
                        .await
                        .unwrap_or(0);
                (vec!["Sync complete.".to_string()], cal_count as usize)
            }
            Err(e) => (vec![format!("Sync failed: {}", e)], 0),
        }
    }
}

async fn force_sync_source(
    State(state): State<Arc<AppState>>,
    auth_user: crate::auth::AuthUser,
    headers: HeaderMap,
    Path(source_id): Path<String>,
    Form(csrf): Form<CsrfForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &csrf._csrf) {
        return resp;
    }
    let user = &auth_user.user;

    // Verify ownership
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
         FROM caldav_sources cs JOIN accounts a ON a.id = cs.account_id
         WHERE cs.id = ? AND a.user_id = ?",
    )
    .bind(&source_id)
    .bind(&user.id)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    let (
        sid,
        url,
        username,
        password_enc,
        auth_type,
        access_token_enc,
        token_expires_at,
        provider_type,
    ) = match source {
        Some(s) => s,
        None => return Html("Source not found.".to_string()).into_response(),
    };

    // Clear sync tokens to force a full fetch (same as `calrs sync --full`)
    let _ = sqlx::query("UPDATE calendars SET sync_token = NULL, ctag = NULL WHERE source_id = ?")
        .bind(&sid)
        .execute(&state.pool)
        .await;

    tracing::info!(source_id = %sid, "force full resync triggered from dashboard");

    let name: String = sqlx::query_scalar("SELECT name FROM caldav_sources WHERE id = ?")
        .bind(&sid)
        .fetch_one(&state.pool)
        .await
        .unwrap_or_else(|_| "Source".to_string());

    let (messages, _) = run_sync_for_source(
        &state.pool,
        &state.secret_key,
        &sid,
        &url,
        &username,
        password_enc.as_deref(),
        &auth_type,
        access_token_enc.as_deref(),
        token_expires_at.as_deref(),
        &provider_type,
    )
    .await;

    render_sync_result(&state, &auth_user, &name, &messages).into_response()
}

async fn sync_source(
    State(state): State<Arc<AppState>>,
    auth_user: crate::auth::AuthUser,
    headers: HeaderMap,
    Path(source_id): Path<String>,
    Form(csrf): Form<CsrfForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &csrf._csrf) {
        return resp;
    }
    let user = &auth_user.user;

    let source: Option<(
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
        "SELECT cs.id, cs.url, cs.username, cs.password_enc, cs.name, cs.auth_type, cs.access_token_enc, cs.token_expires_at, cs.provider_type
         FROM caldav_sources cs
         JOIN accounts a ON a.id = cs.account_id
         WHERE cs.id = ? AND a.user_id = ?",
    )
    .bind(&source_id)
    .bind(&user.id)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    let (
        sid,
        url,
        username,
        password_enc,
        name,
        auth_type,
        access_token_enc,
        token_expires_at,
        provider_type,
    ) = match source {
        Some(s) => s,
        None => return Html("Source not found.".to_string()).into_response(),
    };

    tracing::info!(source_id = %sid, "calendar sync triggered from dashboard");

    let (messages, calendar_count) = run_sync_for_source(
        &state.pool,
        &state.secret_key,
        &sid,
        &url,
        &username,
        password_enc.as_deref(),
        &auth_type,
        access_token_enc.as_deref(),
        token_expires_at.as_deref(),
        &provider_type,
    )
    .await;

    // If write_calendar_href is not yet configured and we found calendars,
    // redirect to the write-calendar setup page (onboarding flow).
    let write_href: Option<String> =
        sqlx::query_scalar("SELECT write_calendar_href FROM caldav_sources WHERE id = ?")
            .bind(&sid)
            .fetch_optional(&state.pool)
            .await
            .unwrap_or(None)
            .flatten();

    if write_href.is_none() && calendar_count > 0 {
        let joined_messages = messages.join("\n");
        let encoded_messages = urlencoding::encode(&joined_messages);
        return Redirect::to(&format!(
            "/dashboard/sources/{}/setup-write?sync_messages={}",
            sid, encoded_messages
        ))
        .into_response();
    }

    render_sync_result(&state, &auth_user, &name, &messages).into_response()
}

fn render_sync_result(
    state: &AppState,
    auth_user: &crate::auth::AuthUser,
    source_name: &str,
    messages: &[String],
) -> Html<String> {
    let tmpl = match state.templates.get_template("source_test.html") {
        Ok(t) => t,
        Err(_) => {
            return Html(format!(
                "<p>{}</p><p><a href=\"/dashboard\">Back to dashboard</a></p>",
                messages.join("<br>")
            ))
        }
    };
    let (impersonating, impersonating_name, _) = impersonation_ctx(auth_user);
    Html(
        tmpl.render(context! {
            result => messages.join("\n"),
            source_name => source_name,
            sidebar => sidebar_context(auth_user, "sources"),
            impersonating => impersonating,
            impersonating_name => impersonating_name,
        })
        .unwrap_or_else(|e| internal_error_body("template render", &e)),
    )
}

#[derive(Deserialize)]
struct SetupWriteQuery {
    sync_messages: Option<String>,
}

async fn setup_write_calendar(
    State(state): State<Arc<AppState>>,
    auth_user: crate::auth::AuthUser,
    Path(source_id): Path<String>,
    Query(query): Query<SetupWriteQuery>,
) -> impl IntoResponse {
    let user = &auth_user.user;

    // Fetch source name and verify ownership
    let source: Option<(String, String)> = sqlx::query_as(
        "SELECT cs.id, cs.name FROM caldav_sources cs
         JOIN accounts a ON a.id = cs.account_id
         WHERE cs.id = ? AND a.user_id = ?",
    )
    .bind(&source_id)
    .bind(&user.id)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    let (_sid, source_name) = match source {
        Some(s) => s,
        None => return Redirect::to("/dashboard/sources").into_response(),
    };

    // Get calendars for this source, sorted by event count (most events first)
    let calendars: Vec<(String, Option<String>, Option<String>, i64)> = sqlx::query_as(
        "SELECT c.href, c.display_name, c.color,
                (SELECT COUNT(*) FROM events e WHERE e.calendar_id = c.id) as event_count
         FROM calendars c WHERE c.source_id = ?
         ORDER BY event_count DESC, c.display_name",
    )
    .bind(&source_id)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    if calendars.is_empty() {
        return Redirect::to("/dashboard/sources").into_response();
    }

    let cal_values: Vec<minijinja::Value> = calendars
        .iter()
        .map(|(href, name, color, event_count)| {
            context! {
                href => href,
                name => name.as_deref().unwrap_or(href),
                color => color,
                event_count => event_count,
            }
        })
        .collect();

    let tmpl = match state.templates.get_template("source_write_setup.html") {
        Ok(t) => t,
        Err(e) => return internal_error_response("template render", &e),
    };

    Html(
        tmpl.render(context! {
            source_id => source_id,
            source_name => source_name,
            calendars => cal_values,
            sync_messages => query.sync_messages,
        })
        .unwrap_or_else(|e| internal_error_body("template render", &e)),
    )
    .into_response()
}

#[derive(Deserialize)]
struct WriteCalendarForm {
    _csrf: Option<String>,
    calendar_href: String,
}

async fn set_write_calendar(
    State(state): State<Arc<AppState>>,
    auth_user: crate::auth::AuthUser,
    headers: HeaderMap,
    Path(source_id): Path<String>,
    Form(form): Form<WriteCalendarForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }
    let user = &auth_user.user;

    // Verify source belongs to this user
    let owned: Option<(String,)> = sqlx::query_as(
        "SELECT cs.id FROM caldav_sources cs
         JOIN accounts a ON a.id = cs.account_id
         WHERE cs.id = ? AND a.user_id = ?",
    )
    .bind(&source_id)
    .bind(&user.id)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    if owned.is_none() {
        return Redirect::to("/dashboard/sources").into_response();
    }

    let href = if form.calendar_href.is_empty() {
        None
    } else {
        Some(form.calendar_href)
    };

    let _ = sqlx::query("UPDATE caldav_sources SET write_calendar_href = ? WHERE id = ?")
        .bind(&href)
        .bind(&source_id)
        .execute(&state.pool)
        .await;

    tracing::info!(source_id = %source_id, "write calendar configured");

    Redirect::to("/dashboard/sources").into_response()
}

fn render_event_type_form_error(
    state: &AppState,
    auth_user: &crate::auth::AuthUser,
    error: &str,
    form: &EventTypeForm,
    editing: bool,
) -> Html<String> {
    let tmpl = match state.templates.get_template("event_type_form.html") {
        Ok(t) => t,
        Err(e) => return internal_error_html("template render", &e),
    };

    let (impersonating, impersonating_name, _) = impersonation_ctx(auth_user);
    Html(
        tmpl.render(context! {
            editing => editing,
            form_title => form.title.as_str(),
            form_slug => form.slug.as_str(),
            form_description => form.description.as_deref().unwrap_or(""),
            form_duration => parse_int_field(&form.duration_min, 30),
            form_slot_interval => parse_optional_positive_int(&form.slot_interval_min).unwrap_or(0),
            form_buffer_before => parse_int_field(&form.buffer_before, 0),
            form_buffer_after => parse_int_field(&form.buffer_after, 0),
            form_min_notice => parse_int_field(&form.min_notice_min, 60),
            form_requires_confirmation => form.requires_confirmation.as_deref() == Some("on"),
            form_visibility => form.visibility.as_deref().unwrap_or("public"),
            form_location_type => form.location_type.as_deref().unwrap_or("link"),
            form_location_value => form.location_value.as_deref().unwrap_or(""),
            form_meeting_pattern_override => form.meeting_pattern_override.as_deref().unwrap_or(""),
            form_avail_days => form.avail_days.as_deref().unwrap_or("1,2,3,4,5"),
            form_avail_start => form.avail_start.as_deref().unwrap_or("09:00"),
            form_avail_end => form.avail_end.as_deref().unwrap_or("17:00"),
            form_avail_windows => form.avail_windows.as_deref().unwrap_or(""),
            form_avail_schedule => form.avail_schedule.as_deref().unwrap_or(""),
            form_default_calendar_view => form.default_calendar_view.as_deref().unwrap_or("month"),
            form_first_slot_only => form.first_slot_only.as_deref() == Some("on"),
            form_frequency_limits => form.frequency_limits.as_str(),
            form_timezone => form.timezone.as_deref().unwrap_or(&auth_user.user.timezone),
            form_cancel_notice_value => parse_int_field(&form.cancel_notice_value, 0),
            form_cancel_notice_unit => match form.cancel_notice_unit.as_str() {
                "hours" => "hours",
                "days" => "days",
                _ => "minutes",
            },
            form_reschedule_notice_value => parse_int_field(&form.reschedule_notice_value, 0),
            form_reschedule_notice_unit => match form.reschedule_notice_unit.as_str() {
                "hours" => "hours",
                "days" => "days",
                _ => "minutes",
            },
            tz_options => common_timezones_with(form.timezone.as_deref().unwrap_or(&auth_user.user.timezone))
                .iter()
                .map(|(iana, label)| context! { value => iana, label => label })
                .collect::<Vec<_>>(),
            error => error,
            sidebar => sidebar_context(auth_user, "event-types"),
            impersonating => impersonating,
            impersonating_name => impersonating_name,
        })
        .unwrap_or_else(|e| internal_error_body("template render", &e)),
    )
}

// --- Invite management handlers ---

const MAX_BULK_INVITES: usize = 100;

#[derive(Deserialize)]
struct BulkInviteForm {
    _csrf: Option<String>,
    recipients: String,
    message: Option<String>,
    expires_days: Option<i32>,
    single_use: Option<String>, // checkbox: "on" or absent
}

#[derive(Default)]
struct BulkInviteResult {
    sent: Vec<String>,
    invalid: Vec<String>,
    duplicates: Vec<String>,
    failed: Vec<String>,
    over_limit: bool,
}

fn parse_bulk_recipients(input: &str, max: usize) -> (Vec<(String, String)>, BulkInviteResult) {
    let mut valid: Vec<(String, String)> = Vec::new();
    let mut result = BulkInviteResult::default();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    for raw in input.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if valid.len() + result.invalid.len() + result.duplicates.len() >= max {
            result.over_limit = true;
            break;
        }
        if !is_plausible_email(line) {
            result.invalid.push(line.to_string());
            continue;
        }
        let key = line.to_ascii_lowercase();
        if !seen.insert(key) {
            result.duplicates.push(line.to_string());
            continue;
        }
        let name = derive_name_from_email(line);
        valid.push((line.to_string(), name));
    }
    (valid, result)
}

fn is_plausible_email(s: &str) -> bool {
    if s.chars().any(char::is_whitespace) {
        return false;
    }
    if s.len() > 254 {
        return false;
    }
    let mut parts = s.splitn(2, '@');
    let local = parts.next().unwrap_or("");
    let domain = parts.next().unwrap_or("");
    !local.is_empty() && domain.contains('.') && domain.len() >= 3 && !domain.starts_with('.')
}

fn derive_name_from_email(email: &str) -> String {
    let local = email.split('@').next().unwrap_or(email);
    let parts: Vec<String> = local
        .split(['.', '_', '-', '+'])
        .filter(|s| !s.is_empty())
        .map(|s| {
            let mut chars = s.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect();
    if parts.is_empty() {
        local.to_string()
    } else {
        parts.join(" ")
    }
}

fn bulk_result_context(result: &BulkInviteResult) -> minijinja::Value {
    context! {
        sent_count => result.sent.len(),
        invalid => &result.invalid,
        duplicates => &result.duplicates,
        failed => &result.failed,
        over_limit => result.over_limit,
        max_recipients => MAX_BULK_INVITES,
        has_issues => !result.invalid.is_empty() || !result.duplicates.is_empty() || !result.failed.is_empty() || result.over_limit,
    }
}

async fn render_invite_management(
    state: &Arc<AppState>,
    auth_user: &crate::auth::AuthUser,
    event_type_id: &str,
    bulk_result: Option<&BulkInviteResult>,
) -> Response {
    let et: Option<(
        String,
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        String,
    )> = sqlx::query_as(
        "SELECT et.id, et.title, et.slug,
                CASE WHEN et.team_id IS NOT NULL THEN t.slug ELSE NULL END,
                CASE WHEN et.team_id IS NULL THEN u.username ELSE NULL END,
                CASE WHEN et.team_id IS NOT NULL THEN t.name ELSE u.name END,
                et.visibility
         FROM event_types et
         LEFT JOIN teams t ON t.id = et.team_id
         LEFT JOIN accounts a ON a.id = et.account_id
         LEFT JOIN users u ON u.id = a.user_id
         WHERE et.id = ? AND et.visibility IN ('private', 'internal')",
    )
    .bind(event_type_id)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    let (et_id, et_title, et_slug, team_slug, username, owner_name, visibility) = match et {
        Some(e) => e,
        None => return Html("Private event type not found.".to_string()).into_response(),
    };

    // Internal event types: any authenticated user can issue invites — that's
    // the documented "any authenticated colleague can distribute" contract.
    // Private event types: invite issuance is management (admin / owner /
    // team admin only).
    if visibility == "private" && !can_manage_event_type(&state.pool, &auth_user.user, &et_id).await
    {
        return Html("Access denied.".to_string()).into_response();
    }

    let invites: Vec<(String, String, String, String, Option<String>, Option<String>, i32, i32, String, String)> = sqlx::query_as(
        "SELECT bi.id, bi.token, bi.guest_name, bi.guest_email, bi.message, bi.expires_at, bi.max_uses, bi.used_count, bi.created_at, u.name
         FROM booking_invites bi
         JOIN users u ON u.id = bi.created_by_user_id
         WHERE bi.event_type_id = ?
         ORDER BY bi.created_at DESC",
    )
    .bind(&et_id)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    let base_url = std::env::var("CALRS_BASE_URL").unwrap_or_default();
    let invites_ctx: Vec<minijinja::Value> = invites
        .iter()
        .map(
            |(
                id,
                token,
                guest_name,
                guest_email,
                message,
                expires_at,
                max_uses,
                used_count,
                created_at,
                created_by,
            )| {
                let is_expired = expires_at.as_ref().is_some_and(|exp| {
                    exp < &chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string()
                });
                let is_used = *used_count >= *max_uses;
                let invite_url = if let Some(ts) = &team_slug {
                    format!("{}/team/{}/{}?invite={}", base_url, ts, et_slug, token)
                } else if let Some(un) = &username {
                    format!("{}/u/{}/{}?invite={}", base_url, un, et_slug, token)
                } else {
                    format!("{}?invite={}", base_url, token)
                };
                context! {
                    id => id,
                    guest_name => guest_name,
                    guest_email => guest_email,
                    message => message,
                    expires_at => expires_at,
                    max_uses => max_uses,
                    used_count => used_count,
                    created_at => created_at,
                    created_by => created_by,
                    is_expired => is_expired,
                    is_used => is_used,
                    invite_url => invite_url,
                }
            },
        )
        .collect();

    // Internal events let any authenticated user *create* invites, but only
    // admins/owners can *delete* them. Pass `can_delete_invites` to the
    // template so it can hide the Delete button for users who'd just hit a
    // 403 — keeps the UI consistent with the SQL gate in `delete_invite`.
    let can_delete_invites = can_manage_event_type(&state.pool, &auth_user.user, &et_id).await;

    let tmpl = match state.templates.get_template("invite_form.html") {
        Ok(t) => t,
        Err(e) => return internal_error_response("template render", &e),
    };

    let bulk_ctx = bulk_result.map(bulk_result_context);
    let (impersonating, impersonating_name, _) = impersonation_ctx(auth_user);
    Html(
        tmpl.render(context! {
            sidebar => sidebar_context(auth_user, "event-types"),
            impersonating => impersonating,
            impersonating_name => impersonating_name,
            event_type_id => et_id,
            event_type_title => et_title,
            event_type_slug => et_slug,
            team_slug => team_slug,
            username => username,
            owner_name => owner_name,
            invites => invites_ctx,
            bulk_result => bulk_ctx,
            can_delete_invites => can_delete_invites,
            success => "",
            error => "",
        })
        .unwrap_or_else(|e| internal_error_body("template render", &e)),
    )
    .into_response()
}

async fn invite_management_page(
    State(state): State<Arc<AppState>>,
    auth_user: crate::auth::AuthUser,
    Path(event_type_id): Path<String>,
) -> impl IntoResponse {
    render_invite_management(&state, &auth_user, &event_type_id, None).await
}

async fn send_invite_bulk(
    State(state): State<Arc<AppState>>,
    auth_user: crate::auth::AuthUser,
    headers: HeaderMap,
    Path(event_type_id): Path<String>,
    Form(form): Form<BulkInviteForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }

    let et: Option<(String, String, Option<String>, Option<String>, String)> = sqlx::query_as(
        "SELECT et.id, et.title,
                CASE WHEN et.team_id IS NOT NULL THEN t.slug ELSE NULL END,
                CASE WHEN et.team_id IS NULL THEN u.username ELSE NULL END,
                et.visibility
         FROM event_types et
         LEFT JOIN teams t ON t.id = et.team_id
         LEFT JOIN accounts a ON a.id = et.account_id
         LEFT JOIN users u ON u.id = a.user_id
         WHERE et.id = ? AND et.visibility IN ('private', 'internal')",
    )
    .bind(&event_type_id)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    let (et_id, et_title, team_slug, username, visibility) = match et {
        Some(e) => e,
        None => return Redirect::to("/dashboard/event-types").into_response(),
    };

    // Private event types: invite issuance is management (admin / owner / team
    // admin only). Internal event types: any authenticated user can issue
    // invites, matching the quick-link contract.
    if visibility == "private" && !can_manage_event_type(&state.pool, &auth_user.user, &et_id).await
    {
        return Redirect::to("/dashboard/event-types").into_response();
    }

    let (valid_recipients, mut result) = parse_bulk_recipients(&form.recipients, MAX_BULK_INVITES);

    let single_use = form.single_use.as_deref() != Some("on");
    let max_uses = if single_use { 1 } else { 999 };
    let expires_at = form.expires_days.filter(|&d| d > 0).map(|days| {
        (chrono::Utc::now() + chrono::Duration::days(days as i64))
            .format("%Y-%m-%d %H:%M:%S")
            .to_string()
    });
    let message_opt = form
        .message
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    let base_url = std::env::var("CALRS_BASE_URL").unwrap_or_default();
    let et_slug: Option<String> = if !valid_recipients.is_empty() {
        sqlx::query_scalar("SELECT slug FROM event_types WHERE id = ?")
            .bind(&et_id)
            .fetch_optional(&state.pool)
            .await
            .unwrap_or(None)
    } else {
        None
    };
    let smtp_config = if !base_url.is_empty() && et_slug.is_some() && !valid_recipients.is_empty() {
        crate::email::load_smtp_config(&state.pool, &state.secret_key)
            .await
            .ok()
            .flatten()
    } else {
        None
    };

    for (email, name) in valid_recipients {
        let token = uuid::Uuid::new_v4().to_string();
        let row_id = uuid::Uuid::new_v4().to_string();
        let insert_res = sqlx::query(
            "INSERT INTO booking_invites (id, event_type_id, token, guest_name, guest_email, message, expires_at, max_uses, created_by_user_id)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&row_id)
        .bind(&et_id)
        .bind(&token)
        .bind(&name)
        .bind(&email)
        .bind(message_opt)
        .bind(&expires_at)
        .bind(max_uses)
        .bind(&auth_user.user.id)
        .execute(&state.pool)
        .await;

        if insert_res.is_err() {
            tracing::warn!(email = %email, "bulk invite DB insert failed");
            result.failed.push(email);
            continue;
        }

        if let (Some(slug), Some(cfg)) = (et_slug.as_ref(), smtp_config.as_ref()) {
            let invite_url = if let Some(ts) = &team_slug {
                format!("{}/team/{}/{}?invite={}", base_url, ts, slug, token)
            } else if let Some(un) = &username {
                format!("{}/u/{}/{}?invite={}", base_url, un, slug, token)
            } else {
                String::new()
            };

            if !invite_url.is_empty() {
                let send_res = crate::email::send_invite_email(
                    cfg,
                    &name,
                    &email,
                    &et_title,
                    &auth_user.user.name,
                    message_opt,
                    &invite_url,
                    expires_at.as_deref(),
                )
                .await;
                if send_res.is_err() {
                    tracing::warn!(email = %email, "bulk invite SMTP send failed");
                    result.failed.push(email);
                    continue;
                }
            }
        }

        result.sent.push(email);
    }

    tracing::info!(
        event_type = %et_id,
        sent = result.sent.len(),
        invalid = result.invalid.len(),
        duplicates = result.duplicates.len(),
        failed = result.failed.len(),
        over_limit = result.over_limit,
        invited_by = %auth_user.user.email,
        "bulk invites processed",
    );

    render_invite_management(&state, &auth_user, &event_type_id, Some(&result)).await
}

#[derive(Deserialize)]
struct DeleteInviteForm {
    _csrf: Option<String>,
}

async fn delete_invite(
    State(state): State<Arc<AppState>>,
    auth_user: crate::auth::AuthUser,
    headers: HeaderMap,
    Path(invite_id): Path<String>,
    Form(form): Form<DeleteInviteForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }

    // Allow delete for: global admin, personal event type creator, the user who
    // created this specific invite, or a team admin of the team that owns the
    // event type.
    let is_global_admin = auth_user.user.role == "admin";
    let et_id: Option<String> = if is_global_admin {
        sqlx::query_scalar("SELECT event_type_id FROM booking_invites WHERE id = ?")
            .bind(&invite_id)
            .fetch_optional(&state.pool)
            .await
            .unwrap_or(None)
    } else {
        sqlx::query_scalar(
            "SELECT bi.event_type_id FROM booking_invites bi
             JOIN event_types et ON et.id = bi.event_type_id
             LEFT JOIN accounts a ON a.id = et.account_id
             LEFT JOIN team_members tm ON tm.team_id = et.team_id AND tm.user_id = ? AND tm.role = 'admin'
             WHERE bi.id = ? AND (
                 (et.team_id IS NULL AND a.user_id = ?) OR
                 (et.team_id IS NOT NULL AND tm.user_id IS NOT NULL)
             )",
        )
        .bind(&auth_user.user.id)
        .bind(&invite_id)
        .bind(&auth_user.user.id)
        .fetch_optional(&state.pool)
        .await
        .unwrap_or(None)
    };

    if et_id.is_some() {
        let _ = sqlx::query("DELETE FROM booking_invites WHERE id = ?")
            .bind(&invite_id)
            .execute(&state.pool)
            .await;
    }

    tracing::info!(invite_id = %invite_id, deleted_by = %auth_user.user.email, "invite deleted");

    match et_id {
        Some(id) => Redirect::to(&format!("/dashboard/invites/{}", id)).into_response(),
        None => Redirect::to("/dashboard/event-types").into_response(),
    }
}

// --- Quick invite link (for internal event types) ---

async fn generate_quick_link(
    State(state): State<Arc<AppState>>,
    auth_user: crate::auth::AuthUser,
    headers: HeaderMap,
    Path(event_type_id): Path<String>,
    Form(form): Form<CsrfForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }

    let et: Option<(String, String, Option<String>, Option<String>, String)> = sqlx::query_as(
        "SELECT et.id, et.slug,
                CASE WHEN et.team_id IS NOT NULL THEN t.slug ELSE NULL END,
                CASE WHEN et.team_id IS NULL THEN u.username ELSE NULL END,
                et.visibility
         FROM event_types et
         LEFT JOIN teams t ON t.id = et.team_id
         LEFT JOIN accounts a ON a.id = et.account_id
         LEFT JOIN users u ON u.id = a.user_id
         WHERE et.id = ? AND et.visibility IN ('private', 'internal')",
    )
    .bind(&event_type_id)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    let (et_id, et_slug, team_slug, username, visibility) = match et {
        Some(e) => e,
        None => return Redirect::to("/dashboard/invite-links").into_response(),
    };

    // Private event types: only owner (personal) or team admin (team event)
    // can generate quick links. Internal event types remain open to any
    // authenticated user — that's the documented "any authenticated colleague
    // can distribute a one-time link" contract.
    if visibility == "private" && !can_manage_event_type(&state.pool, &auth_user.user, &et_id).await
    {
        return Redirect::to("/dashboard/invite-links").into_response();
    }

    let token = uuid::Uuid::new_v4().to_string();
    let expires_at = (chrono::Utc::now() + chrono::Duration::days(7))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();

    let _ = sqlx::query(
        "INSERT INTO booking_invites (id, event_type_id, token, guest_name, guest_email, expires_at, max_uses, created_by_user_id)
         VALUES (?, ?, ?, '', '', ?, 1, ?)",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(&et_id)
    .bind(&token)
    .bind(&expires_at)
    .bind(&auth_user.user.id)
    .execute(&state.pool)
    .await;

    tracing::info!(event_type = %et_id, created_by = %auth_user.user.email, "quick invite link generated");

    let base_url = std::env::var("CALRS_BASE_URL").unwrap_or_default();
    let invite_url = if let Some(ts) = &team_slug {
        format!("{}/team/{}/{}?invite={}", base_url, ts, et_slug, token)
    } else if let Some(un) = &username {
        format!("{}/u/{}/{}?invite={}", base_url, un, et_slug, token)
    } else {
        format!("{}?invite={}", base_url, token)
    };

    // Return JSON with the URL for the frontend to copy
    axum::Json(serde_json::json!({ "url": invite_url })).into_response()
}

// --- Availability overrides ---

async fn overrides_page(
    State(state): State<Arc<AppState>>,
    auth_user: crate::auth::AuthUser,
    Path(slug): Path<String>,
) -> impl IntoResponse {
    let user = &auth_user.user;
    let is_global_admin = user.role == "admin";

    let et: Option<(String, String, Option<String>)> = if is_global_admin {
        sqlx::query_as(
            "SELECT et.id, et.title, et.team_id FROM event_types et WHERE et.slug = ? LIMIT 1",
        )
        .bind(&slug)
        .fetch_optional(&state.pool)
        .await
        .unwrap_or(None)
    } else {
        find_manageable_event_type_by_slug(&state.pool, &user.id, &slug).await
    };

    let (et_id, et_title, team_id) = match et {
        Some(e) => e,
        None => return Redirect::to("/dashboard/event-types").into_response(),
    };
    let is_team = team_id.is_some();

    let overrides: Vec<(String, String, Option<String>, Option<String>, i32)> = sqlx::query_as(
        "SELECT id, date, start_time, end_time, is_blocked FROM availability_overrides WHERE event_type_id = ? ORDER BY date, start_time",
    )
    .bind(&et_id)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    // Dashboard handler: stays English until the dashboard surface is translated.
    let overrides_ctx: Vec<minijinja::Value> = overrides
        .iter()
        .map(|(id, date, start_time, end_time, is_blocked)| {
            let date_label = NaiveDate::parse_from_str(date, "%Y-%m-%d")
                .map(|d| crate::i18n::format_long_date(d, "en"))
                .unwrap_or_else(|_| date.clone());
            context! {
                id => id,
                date => date,
                date_label => date_label,
                start_time => start_time,
                end_time => end_time,
                is_blocked => *is_blocked != 0,
            }
        })
        .collect();

    let tmpl = match state.templates.get_template("overrides.html") {
        Ok(t) => t,
        Err(e) => return internal_error_response("template render", &e),
    };

    let (impersonating, impersonating_name, _) = impersonation_ctx(&auth_user);

    Html(
        tmpl.render(context! {
            sidebar => sidebar_context(&auth_user, "event-types"),
            event_type_title => et_title,
            event_type_slug => slug,
            overrides => overrides_ctx,
            is_team => is_team,
            impersonating => impersonating,
            impersonating_name => impersonating_name,
        })
        .unwrap_or_default(),
    )
    .into_response()
}

#[derive(Deserialize)]
struct OverrideForm {
    _csrf: Option<String>,
    date: String,
    override_type: String,
    start_time: Option<String>,
    end_time: Option<String>,
}

async fn create_override(
    State(state): State<Arc<AppState>>,
    auth_user: crate::auth::AuthUser,
    headers: HeaderMap,
    Path(slug): Path<String>,
    Form(form): Form<OverrideForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }
    let user = &auth_user.user;
    let is_global_admin = user.role == "admin";

    let et_id: Option<String> = if is_global_admin {
        sqlx::query_scalar("SELECT id FROM event_types WHERE slug = ? LIMIT 1")
            .bind(&slug)
            .fetch_optional(&state.pool)
            .await
            .unwrap_or(None)
    } else {
        find_manageable_event_type_by_slug(&state.pool, &user.id, &slug)
            .await
            .map(|(id, _, _)| id)
    };

    let et_id = match et_id {
        Some(id) => id,
        None => return Redirect::to("/dashboard/event-types").into_response(),
    };

    // Validate date
    if NaiveDate::parse_from_str(&form.date, "%Y-%m-%d").is_err() {
        return Redirect::to(&format!("/dashboard/event-types/{}/overrides", slug)).into_response();
    }

    let is_blocked = form.override_type != "custom";
    let (start_time, end_time) = if !is_blocked {
        let s = form.start_time.as_deref().unwrap_or("");
        let e = form.end_time.as_deref().unwrap_or("");
        if s.is_empty() || e.is_empty() || s >= e {
            return Redirect::to(&format!("/dashboard/event-types/{}/overrides", slug))
                .into_response();
        }
        (Some(s.to_string()), Some(e.to_string()))
    } else {
        (None, None)
    };

    let id = uuid::Uuid::new_v4().to_string();
    let _ = sqlx::query(
        "INSERT INTO availability_overrides (id, event_type_id, date, start_time, end_time, is_blocked) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&et_id)
    .bind(&form.date)
    .bind(&start_time)
    .bind(&end_time)
    .bind(if is_blocked { 1 } else { 0 })
    .execute(&state.pool)
    .await;

    tracing::info!(
        override_id = %id,
        event_type = %slug,
        date = %form.date,
        is_blocked = is_blocked,
        "availability override created"
    );

    Redirect::to(&format!("/dashboard/event-types/{}/overrides", slug)).into_response()
}

#[derive(Deserialize)]
struct DeleteOverrideForm {
    _csrf: Option<String>,
}

async fn delete_override(
    State(state): State<Arc<AppState>>,
    auth_user: crate::auth::AuthUser,
    headers: HeaderMap,
    Path((slug, override_id)): Path<(String, String)>,
    Form(form): Form<DeleteOverrideForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }
    let user = &auth_user.user;

    // Look up the override's event type, then check management policy via
    // `can_manage_event_type` so the rule lives in one place.
    let target_et_id: Option<String> =
        sqlx::query_scalar("SELECT event_type_id FROM availability_overrides WHERE id = ?")
            .bind(&override_id)
            .fetch_optional(&state.pool)
            .await
            .unwrap_or(None);

    if let Some(et_id) = target_et_id {
        if can_manage_event_type(&state.pool, user, &et_id).await {
            let _ = sqlx::query("DELETE FROM availability_overrides WHERE id = ?")
                .bind(&override_id)
                .execute(&state.pool)
                .await;
            tracing::info!(override_id = %override_id, deleted_by = %user.email, "availability override deleted");
        }
    }

    Redirect::to(&format!("/dashboard/event-types/{}/overrides", slug)).into_response()
}

/// Renders the embed code generator for a personal event type. The page is
/// all client-side once rendered: changing form fields rebuilds the snippet
/// and reloads the preview iframe — nothing is persisted server-side.
async fn embed_page(
    State(state): State<Arc<AppState>>,
    auth_user: crate::auth::AuthUser,
    Path(slug): Path<String>,
) -> Response {
    let user = &auth_user.user;

    let et: Option<(String, String, String, String, String)> = sqlx::query_as(
        "SELECT et.id, et.slug, et.title, et.default_calendar_view, et.visibility \
         FROM event_types et \
         JOIN accounts a ON a.id = et.account_id \
         WHERE a.user_id = ? AND et.slug = ? AND et.team_id IS NULL",
    )
    .bind(&user.id)
    .bind(&slug)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    let (_et_id, et_slug, et_title, default_calendar_view, visibility) = match et {
        Some(e) => e,
        None => return Redirect::to("/dashboard/event-types").into_response(),
    };

    // Username for the cal link path: /u/{username}/{slug}. `users.username` is
    // nullable (migration 003) and all /u/{username} lookups match on it, so a
    // user without a username can't produce a working embed link. Rather than
    // emit a snippet pointing at a 404, render the page with a notice and no
    // snippet (has_username = false).
    let username = user.username.clone().filter(|u| !u.is_empty());
    let has_username = username.is_some();
    let cal_path = match &username {
        Some(u) => format!("/u/{}/{}", u, et_slug),
        None => String::new(),
    };

    let base_url = embed_base_url();
    let accent = org_accent_hex(&state.pool).await;

    let tmpl = match state.templates.get_template("embed.html") {
        Ok(t) => t,
        Err(e) => return internal_error_response("template render", &e),
    };

    let (impersonating, impersonating_name, _) = impersonation_ctx(&auth_user);

    Html(
        tmpl.render(context! {
            sidebar => sidebar_context(&auth_user, "event-types"),
            event_type_title => et_title,
            event_type_slug => et_slug,
            cal_path => cal_path,
            has_username => has_username,
            base_url => base_url,
            default_layout => default_calendar_view,
            accent_color => accent,
            visibility => visibility,
            impersonating => impersonating,
            impersonating_name => impersonating_name,
        })
        .unwrap_or_default(),
    )
    .into_response()
}

/// Absolute base URL for embed snippets: `CALRS_BASE_URL` without a trailing
/// slash, or empty (the page then falls back to the dashboard's own origin).
fn embed_base_url() -> String {
    std::env::var("CALRS_BASE_URL")
        .unwrap_or_default()
        .trim_end_matches('/')
        .to_string()
}

/// Resolve the org accent hex for prefilling the embed brand color. Mirrors
/// build_theme_css precedence: the preset's accent for a preset theme,
/// `custom_accent` only when theme='custom', default blue otherwise.
async fn org_accent_hex(pool: &SqlitePool) -> String {
    let theme_row: Option<(String, Option<String>)> =
        sqlx::query_as("SELECT theme, custom_accent FROM auth_config WHERE id = 'singleton'")
            .fetch_optional(pool)
            .await
            .unwrap_or(None);
    match theme_row {
        Some((ref theme, ref custom)) if theme == "custom" => custom
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "#2563eb".to_string()),
        Some((ref theme, _)) => preset_accent(theme).to_string(),
        None => "#2563eb".to_string(),
    }
}

/// Embed code generator for a team event type. Mirrors `embed_page` but the
/// booking link is the team path `/team/{team_slug}/{event_slug}`, which is
/// always well-formed (teams always have a slug), so there is no missing-link
/// case. Access is restricted to team admins and global admins.
async fn group_embed_page(
    State(state): State<Arc<AppState>>,
    auth_user: crate::auth::AuthUser,
    Path((team_id, slug)): Path<(String, String)>,
) -> Response {
    let user = &auth_user.user;
    let is_admin = user.role == "admin";

    if !is_admin && !is_team_admin(&state.pool, &user.id, &team_id).await {
        return Html("You are not a team admin of this team.".to_string()).into_response();
    }

    let et: Option<(String, String, String, String, String, String)> = sqlx::query_as(
        "SELECT et.slug, et.title, et.default_calendar_view, et.visibility, t.slug, t.visibility \
         FROM event_types et \
         JOIN teams t ON t.id = et.team_id \
         WHERE et.team_id = ? AND et.slug = ?",
    )
    .bind(&team_id)
    .bind(&slug)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    let (et_slug, et_title, default_calendar_view, visibility, team_slug, team_visibility) =
        match et {
            Some(e) => e,
            None => return Redirect::to("/dashboard/event-types").into_response(),
        };

    let cal_path = format!("/team/{}/{}", team_slug, et_slug);
    let base_url = embed_base_url();
    let accent = org_accent_hex(&state.pool).await;

    let tmpl = match state.templates.get_template("embed.html") {
        Ok(t) => t,
        Err(e) => return internal_error_response("template render", &e),
    };

    let (impersonating, impersonating_name, _) = impersonation_ctx(&auth_user);

    // Team event types always sit on a real team slug, so the embed link is
    // never dead — has_username is always true here.
    Html(
        tmpl.render(context! {
            sidebar => sidebar_context(&auth_user, "event-types"),
            event_type_title => et_title,
            event_type_slug => et_slug,
            cal_path => cal_path,
            has_username => true,
            base_url => base_url,
            default_layout => default_calendar_view,
            accent_color => accent,
            visibility => visibility,
            team_visibility => team_visibility,
            impersonating => impersonating,
            impersonating_name => impersonating_name,
        })
        .unwrap_or_default(),
    )
    .into_response()
}

