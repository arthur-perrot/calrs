// --- User-scoped booking handlers ---

async fn show_slots_for_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((username, slug)): Path<(String, String)>,
    Query(query): Query<SlotsQuery>,
) -> Response {
    let embed = query.embed_params();
    // Dynamic group pages (`alice+bob`) intentionally return before embed
    // threading: embedding ad-hoc combined links is out of scope, so these
    // render with full chrome and don't autosize. The embed generator only
    // produces single-user/team links.
    if username.contains('+') {
        return show_dynamic_group_slots(&state, &headers, &username, &slug, &query)
            .await
            .into_response();
    }

    let user: Option<(
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
    )> = sqlx::query_as(
        "SELECT id, name, title, avatar_path, language FROM users WHERE username = ? AND enabled = 1",
    )
    .bind(&username)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    let (host_user_id, host_name, host_title, host_avatar_path, user_lang) = match user {
        Some(user) => user,
        None => return Html("User not found.".to_string()).into_response(),
    };

    let lang = crate::i18n::resolve(user_lang.as_deref(), &headers);

    let et: Option<(String, String, String, Option<String>, i32, i32, i32, i32, String, Option<String>, String, String)> = sqlx::query_as(
        "SELECT et.id, et.slug, et.title, et.description, et.duration_min, et.buffer_before, et.buffer_after, et.min_notice_min, et.location_type, et.location_value, et.visibility, et.default_calendar_view
         FROM event_types et
         JOIN accounts a ON a.id = et.account_id
         WHERE a.user_id = ? AND et.slug = ? AND et.enabled = 1",
    )
    .bind(&host_user_id)
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
        visibility,
        default_calendar_view,
    ) = match et {
        Some(e) => e,
        None => return Html("Event type not found.".to_string()).into_response(),
    };

    // Validate invite token for private event types
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
    } else {
        invite_guest_name = None;
        invite_guest_email = None;
    }

    // Sync calendars if stale before computing availability
    crate::commands::sync::sync_if_stale(&state.pool, &state.secret_key, &host_user_id).await;

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

    let now_host = Utc::now().with_timezone(&host_tz).naive_local();
    let end_date = now_host.date() + Duration::days((start_offset + days_ahead) as i64);
    let window_end = end_date.and_hms_opt(23, 59, 59).unwrap_or(now_host);
    let busy = BusySource::Individual(
        fetch_busy_times_for_user(
            &state.pool,
            &host_user_id,
            now_host,
            window_end,
            host_tz,
            Some(&et_id),
        )
        .await,
    );
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
            host_name => host_name,
            host_title => host_title.as_deref().unwrap_or(""),
            host_user_id => host_user_id,
            host_has_avatar => host_avatar_path.is_some(),
            host_initials => compute_initials(&host_name),
            username => username,
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
            invite_guest_name => invite_guest_name.as_deref().unwrap_or(""),
            invite_guest_email => invite_guest_email.as_deref().unwrap_or(""),
            default_calendar_view => embed.layout.as_deref().filter(|s| !s.is_empty()).unwrap_or(default_calendar_view.as_str()),
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

async fn show_book_form_for_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((username, slug)): Path<(String, String)>,
    Query(query): Query<BookQuery>,
) -> Response {
    let embed = query.embed_params();
    if username.contains('+') {
        return show_dynamic_group_book_form(&state, &headers, &username, &slug, &query)
            .await
            .into_response();
    }

    let et: Option<(String, String, String, Option<String>, i32, String, Option<String>, String, i32, Option<String>)> = sqlx::query_as(
        "SELECT et.id, et.slug, et.title, et.description, et.duration_min, et.location_type, et.location_value, et.visibility, et.max_additional_guests, u.language
         FROM event_types et
         JOIN accounts a ON a.id = et.account_id
         JOIN users u ON u.id = a.user_id
         WHERE u.username = ? AND et.slug = ? AND et.enabled = 1 AND u.enabled = 1",
    )
    .bind(&username)
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
        visibility,
        max_additional_guests,
        user_lang,
    ) = match et {
        Some(e) => e,
        None => return Html("Event type not found.".to_string()).into_response(),
    };

    let lang = crate::i18n::resolve(user_lang.as_deref(), &headers);

    // Validate invite token for private event types
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
    } else {
        invite_guest_name = None;
        invite_guest_email = None;
    }

    let host_name: String = sqlx::query_scalar("SELECT name FROM users WHERE username = ?")
        .bind(&username)
        .fetch_optional(&state.pool)
        .await
        .unwrap_or(None)
        .unwrap_or_else(|| "Host".to_string());

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
            host_name => host_name,
            username => username,
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

async fn handle_booking_for_user(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path((username, slug)): Path<(String, String)>,
    Query(embed): Query<EmbedParams>,
    Form(form): Form<BookForm>,
) -> Response {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }
    let captcha_cfg = state.captcha_config.read().await;
    if captcha::verify(&captcha_cfg, form.captcha_token.as_deref())
        .await
        .is_err()
    {
        tracing::warn!("captcha failed on user booking");
        return render_booking_action_error(
            &state,
            &headers,
            "Captcha verification failed",
            "Please go back and try again.",
        );
    }
    drop(captcha_cfg);
    if username.contains('+') {
        return handle_dynamic_group_booking(&state, &headers, &username, &slug, &form)
            .await
            .into_response();
    }
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

    let et: Option<(String, String, String, i32, i32, i32, i32, i32, String, Option<String>, String, Option<i32>, String, i32, Option<String>)> = sqlx::query_as(
        "SELECT et.id, et.slug, et.title, et.duration_min, et.buffer_before, et.buffer_after, et.min_notice_min, et.requires_confirmation, et.location_type, et.location_value, u.id, et.reminder_minutes, et.visibility, et.max_additional_guests, u.language
         FROM event_types et
         JOIN accounts a ON a.id = et.account_id
         JOIN users u ON u.id = a.user_id
         WHERE u.username = ? AND et.slug = ? AND et.enabled = 1 AND u.enabled = 1",
    )
    .bind(&username)
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
        host_user_id,
        reminder_min,
        visibility,
        max_additional_guests,
        user_lang,
    ) = match et {
        Some(e) => e,
        None => return Html("Event type not found.".to_string()).into_response(),
    };

    let lang = crate::i18n::resolve(user_lang.as_deref(), &headers);
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

    // Validate invite token for private event types
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

    // Start a transaction to ensure atomicity of availability check + insert.
    let mut tx = match state.pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            return internal_error_response("database query", &e);
        }
    };

    let busy = fetch_busy_times_for_user(
        &state.pool,
        &host_user_id,
        buf_start,
        buf_end,
        host_tz,
        Some(&et_id),
    )
    .await;
    if has_conflict(&busy, buf_start, buf_end) {
        let _ = tx.rollback().await;
        return Html("This slot is no longer available.".to_string()).into_response();
    }

    // Check booking frequency limits. Personal event-type flows don't have a
    // team assignee, so per-member caps degrade to event-type-wide here.
    if would_exceed_frequency_limit(&state.pool, &et_id, slot_start, None).await {
        let _ = tx.rollback().await;
        return render_booking_action_error(
            &state,
            &headers,
            "Not available right now",
            "The host isn't accepting more bookings for this date. Please pick a different date, or check back later.",
        );
    }

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

    // Build BookingDetails once. CalDAV push and email send both need it,
    // and CalDAV push must run independently of whether SMTP is configured.
    let host: Option<(String, String)> = sqlx::query_as(
        "SELECT u.name, COALESCE(u.booking_email, u.email) FROM users u WHERE u.username = ?",
    )
    .bind(&username)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    let host_user_id: Option<String> =
        sqlx::query_scalar("SELECT id FROM users WHERE username = ?")
            .bind(&username)
            .fetch_optional(&state.pool)
            .await
            .unwrap_or(None);
    let location_display = resolve_booking_location(
        &state,
        &id,
        &et_id,
        host_user_id.as_deref(),
        loc_value.as_deref(),
        &form.name,
        &form.email,
        !needs_approval,
    )
    .await;

    if let Some((host_name, host_email)) = host {
        let details = crate::email::BookingDetails {
            event_title: et_title.clone(),
            date: form.date.clone(),
            start_time: form.time.clone(),
            end_time: guest_end_time.clone(),
            guest_name: form.name.clone(),
            guest_email: form.email.clone(),
            guest_timezone: guest_timezone.clone(),
            host_name,
            host_email,
            uid: uid.clone(),
            notes: form.notes.clone(),
            location: location_display.clone(),
            reminder_minutes: reminder_min,
            additional_attendees: additional_attendees.clone(),
            guest_language: Some(lang.to_string()),
            host_timezone: host_tz.name().to_string(),
            ..Default::default()
        };

        // Push confirmed bookings to CalDAV regardless of SMTP availability.
        if !needs_approval {
            if let Some(uid_user) = host_user_id.as_deref() {
                caldav_push_booking(&state.pool, &state.secret_key, uid_user, &uid, &details).await;
            }
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
    }

    let host_name: String = sqlx::query_scalar("SELECT name FROM users WHERE username = ?")
        .bind(&username)
        .fetch_optional(&state.pool)
        .await
        .unwrap_or(None)
        .unwrap_or_else(|| "Host".to_string());

    let date_label = crate::i18n::format_long_date(date, lang);
    let (cancel_notice_min, reschedule_notice_min) =
        fetch_event_type_notice_minutes(&state.pool, &et_id).await;

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

include!("slots.rs");

// --- Handlers ---

#[derive(Deserialize)]
struct SlotsQuery {
    #[serde(default)]
    month: Option<String>,
    #[serde(default)]
    tz: Option<String>,
    #[serde(default)]
    invite: Option<String>,
    /// When "1", perform full sync + computation (AJAX callback for deferred loading)
    #[serde(default)]
    deferred: Option<String>,
    #[serde(default)]
    embed: Option<String>,
    #[serde(default)]
    layout: Option<String>,
    #[serde(default)]
    theme: Option<String>,
    #[serde(default)]
    brand: Option<String>,
}

impl SlotsQuery {
    fn embed_params(&self) -> EmbedParams {
        EmbedParams {
            embed: self.embed.clone(),
            layout: self.layout.clone(),
            theme: self.theme.clone(),
            brand: self.brand.clone(),
        }
    }
}

/// Parse a "YYYY-MM" month param, returning (year, month_1indexed). Defaults to current month in guest TZ.
fn parse_month_param(param: Option<&str>, guest_tz: Tz) -> (i32, u32) {
    if let Some(s) = param {
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() == 2 {
            if let (Ok(y), Ok(m)) = (parts[0].parse::<i32>(), parts[1].parse::<u32>()) {
                if (1..=12).contains(&m) {
                    return (y, m);
                }
            }
        }
    }
    let now = Utc::now().with_timezone(&guest_tz).naive_local();
    (now.date().year(), now.date().month())
}

/// Build month-based slot computation parameters and context variables.
/// Returns (start_offset, days_ahead, month_label, prev_month, next_month, first_weekday, days_in_month, today_date, month_year)
fn build_month_params(
    year: i32,
    month: u32,
    host_tz: Tz,
    guest_tz: Tz,
    lang: &str,
) -> (
    i32,
    i32,
    String,
    Option<String>,
    String,
    u32,
    u32,
    String,
    String,
) {
    let now_guest = Utc::now().with_timezone(&guest_tz).naive_local();
    let now_host = Utc::now().with_timezone(&host_tz).naive_local();
    let today_guest = now_guest.date();

    let month_start = NaiveDate::from_ymd_opt(year, month, 1).unwrap();
    let month_end = if month == 12 {
        NaiveDate::from_ymd_opt(year + 1, 1, 1).unwrap()
    } else {
        NaiveDate::from_ymd_opt(year, month + 1, 1).unwrap()
    } - Duration::days(1);

    let days_in_month = (month_end - month_start).num_days() as u32 + 1;

    // Compute start_offset and days_ahead relative to host's today
    let host_today = now_host.date();
    let start_offset = (month_start - host_today).num_days().max(0) as i32;
    let end_offset = (month_end - host_today).num_days() as i32 + 2; // +2 buffer for TZ edge cases
    let days_ahead = (end_offset - start_offset).max(1);

    let month_label = crate::i18n::format_month_year(month_start, lang);
    let month_year = format!("{}-{:02}", year, month);

    // prev_month: None if viewing current month or earlier
    let current_month_start =
        NaiveDate::from_ymd_opt(today_guest.year(), today_guest.month(), 1).unwrap();
    let prev_month = if month_start > current_month_start {
        let (py, pm) = if month == 1 {
            (year - 1, 12)
        } else {
            (year, month - 1)
        };
        Some(format!("{}-{:02}", py, pm))
    } else {
        None
    };

    let (ny, nm) = if month == 12 {
        (year + 1, 1)
    } else {
        (year, month + 1)
    };
    let next_month = format!("{}-{:02}", ny, nm);

    // Monday = 0 for the grid
    let first_weekday = month_start.weekday().num_days_from_monday();
    let today_date = today_guest.format("%Y-%m-%d").to_string();

    (
        start_offset,
        days_ahead,
        month_label,
        prev_month,
        next_month,
        first_weekday,
        days_in_month,
        today_date,
        month_year,
    )
}

/// Parse a timezone string into a Tz, falling back to server local.
fn parse_guest_tz(tz: Option<&str>) -> Tz {
    tz.and_then(|s| s.parse::<Tz>().ok()).unwrap_or_else(|| {
        // Fall back to server's local timezone
        iana_time_zone::get_timezone()
            .ok()
            .and_then(|s| s.parse::<Tz>().ok())
            .unwrap_or(Tz::UTC)
    })
}

/// Normalize a timezone value submitted via an event-type form. Accepts the
/// input only if it parses as a valid IANA timezone, otherwise returns the
/// fallback (typically the submitting user's timezone).
fn normalize_event_type_tz(input: Option<&str>, fallback: &str) -> String {
    input
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter(|s| s.parse::<Tz>().is_ok())
        .map(str::to_string)
        .unwrap_or_else(|| fallback.to_string())
}

/// Get the host's timezone from the event type owner's profile.
/// Falls back to the server's local timezone, then UTC.
/// Convert a naive datetime in the guest's timezone to the equivalent naive
/// datetime in the host's timezone. Used when accepting a booking: the URL
/// carries the time the guest clicked (their local time), but availability
/// checks, storage, and the existing display code all assume host-local.
fn guest_to_host_local(guest_local: NaiveDateTime, guest_tz: Tz, host_tz: Tz) -> NaiveDateTime {
    use chrono::TimeZone;
    let utc = guest_tz
        .from_local_datetime(&guest_local)
        .earliest()
        .unwrap_or_else(|| guest_tz.from_utc_datetime(&guest_local))
        .with_timezone(&Utc);
    utc.with_timezone(&host_tz).naive_local()
}

async fn get_host_tz(pool: &SqlitePool, et_id: &str) -> Tz {
    if !et_id.is_empty() {
        // Prefer the explicit event-type timezone (migration 046). Falls back
        // to the account owner's timezone for rows where it is still NULL.
        if let Some(tz_str) = sqlx::query_scalar::<_, String>(
            "SELECT COALESCE(NULLIF(et.timezone, ''), u.timezone)
             FROM event_types et
             JOIN accounts a ON a.id = et.account_id
             JOIN users u ON u.id = a.user_id
             WHERE et.id = ?",
        )
        .bind(et_id)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        {
            if let Ok(tz) = tz_str.parse::<Tz>() {
                return tz;
            }
        }
    }
    server_tz()
}

/// Get a user's timezone from their profile. Falls back to server TZ.
async fn get_user_tz(pool: &SqlitePool, user_id: &str) -> Tz {
    if let Some(tz_str) = sqlx::query_scalar::<_, String>("SELECT timezone FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
    {
        if let Ok(tz) = tz_str.parse::<Tz>() {
            return tz;
        }
    }
    server_tz()
}

/// Server's local timezone as fallback.
fn server_tz() -> Tz {
    iana_time_zone::get_timezone()
        .ok()
        .and_then(|s| s.parse::<Tz>().ok())
        .unwrap_or(Tz::UTC)
}

/// Common IANA timezones for the selector (most used ones).
fn common_timezones_with(guest_tz: &str) -> Vec<(String, String)> {
    use chrono::Utc;
    let now = Utc::now();
    let entries: &[(&str, &str)] = &[
        ("Pacific/Midway", "Midway"),
        ("Pacific/Honolulu", "Hawaii"),
        ("America/Anchorage", "Alaska"),
        ("America/Los_Angeles", "Los Angeles"),
        ("America/Denver", "Denver"),
        ("America/Chicago", "Chicago"),
        ("America/New_York", "New York"),
        ("America/Sao_Paulo", "São Paulo"),
        ("Atlantic/Cape_Verde", "Cape Verde"),
        ("UTC", "UTC"),
        ("Europe/London", "London"),
        ("Europe/Paris", "Paris, Brussels"),
        ("Europe/Helsinki", "Helsinki, Kyiv"),
        ("Europe/Moscow", "Moscow"),
        ("Asia/Dubai", "Dubai"),
        ("Asia/Kolkata", "India"),
        ("Asia/Bangkok", "Bangkok"),
        ("Asia/Shanghai", "Shanghai"),
        ("Asia/Tokyo", "Tokyo"),
        ("Australia/Sydney", "Sydney"),
        ("Pacific/Auckland", "Auckland"),
    ];

    let format_label = |iana: &str, city: &str| -> String {
        if iana == "UTC" {
            "UTC".to_string()
        } else if let Ok(tz) = iana.parse::<chrono_tz::Tz>() {
            let offset = now.with_timezone(&tz).offset().fix().local_minus_utc();
            let h = offset / 3600;
            let m = (offset.abs() % 3600) / 60;
            let offset_str = if m != 0 {
                format!("UTC{:+}:{:02}", h, m)
            } else {
                format!("UTC{:+}", h)
            };
            format!("{} ({})", city, offset_str)
        } else {
            format!("{} ({})", city, iana)
        }
    };

    let mut result: Vec<(String, String)> = entries
        .iter()
        .map(|(iana, city)| {
            let label = format_label(iana, city);
            (iana.to_string(), label)
        })
        .collect();

    // If guest timezone is not in the common list, insert it sorted by UTC offset
    if !guest_tz.is_empty() && !entries.iter().any(|(iana, _)| *iana == guest_tz) {
        if let Ok(tz) = guest_tz.parse::<chrono_tz::Tz>() {
            let guest_offset = now.with_timezone(&tz).offset().fix().local_minus_utc();
            let label = format_label(guest_tz, guest_tz);
            // Find insertion point by UTC offset
            let pos = result
                .iter()
                .position(|(iana, _)| {
                    if *iana == "UTC" {
                        guest_offset < 0
                    } else if let Ok(t) = iana.parse::<chrono_tz::Tz>() {
                        let o = now.with_timezone(&t).offset().fix().local_minus_utc();
                        o > guest_offset
                    } else {
                        false
                    }
                })
                .unwrap_or(result.len());
            result.insert(pos, (guest_tz.to_string(), label));
        }
    }

    result
}

/// Returns CSS that overrides all theme variables for the given preset theme.
fn preset_theme_css(theme: &str) -> &'static str {
    match theme {
        "nord" => concat!(
            ":root{--bg:#eceff4;--surface:#fff;--surface-hover:#e5e9f0;--text:#2e3440;--text-secondary:#4c566a;--text-muted:#7b88a1;",
            "--border:#d8dee9;--border-hover:#b3bdd1;--accent:#5e81ac;--accent-hover:#4c6f97;--accent-subtle:#e8eef5;",
            "--accent-border:#b3cde0;--accent-muted:#81a1c1;--success:#a3be8c;--error-bg:#f5e6e8;--error-text:#bf616a}",
            " html.dark{--bg:#2e3440;--surface:#3b4252;--surface-hover:#434c5e;--text:#eceff4;--text-secondary:#d8dee9;--text-muted:#7b88a1;",
            "--border:#434c5e;--border-hover:#4c566a;--accent:#81a1c1;--accent-hover:#88c0d0;--accent-subtle:rgba(129,161,193,0.12);",
            "--accent-border:rgba(129,161,193,0.3);--accent-muted:#5e81ac;--success:#a3be8c;--error-bg:rgba(191,97,106,0.12);--error-text:#bf616a}"
        ),
        "dracula" => concat!(
            ":root{--bg:#f0edf5;--surface:#fff;--surface-hover:#e8e4ef;--text:#282a36;--text-secondary:#44475a;--text-muted:#7c7f94;",
            "--border:#d6d0e0;--border-hover:#b3adc4;--accent:#bd93f9;--accent-hover:#a76ff0;--accent-subtle:#f3eefe;",
            "--accent-border:#d4bffc;--accent-muted:#caa6fc;--success:#50fa7b;--error-bg:#fce4ec;--error-text:#ff5555}",
            " html.dark{--bg:#282a36;--surface:#44475a;--surface-hover:#4d5068;--text:#f8f8f2;--text-secondary:#d0cfe4;--text-muted:#7c7f94;",
            "--border:#4d5068;--border-hover:#6272a4;--accent:#bd93f9;--accent-hover:#caa6fc;--accent-subtle:rgba(189,147,249,0.12);",
            "--accent-border:rgba(189,147,249,0.3);--accent-muted:#9b6dff;--success:#50fa7b;--error-bg:rgba(255,85,85,0.12);--error-text:#ff5555}"
        ),
        "gruvbox" => concat!(
            ":root{--bg:#f9f5d7;--surface:#fbf1c7;--surface-hover:#f2e5bc;--text:#3c3836;--text-secondary:#504945;--text-muted:#928374;",
            "--border:#d5c4a1;--border-hover:#bdae93;--accent:#d65d0e;--accent-hover:#af3a03;--accent-subtle:#fef0e2;",
            "--accent-border:#f0b886;--accent-muted:#e78a4e;--success:#98971a;--error-bg:#fde8e6;--error-text:#cc241d}",
            " html.dark{--bg:#282828;--surface:#3c3836;--surface-hover:#504945;--text:#ebdbb2;--text-secondary:#d5c4a1;--text-muted:#928374;",
            "--border:#504945;--border-hover:#665c54;--accent:#fe8019;--accent-hover:#fabd2f;--accent-subtle:rgba(254,128,25,0.1);",
            "--accent-border:rgba(254,128,25,0.25);--accent-muted:#d65d0e;--success:#b8bb26;--error-bg:rgba(251,73,52,0.1);--error-text:#fb4934}"
        ),
        "solarized" => concat!(
            ":root{--bg:#fdf6e3;--surface:#eee8d5;--surface-hover:#e8e1cb;--text:#657b83;--text-secondary:#586e75;--text-muted:#93a1a1;",
            "--border:#d6cdb5;--border-hover:#b8b09a;--accent:#268bd2;--accent-hover:#1a6fad;--accent-subtle:#edf5fb;",
            "--accent-border:#a3cee8;--accent-muted:#6aafe2;--success:#859900;--error-bg:#fdf0ed;--error-text:#dc322f}",
            " html.dark{--bg:#002b36;--surface:#073642;--surface-hover:#0a4050;--text:#839496;--text-secondary:#93a1a1;--text-muted:#586e75;",
            "--border:#0a4050;--border-hover:#1a5060;--accent:#268bd2;--accent-hover:#6aafe2;--accent-subtle:rgba(38,139,210,0.1);",
            "--accent-border:rgba(38,139,210,0.25);--accent-muted:#1a6fad;--success:#859900;--error-bg:rgba(220,50,47,0.1);--error-text:#dc322f}"
        ),
        "tokyo-night" => concat!(
            ":root{--bg:#f0f0f5;--surface:#fff;--surface-hover:#e8e8ef;--text:#343b58;--text-secondary:#4c5478;--text-muted:#9099b0;",
            "--border:#d5d6e2;--border-hover:#b0b2c4;--accent:#7a5af5;--accent-hover:#6340db;--accent-subtle:#f0ecfe;",
            "--accent-border:#c4b5fd;--accent-muted:#a78bfa;--success:#41a87a;--error-bg:#fce8ec;--error-text:#e04071}",
            " html.dark{--bg:#1a1b26;--surface:#24283b;--surface-hover:#2f3349;--text:#a9b1d6;--text-secondary:#c0caf5;--text-muted:#565f89;",
            "--border:#2f3349;--border-hover:#414868;--accent:#7aa2f7;--accent-hover:#89b4fa;--accent-subtle:rgba(122,162,247,0.1);",
            "--accent-border:rgba(122,162,247,0.25);--accent-muted:#3d59a1;--success:#9ece6a;--error-bg:rgba(247,118,142,0.1);--error-text:#f7768e}"
        ),
        "vates" => concat!(
            ":root{--bg:#f5f4f0;--surface:#fff;--surface-hover:#faf9f5;--text:#1a1b38;--text-secondary:#3d3e58;--text-muted:#7a7b94;",
            "--border:#e2e1dc;--border-hover:#b5b4ae;--accent:#be1621;--accent-hover:#a01219;--accent-subtle:#fdf1f1;",
            "--accent-border:#f0b8bb;--accent-muted:#d4555e;--success:#2ca878;--error-bg:#fdf1f1;--error-text:#be1621}",
            " html.dark{--bg:#1a1b38;--surface:#262748;--surface-hover:#32335a;--text:#f0efe8;--text-secondary:#c8c7c0;--text-muted:#7a7b94;",
            "--border:#32335a;--border-hover:#4a4b6e;--accent:#e0424c;--accent-hover:#ef7f18;--accent-subtle:rgba(190,22,33,0.12);",
            "--accent-border:rgba(190,22,33,0.3);--accent-muted:#8a1018;--success:#2ca878;--error-bg:rgba(190,22,33,0.12);--error-text:#e0424c}"
        ),
        // "default" (blue) — no overrides needed, base.html defines it
        _ => "",
    }
}

/// Light-mode accent hex for a preset theme, mirroring the `--accent` values in
/// `preset_theme_css`. Used to prefill the embed brand color so it matches the
/// org theme even when a preset (not a custom theme) is active.
fn preset_accent(theme: &str) -> &'static str {
    match theme {
        "nord" => "#5e81ac",
        "dracula" => "#bd93f9",
        "gruvbox" => "#d65d0e",
        "solarized" => "#268bd2",
        "tokyo-night" => "#7a5af5",
        "vates" => "#be1621",
        // "default" (blue) and anything unknown
        _ => "#2563eb",
    }
}

/// Build custom theme CSS from user-provided hex colors.
fn custom_theme_css(
    accent: &str,
    accent_hover: &str,
    bg: &str,
    surface: &str,
    text: &str,
) -> String {
    // Validate that all colors look like hex codes
    let validate_hex = |c: &str| -> bool {
        let c = c.trim();
        c.len() == 7 && c.starts_with('#') && c[1..].chars().all(|ch| ch.is_ascii_hexdigit())
    };
    if ![accent, accent_hover, bg, surface, text]
        .iter()
        .all(|c| validate_hex(c))
    {
        return String::new();
    }
    // Parse accent for subtle/border/muted derivations
    let r = u8::from_str_radix(&accent[1..3], 16).unwrap_or(0);
    let g = u8::from_str_radix(&accent[3..5], 16).unwrap_or(0);
    let b = u8::from_str_radix(&accent[5..7], 16).unwrap_or(0);

    format!(
        ":root{{--bg:{bg};--surface:{surface};--text:{text};--accent:{accent};--accent-hover:{accent_hover};\
         --accent-subtle:rgba({r},{g},{b},0.08);--accent-border:rgba({r},{g},{b},0.25);--accent-muted:rgba({r},{g},{b},0.5)}}\
         html.dark{{--bg:{bg};--surface:{surface};--text:{text};--accent:{accent};--accent-hover:{accent_hover};\
         --accent-subtle:rgba({r},{g},{b},0.12);--accent-border:rgba({r},{g},{b},0.3);--accent-muted:rgba({r},{g},{b},0.5)}}",
    )
}

/// Build the full theme CSS string from DB settings.
async fn build_theme_css(pool: &SqlitePool) -> String {
    let row: Option<(String, Option<String>, Option<String>, Option<String>, Option<String>, Option<String>)> =
        sqlx::query_as("SELECT theme, custom_accent, custom_accent_hover, custom_bg, custom_surface, custom_text FROM auth_config WHERE id = 'singleton'")
            .fetch_optional(pool)
            .await
            .unwrap_or(None);
    match row {
        Some((ref theme, ref ca, ref cah, ref cb, ref cs, ref ct)) if theme == "custom" => {
            let accent = ca.as_deref().unwrap_or("#2563eb");
            let accent_hover = cah.as_deref().unwrap_or("#1d4ed8");
            let bg = cb.as_deref().unwrap_or("#f4f4f5");
            let surface = cs.as_deref().unwrap_or("#ffffff");
            let text = ct.as_deref().unwrap_or("#18181b");
            custom_theme_css(accent, accent_hover, bg, surface, text)
        }
        Some((ref theme, ..)) => preset_theme_css(theme).to_string(),
        None => String::new(),
    }
}

/// Get the current theme name from DB.
async fn get_theme_name(pool: &SqlitePool) -> String {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT theme FROM auth_config WHERE id = 'singleton'")
            .fetch_optional(pool)
            .await
            .unwrap_or(None);
    row.map(|r| r.0).unwrap_or_else(|| "default".to_string())
}

/// Get custom theme colors from DB (for populating the form).
async fn get_custom_colors(pool: &SqlitePool) -> (String, String, String, String, String) {
    let row: Option<(Option<String>, Option<String>, Option<String>, Option<String>, Option<String>)> =
        sqlx::query_as("SELECT custom_accent, custom_accent_hover, custom_bg, custom_surface, custom_text FROM auth_config WHERE id = 'singleton'")
            .fetch_optional(pool)
            .await
            .unwrap_or(None);
    match row {
        Some((a, ah, bg, s, t)) => (
            a.unwrap_or_else(|| "#2563eb".to_string()),
            ah.unwrap_or_else(|| "#1d4ed8".to_string()),
            bg.unwrap_or_else(|| "#f4f4f5".to_string()),
            s.unwrap_or_else(|| "#ffffff".to_string()),
            t.unwrap_or_else(|| "#18181b".to_string()),
        ),
        None => (
            "#2563eb".to_string(),
            "#1d4ed8".to_string(),
            "#f4f4f5".to_string(),
            "#ffffff".to_string(),
            "#18181b".to_string(),
        ),
    }
}

async fn show_slots(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(slug): Path<String>,
    Query(query): Query<SlotsQuery>,
) -> impl IntoResponse {
    let lang = crate::i18n::detect_from_headers(&headers);
    let et: Option<(String, String, String, Option<String>, i32, i32, i32, i32, String, String)> = sqlx::query_as(
        "SELECT id, slug, title, description, duration_min, buffer_before, buffer_after, min_notice_min, visibility, default_calendar_view
         FROM event_types WHERE slug = ? AND enabled = 1",
    )
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
        visibility,
        default_calendar_view,
    ) = match et {
        Some(e) => e,
        None => return Html("Event type not found.".to_string()),
    };

    // Block private event types on legacy route (use /u/ or /team/ routes with invite token instead)
    if visibility == "private" || visibility == "internal" {
        return Html("This event type requires an invite link.".to_string());
    }

    let host_info: Option<(String, String, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT u.id, u.name, u.title, u.avatar_path FROM users u JOIN accounts a ON a.user_id = u.id JOIN event_types et ON et.account_id = a.id WHERE et.id = ?",
    )
    .bind(&et_id)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    let (host_user_id, host_name, host_title, host_avatar_path) =
        host_info.unwrap_or_else(|| ("".to_string(), "Host".to_string(), None, None));

    // Sync calendars if stale before computing availability
    crate::commands::sync::sync_if_stale(&state.pool, &state.secret_key, &host_user_id).await;

    let guest_tz = parse_guest_tz(query.tz.as_deref());
    let host_tz = get_host_tz(&state.pool, &et_id).await;
    let guest_tz_name = guest_tz.name().to_string();

    let (year, mo) = parse_month_param(query.month.as_deref(), guest_tz);
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
    ) = build_month_params(year, mo, host_tz, guest_tz, lang);

    let now_host = Utc::now().with_timezone(&host_tz).naive_local();
    let end_date = now_host.date() + Duration::days((start_offset + days_ahead) as i64);
    let window_end = end_date.and_hms_opt(23, 59, 59).unwrap_or(now_host);
    let busy = BusySource::Individual(
        fetch_busy_times_for_user(
            &state.pool,
            &host_user_id,
            now_host,
            window_end,
            host_tz,
            Some(&et_id),
        )
        .await,
    );
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

    let (meeting_jitsi_label, meeting_webhook_label) = meeting_provider_labels(&state).await;
    let tmpl = match state.templates.get_template("slots.html") {
        Ok(t) => t,
        Err(e) => return internal_error_html("internal", &e),
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
            },
            host_name => &host_name,
            host_title => host_title.as_deref().unwrap_or(""),
            host_user_id => &host_user_id,
            host_has_avatar => host_avatar_path.is_some(),
            host_initials => compute_initials(&host_name),
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
            default_calendar_view => default_calendar_view,
            company_link => state.company_link.read().await.clone(),
            lang => lang,
        })
        .unwrap_or_else(|e| internal_error_body("template render", &e));

    Html(rendered)
}

#[derive(Deserialize)]
struct BookQuery {
    date: String,
    time: String,
    #[serde(default)]
    tz: Option<String>,
    #[serde(default)]
    invite: Option<String>,
    #[serde(default)]
    embed: Option<String>,
    #[serde(default)]
    layout: Option<String>,
    #[serde(default)]
    theme: Option<String>,
    #[serde(default)]
    brand: Option<String>,
}

impl BookQuery {
    fn embed_params(&self) -> EmbedParams {
        EmbedParams {
            embed: self.embed.clone(),
            layout: self.layout.clone(),
            theme: self.theme.clone(),
            brand: self.brand.clone(),
        }
    }
}

async fn show_book_form(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(slug): Path<String>,
    Query(query): Query<BookQuery>,
) -> impl IntoResponse {
    let lang = crate::i18n::detect_from_headers(&headers);
    let et: Option<(String, String, String, Option<String>, i32, i32, String)> = sqlx::query_as(
        "SELECT id, slug, title, description, duration_min, max_additional_guests, visibility
         FROM event_types WHERE slug = ? AND enabled = 1",
    )
    .bind(&slug)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    let (et_id, et_slug, et_title, et_desc, duration, max_additional_guests, visibility) = match et
    {
        Some(e) => e,
        None => return Html("Event type not found.".to_string()),
    };

    // Block non-public event types on legacy route
    if visibility == "private" || visibility == "internal" {
        return Html("This event type requires an invite link.".to_string());
    }

    let host_name: String = sqlx::query_scalar(
        "SELECT a.name FROM accounts a JOIN event_types et ON et.account_id = a.id WHERE et.id = ?",
    )
    .bind(&et_id)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None)
    .unwrap_or_else(|| "Host".to_string());

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

    let (meeting_jitsi_label, meeting_webhook_label) = meeting_provider_labels(&state).await;
    let tmpl = match state.templates.get_template("book.html") {
        Ok(t) => t,
        Err(e) => return internal_error_html("internal", &e),
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
            },
            host_name => host_name,
            date => query.date,
            date_label => date_label,
            time_start => query.time,
            time_end => end_time,
            guest_tz => guest_tz_name,
            error => "",
            form_name => "",
            form_email => "",
            form_notes => "",
            max_additional_guests => max_additional_guests,
            company_link => state.company_link.read().await.clone(),
            captcha_enabled => captcha.enabled,
            captcha_api_endpoint => captcha.api_endpoint,
            captcha_widget_url => captcha.widget_url,
            lang => lang,
        })
        .unwrap_or_else(|e| internal_error_body("template render", &e));

    Html(rendered)
}

fn validate_booking_input(name: &str, email: &str, notes: &Option<String>) -> Result<(), String> {
    let name = name.trim();
    if name.is_empty() || name.len() > 255 {
        return Err("Name must be between 1 and 255 characters.".to_string());
    }
    let email = email.trim();
    if email.is_empty() || email.len() > 255 {
        return Err("Email must be between 1 and 255 characters.".to_string());
    }
    if !email.contains('@')
        || email
            .rsplit('@')
            .next()
            .is_none_or(|domain| !domain.contains('.'))
    {
        return Err("Please enter a valid email address.".to_string());
    }
    if let Some(notes) = notes {
        if notes.len() > 5000 {
            return Err("Notes must be 5000 characters or less.".to_string());
        }
    }
    Ok(())
}

fn validate_date_not_too_far(date: NaiveDate) -> Result<(), String> {
    let max_date = Utc::now().naive_utc().date() + Duration::days(366);
    if date > max_date {
        return Err("Cannot book more than one year in advance.".to_string());
    }
    Ok(())
}

/// Parse comma-separated additional guest emails, validate format, enforce max count.
/// Returns the list of valid, deduplicated emails (excluding the primary guest email).
fn parse_additional_guests(
    raw: &Option<String>,
    max: i32,
    primary_email: &str,
) -> Result<Vec<String>, String> {
    let raw = match raw {
        Some(s) if !s.trim().is_empty() => s,
        _ => return Ok(vec![]),
    };
    if max <= 0 {
        return Err("Additional guests are not allowed for this event type.".to_string());
    }
    let emails: Vec<String> = raw
        .split(',')
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    if emails.len() > max as usize {
        return Err(format!("You can add at most {} additional guest(s).", max));
    }
    let primary = primary_email.trim().to_lowercase();
    let mut seen = std::collections::HashSet::new();
    let mut result = Vec::new();
    for email in &emails {
        if email == &primary {
            continue; // skip if same as primary guest
        }
        if !email.contains('@')
            || email
                .rsplit('@')
                .next()
                .is_none_or(|domain| !domain.contains('.'))
        {
            return Err(format!("Invalid additional guest email: {}", email));
        }
        if seen.insert(email.clone()) {
            result.push(email.clone());
        }
    }
    Ok(result)
}

#[derive(Deserialize)]
struct BookForm {
    _csrf: Option<String>,
    date: String,
    time: String,
    name: String,
    email: String,
    notes: Option<String>,
    #[serde(default)]
    tz: Option<String>,
    #[serde(default)]
    invite_token: Option<String>,
    #[serde(default)]
    additional_guests: Option<String>,
    #[serde(rename = "cap-token", default)]
    captcha_token: Option<String>,
}

async fn handle_booking(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(slug): Path<String>,
    Form(form): Form<BookForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }
    let lang = crate::i18n::detect_from_headers(&headers);
    let captcha_cfg = state.captcha_config.read().await;
    if captcha::verify(&captcha_cfg, form.captcha_token.as_deref())
        .await
        .is_err()
    {
        tracing::warn!("captcha failed on booking");
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

    let et: Option<(String, String, String, i32, i32, i32, i32, i32, Option<i32>, i32, String)> = sqlx::query_as(
        "SELECT id, slug, title, duration_min, buffer_before, buffer_after, min_notice_min, requires_confirmation, reminder_minutes, max_additional_guests, visibility
         FROM event_types WHERE slug = ? AND enabled = 1",
    )
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
        reminder_min,
        max_additional_guests,
        visibility,
    ) = match et {
        Some(e) => e,
        None => return Html("Event type not found.".to_string()).into_response(),
    };
    let needs_approval = requires_confirmation != 0;

    // Block non-public event types on legacy route
    if visibility == "private" || visibility == "internal" {
        return Html("This event type requires an invite link.".to_string()).into_response();
    }

    // Parse additional guests
    let additional_attendees = match parse_additional_guests(
        &form.additional_guests,
        max_additional_guests,
        &form.email,
    ) {
        Ok(emails) => emails,
        Err(e) => return Html(e).into_response(),
    };

    // Get the host user_id for user-scoped busy time check
    let host_user_id: String = sqlx::query_scalar(
        "SELECT a.user_id FROM accounts a JOIN event_types et ON et.account_id = a.id WHERE et.id = ?",
    )
    .bind(&et_id)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None)
    .unwrap_or_default();

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

    // Validate minimum notice
    let now = Local::now().naive_local();
    if slot_start < now + Duration::minutes(min_notice as i64) {
        return Html("This slot is no longer available (too soon).".to_string()).into_response();
    }

    // Validate conflicts
    let buf_start = slot_start - Duration::minutes(buffer_before as i64);
    let buf_end = slot_end + Duration::minutes(buffer_after as i64);

    // Create booking
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

    // Start a transaction to ensure atomicity of availability check + insert.
    // The unique index idx_bookings_no_overlap is the ultimate guard against double-booking.
    let mut tx = match state.pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            return internal_error_response("database query", &e);
        }
    };

    let busy = fetch_busy_times_for_user(
        &state.pool,
        &host_user_id,
        buf_start,
        buf_end,
        host_tz,
        Some(&et_id),
    )
    .await;
    if has_conflict(&busy, buf_start, buf_end) {
        let _ = tx.rollback().await;
        return Html("This slot is no longer available.".to_string()).into_response();
    }

    // Check booking frequency limits. Personal event-type flows don't have a
    // team assignee, so per-member caps degrade to event-type-wide here.
    if would_exceed_frequency_limit(&state.pool, &et_id, slot_start, None).await {
        let _ = tx.rollback().await;
        return render_booking_action_error(
            &state,
            &headers,
            "Not available right now",
            "The host isn't accepting more bookings for this date. Please pick a different date, or check back later.",
        );
    }

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

    // Build BookingDetails once. CalDAV push and email send both need it,
    // and CalDAV push must run independently of whether SMTP is configured.
    let host: Option<(String, String)> = sqlx::query_as(
        "SELECT u.name, COALESCE(u.booking_email, u.email) FROM users u JOIN accounts a ON a.user_id = u.id WHERE a.id = (SELECT account_id FROM event_types WHERE id = ?)",
    )
    .bind(&et_id)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    if let Some((host_name, host_email)) = host {
        let host_user_id: Option<String> = sqlx::query_scalar(
            "SELECT u.id FROM users u JOIN accounts a ON a.user_id = u.id JOIN event_types et ON et.account_id = a.id WHERE et.id = ?",
        )
        .bind(&et_id)
        .fetch_optional(&state.pool)
        .await
        .unwrap_or(None);
        let location_display = resolve_booking_location(
            &state,
            &id,
            &et_id,
            host_user_id.as_deref(),
            None,
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
            host_name,
            host_email,
            uid: uid.clone(),
            notes: form.notes.clone(),
            location: location_display,
            reminder_minutes: reminder_min,
            additional_attendees: additional_attendees.clone(),
            guest_language: Some(lang.to_string()),
            host_timezone: host_tz.name().to_string(),
            ..Default::default()
        };

        // Push confirmed bookings to CalDAV regardless of SMTP availability.
        if !needs_approval {
            if let Some(uid_user) = host_user_id.as_deref() {
                caldav_push_booking(&state.pool, &state.secret_key, uid_user, &uid, &details).await;
            }
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
    }

    // Render confirmation
    let host_name: String = sqlx::query_scalar(
        "SELECT a.name FROM accounts a JOIN event_types et ON et.account_id = a.id WHERE et.id = ?",
    )
    .bind(&et_id)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None)
    .unwrap_or_else(|| "Host".to_string());

    let date_label = crate::i18n::format_long_date(date, lang);
    let (cancel_notice_min, reschedule_notice_min) =
        fetch_event_type_notice_minutes(&state.pool, &et_id).await;

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
            additional_attendees => additional_attendees,
            cancel_notice_min => cancel_notice_min,
            reschedule_notice_min => reschedule_notice_min,
            company_link => state.company_link.read().await.clone(),
            lang => lang,
        })
        .unwrap_or_else(|e| internal_error_body("template render", &e));

    Html(rendered).into_response()
}

