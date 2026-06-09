// --- Root redirect ---

async fn root_redirect() -> impl IntoResponse {
    Redirect::to("/auth/login")
}

// --- Dashboard (overview) ---

async fn dashboard(
    State(state): State<Arc<AppState>>,
    auth_user: crate::auth::AuthUser,
) -> impl IntoResponse {
    let user = &auth_user.user;

    let event_type_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM event_types et JOIN accounts a ON a.id = et.account_id WHERE a.user_id = ? AND et.team_id IS NULL")
            .bind(&user.id)
            .fetch_one(&state.pool)
            .await
            .unwrap_or(0);

    let pending_bookings: Vec<(
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
    )> = sqlx::query_as(
        "SELECT b.id, b.guest_name, b.guest_email, b.start_at, b.end_at, et.title,
                COALESCE(NULLIF(et.timezone, ''), u.timezone) AS stored_tz,
                COALESCE(NULLIF(b.guest_timezone, ''), 'UTC') AS guest_tz
         FROM bookings b
         JOIN event_types et ON et.id = b.event_type_id
         JOIN accounts a ON a.id = et.account_id
         JOIN users u ON u.id = a.user_id
         WHERE a.user_id = ? AND b.status = 'pending'
         ORDER BY b.start_at",
    )
    .bind(&user.id)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    let upcoming_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM bookings b JOIN event_types et ON et.id = b.event_type_id JOIN accounts a ON a.id = et.account_id WHERE a.user_id = ? AND b.status = 'confirmed' AND b.start_at >= datetime('now')")
            .bind(&user.id)
            .fetch_one(&state.pool)
            .await
            .unwrap_or(0);

    let source_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM caldav_sources cs JOIN accounts a ON a.id = cs.account_id WHERE a.user_id = ?")
            .bind(&user.id)
            .fetch_one(&state.pool)
            .await
            .unwrap_or(0);

    let team_count: i64 = if user.role == "admin" {
        sqlx::query_scalar("SELECT COUNT(*) FROM teams")
            .fetch_one(&state.pool)
            .await
            .unwrap_or(0)
    } else {
        sqlx::query_scalar("SELECT COUNT(*) FROM team_members WHERE user_id = ?")
            .bind(&user.id)
            .fetch_one(&state.pool)
            .await
            .unwrap_or(0)
    };

    let tmpl = match state.templates.get_template("dashboard_overview.html") {
        Ok(t) => t,
        Err(e) => return internal_error_html("template render", &e),
    };

    let host_tz = &user.timezone;
    let pending_ctx: Vec<minijinja::Value> = pending_bookings
        .iter()
        .map(
            |(id, name, email, start, end, title, stored_tz, guest_tz)| {
                let (primary, secondary) =
                    format_booking_for_dashboard(start, end, stored_tz, host_tz, guest_tz);
                context! {
                    id => id,
                    guest_name => name,
                    guest_email => email,
                    start_at => primary,
                    start_at_guest => secondary,
                    event_title => title,
                }
            },
        )
        .collect();

    let pending_count = pending_ctx.len() as i64;

    let (impersonating, impersonating_name, _) = impersonation_ctx(&auth_user);

    Html(
        tmpl.render(context! {
            sidebar => sidebar_context(&auth_user, "overview"),
            user_name => user.name,
            user_email => user.email,
            user_role => user.role,
            username => user.username,
            event_type_count => event_type_count,
            upcoming_count => upcoming_count,
            pending_count => pending_count,
            source_count => source_count,
            team_count => team_count,
            is_admin => user.role == "admin",
            pending_bookings => pending_ctx,
            impersonating => impersonating,
            impersonating_name => impersonating_name,
        })
        .unwrap_or_else(|e| internal_error_body("template render", &e)),
    )
}

// --- Dashboard: Event Types ---

async fn dashboard_event_types(
    State(state): State<Arc<AppState>>,
    auth_user: crate::auth::AuthUser,
) -> impl IntoResponse {
    let user = &auth_user.user;

    let event_types: Vec<(String, String, String, i32, bool, i32, i64, String)> = sqlx::query_as(
        "SELECT et.id, et.slug, et.title, et.duration_min, et.enabled, et.requires_confirmation,
                (SELECT COUNT(*) FROM bookings b WHERE b.event_type_id = et.id AND b.status IN ('confirmed', 'pending')) as active_bookings,
                et.visibility
         FROM event_types et
         JOIN accounts a ON a.id = et.account_id
         WHERE a.user_id = ? AND et.team_id IS NULL
         ORDER BY et.created_at",
    )
    .bind(&user.id)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    let is_admin = user.role == "admin";

    // Teams the user is an admin of — used for `can_manage` (edit/toggle/delete)
    // and "Create team event type" enablement. Regular team members can view but
    // not manage.
    let admin_team_ids: std::collections::HashSet<String> = if is_admin {
        std::collections::HashSet::new() // global admins can manage all
    } else {
        let ids: Vec<(String,)> =
            sqlx::query_as("SELECT team_id FROM team_members WHERE user_id = ? AND role = 'admin'")
                .bind(&user.id)
                .fetch_all(&state.pool)
                .await
                .unwrap_or_default();
        ids.into_iter().map(|(id,)| id).collect()
    };

    let team_event_types: Vec<(
        String,
        String,
        String,
        i32,
        bool,
        String,
        String,
        i64,
        String,
        String,
        String,
    )> = if is_admin {
        sqlx::query_as(
            "SELECT et.id, et.slug, et.title, et.duration_min, et.enabled, t.name, t.slug,
                    (SELECT COUNT(*) FROM bookings b WHERE b.event_type_id = et.id AND b.status IN ('confirmed', 'pending')) as active_bookings,
                    et.visibility, t.id, et.scheduling_mode
             FROM event_types et
             JOIN teams t ON t.id = et.team_id
             WHERE et.team_id IS NOT NULL
             ORDER BY t.name, et.created_at",
        )
        .fetch_all(&state.pool)
        .await
        .unwrap_or_default()
    } else {
        sqlx::query_as(
            "SELECT et.id, et.slug, et.title, et.duration_min, et.enabled, t.name, t.slug,
                    (SELECT COUNT(*) FROM bookings b WHERE b.event_type_id = et.id AND b.status IN ('confirmed', 'pending')) as active_bookings,
                    et.visibility, t.id, et.scheduling_mode
             FROM event_types et
             JOIN teams t ON t.id = et.team_id
             JOIN team_members tm ON tm.team_id = t.id
             WHERE tm.user_id = ?
             ORDER BY t.name, et.created_at",
        )
        .bind(&user.id)
        .fetch_all(&state.pool)
        .await
        .unwrap_or_default()
    };

    // Whether user can create new team event types (global admin or team admin of at least one team)
    let can_create_team_et = is_admin || !admin_team_ids.is_empty();

    let tmpl = match state.templates.get_template("dashboard_event_types.html") {
        Ok(t) => t,
        Err(e) => return internal_error_html("template render", &e),
    };

    // Build a single unified list: personal event types first, then team ones
    let mut all_et_ctx: Vec<minijinja::Value> = Vec::new();

    for (id, slug, title, duration, enabled, req_conf, active_bookings, vis) in &event_types {
        all_et_ctx.push(context! {
            id => id, slug => slug, title => title, duration_min => duration,
            enabled => enabled, requires_confirmation => *req_conf != 0,
            active_bookings => active_bookings, visibility => vis,
            is_team => false, can_manage => true,
            edit_url => format!("/dashboard/event-types/{}/edit", slug),
            toggle_url => format!("/dashboard/event-types/{}/toggle", slug),
            delete_url => format!("/dashboard/event-types/{}/delete", slug),
            overrides_url => format!("/dashboard/event-types/{}/overrides", slug),
            embed_url => format!("/dashboard/event-types/{}/embed", slug),
            view_url => if vis != "private" { user.username.as_ref().map(|u| format!("/u/{}/{}", u, slug)) } else { None::<String> },
        });
    }

    for (
        id,
        slug,
        title,
        duration,
        enabled,
        team_name,
        team_slug,
        active_bookings,
        vis,
        team_id,
        scheduling_mode,
    ) in &team_event_types
    {
        let can_manage = is_admin || admin_team_ids.contains(team_id);
        all_et_ctx.push(context! {
            id => id, slug => slug, title => title, duration_min => duration,
            enabled => enabled, active_bookings => active_bookings, visibility => vis,
            is_team => true, team_name => team_name, team_slug => team_slug,
            team_id => team_id, scheduling_mode => scheduling_mode, can_manage => can_manage,
            edit_url => format!("/dashboard/group-event-types/{}/{}/edit", team_id, slug),
            toggle_url => format!("/dashboard/group-event-types/{}/{}/toggle", team_id, slug),
            delete_url => format!("/dashboard/group-event-types/{}/{}/delete", team_id, slug),
            embed_url => format!("/dashboard/group-event-types/{}/{}/embed", team_id, slug),
            overrides_url => format!("/dashboard/event-types/{}/overrides", slug),
            // Team event types always get a view link — logged-in team members
            // can view private/internal slots without an invite token.
            view_url => Some(format!("/team/{}/{}", team_slug, slug)),
        });
    }

    let (impersonating, impersonating_name, _) = impersonation_ctx(&auth_user);

    Html(
        tmpl.render(context! {
            sidebar => sidebar_context(&auth_user, "event-types"),
            username => user.username,
            all_event_types => all_et_ctx,
            has_any => !event_types.is_empty() || !team_event_types.is_empty(),
            can_create_team_et => can_create_team_et,
            impersonating => impersonating,
            impersonating_name => impersonating_name,
        })
        .unwrap_or_else(|e| internal_error_body("template render", &e)),
    )
}

// --- Dashboard: Bookings ---

async fn dashboard_bookings(
    State(state): State<Arc<AppState>>,
    auth_user: crate::auth::AuthUser,
) -> impl IntoResponse {
    let user = &auth_user.user;

    let pending_bookings: Vec<(
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
    )> = sqlx::query_as(
        "SELECT b.id, b.guest_name, b.guest_email, b.start_at, b.end_at, et.title,
                COALESCE(NULLIF(et.timezone, ''), u.timezone) AS stored_tz,
                COALESCE(NULLIF(b.guest_timezone, ''), 'UTC') AS guest_tz
         FROM bookings b
         JOIN event_types et ON et.id = b.event_type_id
         JOIN accounts a ON a.id = et.account_id
         JOIN users u ON u.id = a.user_id
         WHERE a.user_id = ? AND b.status = 'pending'
         ORDER BY b.start_at",
    )
    .bind(&user.id)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    let upcoming_bookings: Vec<(String, String, String, String, String, String, i32, String, String)> =
        sqlx::query_as(
            "SELECT b.id, b.guest_name, b.guest_email, b.start_at, b.end_at, et.title, b.reschedule_by_host,
                    COALESCE(NULLIF(et.timezone, ''), u.timezone) AS stored_tz,
                    COALESCE(NULLIF(b.guest_timezone, ''), 'UTC') AS guest_tz
         FROM bookings b
         JOIN event_types et ON et.id = b.event_type_id
         JOIN accounts a ON a.id = et.account_id
         JOIN users u ON u.id = a.user_id
         WHERE a.user_id = ? AND b.status = 'confirmed' AND b.start_at >= datetime('now')
         ORDER BY b.start_at
         LIMIT 50",
        )
        .bind(&user.id)
        .fetch_all(&state.pool)
        .await
        .unwrap_or_default();

    // Claimable bookings: unclaimed bookings on event types watched by the user's teams.
    // For team event types et.account_id may be null, so the timezone falls back to the
    // event type's own tz column (always set since migration 046's backfill).
    let claimable_bookings: Vec<(String, String, String, String, String, String, String, String, String, String)> =
        sqlx::query_as(
            "SELECT b.id, b.guest_name, b.guest_email, b.start_at, b.end_at, et.title, t.name, bct.token, \
                    COALESCE(NULLIF(et.timezone, ''), 'UTC') AS stored_tz, \
                    COALESCE(NULLIF(b.guest_timezone, ''), 'UTC') AS guest_tz \
             FROM bookings b \
             JOIN event_types et ON et.id = b.event_type_id \
             JOIN event_type_watchers ew ON ew.event_type_id = et.id \
             JOIN team_members tm ON tm.team_id = ew.team_id \
             JOIN teams t ON t.id = ew.team_id \
             JOIN booking_claim_tokens bct ON bct.booking_id = b.id AND bct.user_id = tm.user_id AND bct.used_at IS NULL \
             WHERE tm.user_id = ? AND b.status = 'confirmed' AND b.claimed_by_user_id IS NULL \
             AND b.start_at >= datetime('now') AND bct.expires_at > datetime('now') \
             ORDER BY b.start_at \
             LIMIT 50",
        )
        .bind(&user.id)
        .fetch_all(&state.pool)
        .await
        .unwrap_or_default();

    let tmpl = match state.templates.get_template("dashboard_bookings.html") {
        Ok(t) => t,
        Err(e) => return internal_error_html("template render", &e),
    };

    let host_tz = &user.timezone;
    let claimable_ctx: Vec<minijinja::Value> = claimable_bookings
        .iter()
        .map(
            |(id, name, email, start, end, title, team_name, token, stored_tz, guest_tz)| {
                let (primary, secondary) =
                    format_booking_for_dashboard(start, end, stored_tz, host_tz, guest_tz);
                context! {
                    id => id,
                    guest_name => name,
                    guest_email => email,
                    start_at => primary,
                    start_at_guest => secondary,
                    event_title => title,
                    team_name => team_name,
                    claim_token => token,
                }
            },
        )
        .collect();

    let pending_ctx: Vec<minijinja::Value> = pending_bookings
        .iter()
        .map(
            |(id, name, email, start, end, title, stored_tz, guest_tz)| {
                let (primary, secondary) =
                    format_booking_for_dashboard(start, end, stored_tz, host_tz, guest_tz);
                context! {
                    id => id,
                    guest_name => name,
                    guest_email => email,
                    start_at => primary,
                    start_at_guest => secondary,
                    event_title => title,
                }
            },
        )
        .collect();

    let bookings_ctx: Vec<minijinja::Value> = upcoming_bookings
        .iter()
        .map(
            |(id, name, email, start, end, title, resched, stored_tz, guest_tz)| {
                let (primary, secondary) =
                    format_booking_for_dashboard(start, end, stored_tz, host_tz, guest_tz);
                context! {
                    id => id,
                    guest_name => name,
                    guest_email => email,
                    start_at => primary,
                    start_at_guest => secondary,
                    event_title => title,
                    awaiting_reschedule => *resched != 0,
                }
            },
        )
        .collect();

    let (impersonating, impersonating_name, _) = impersonation_ctx(&auth_user);

    Html(
        tmpl.render(context! {
            sidebar => sidebar_context(&auth_user, "bookings"),
            pending_bookings => pending_ctx,
            claimable_bookings => claimable_ctx,
            bookings => bookings_ctx,
            impersonating => impersonating,
            impersonating_name => impersonating_name,
        })
        .unwrap_or_else(|e| internal_error_body("template render", &e)),
    )
}

// --- Dashboard: Teams ---

async fn dashboard_teams(
    State(state): State<Arc<AppState>>,
    auth_user: crate::auth::AuthUser,
) -> impl IntoResponse {
    let user = &auth_user.user;
    let is_admin = user.role == "admin";

    // For non-admin users, also fetch which teams they admin
    let teams: Vec<(
        String,
        String,
        String,
        Option<String>,
        String,
        Option<String>,
        Option<String>,
        i64,
    )> = if is_admin {
        sqlx::query_as(
            "SELECT t.id, t.name, t.slug, t.description, t.visibility, t.avatar_path, t.invite_token,
                    (SELECT COUNT(*) FROM team_members tm WHERE tm.team_id = t.id) as member_count
             FROM teams t
             ORDER BY t.name",
        )
        .fetch_all(&state.pool)
        .await
        .unwrap_or_default()
    } else {
        sqlx::query_as(
            "SELECT t.id, t.name, t.slug, t.description, t.visibility, t.avatar_path, t.invite_token,
                    (SELECT COUNT(*) FROM team_members tm WHERE tm.team_id = t.id) as member_count
             FROM teams t
             JOIN team_members tm2 ON tm2.team_id = t.id
             WHERE tm2.user_id = ?
             ORDER BY t.name",
        )
        .bind(&user.id)
        .fetch_all(&state.pool)
        .await
        .unwrap_or_default()
    };

    let member_team_ids: std::collections::HashSet<String> = if is_admin {
        // Global admins can manage all teams
        std::collections::HashSet::new()
    } else {
        let ids: Vec<(String,)> =
            sqlx::query_as("SELECT team_id FROM team_members WHERE user_id = ? AND role = 'admin'")
                .bind(&user.id)
                .fetch_all(&state.pool)
                .await
                .unwrap_or_default();
        ids.into_iter().map(|(id,)| id).collect()
    };

    let tmpl = match state.templates.get_template("dashboard_teams.html") {
        Ok(t) => t,
        Err(e) => return internal_error_html("template render", &e),
    };

    let teams_ctx: Vec<minijinja::Value> = teams
        .iter()
        .map(
            |(id, name, slug, description, visibility, avatar_path, invite_token, member_count)| {
                let initials = name
                    .split_whitespace()
                    .filter_map(|w| w.chars().next())
                    .take(2)
                    .collect::<String>()
                    .to_uppercase();
                let user_is_team_admin = is_admin || member_team_ids.contains(id);
                context! {
                    id => id,
                    name => name,
                    slug => slug,
                    description => description,
                    visibility => visibility,
                    has_avatar => avatar_path.is_some(),
                    initials => initials,
                    member_count => member_count,
                    is_team_admin => user_is_team_admin,
                    invite_token => invite_token,
                }
            },
        )
        .collect();

    let (impersonating, impersonating_name, _) = impersonation_ctx(&auth_user);

    Html(
        tmpl.render(context! {
            sidebar => sidebar_context(&auth_user, "teams"),
            teams => teams_ctx,
            is_admin => is_admin,
            impersonating => impersonating,
            impersonating_name => impersonating_name,
        })
        .unwrap_or_else(|e| internal_error_body("template render", &e)),
    )
}

// --- Team creation form ---

#[derive(Deserialize)]
struct TeamForm {
    _csrf: Option<String>,
    name: String,
    slug: String,
    description: Option<String>,
    visibility: Option<String>,
    #[serde(default)]
    members: String,
    #[serde(default)]
    group_ids: String,
}

/// Split a comma-separated form field into a Vec of non-empty trimmed strings.
fn split_csv_ids(s: &str) -> Vec<String> {
    s.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Parse a dynamic group username string like "alice+bob+carol" into individual usernames.
/// Returns the deduplicated list, or an error if fewer than 2 valid usernames.
/// Parse a numeric form field, defaulting to `default` if empty or invalid.
fn parse_int_field(s: &str, default: i32) -> i32 {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        default
    } else {
        trimmed.parse().unwrap_or(default)
    }
}

fn parse_optional_positive_int(s: &str) -> Option<i32> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        None
    } else {
        trimmed.parse::<i32>().ok().filter(|v| *v > 0)
    }
}

/// Convert a (value, unit) pair from the event type form into a minute count
/// suitable for storage. Returns `None` when the value is blank, zero, or
/// invalid (no restriction). Unit defaults to minutes if missing or unknown.
fn parse_notice_to_minutes(value: &str, unit: &str) -> Option<i32> {
    let v = value.trim();
    if v.is_empty() {
        return None;
    }
    let n: i32 = match v.parse() {
        Ok(n) if n > 0 => n,
        _ => return None,
    };
    let multiplier = match unit.trim() {
        "days" => 1440,
        "hours" => 60,
        _ => 1, // minutes (default)
    };
    n.checked_mul(multiplier).filter(|m| *m > 0)
}

/// Pick the most natural unit for displaying a stored minute value back in
/// the form: divisible by 1440 → days, divisible by 60 → hours, else
/// minutes. Returns `(value, unit)`. Zero / negative / NULL all collapse to
/// `(0, "minutes")` so the form shows an empty restriction.
fn minutes_to_notice_form(min: Option<i32>) -> (i32, &'static str) {
    let m = min.unwrap_or(0);
    if m <= 0 {
        return (0, "minutes");
    }
    if m % 1440 == 0 {
        (m / 1440, "days")
    } else if m % 60 == 0 {
        (m / 60, "hours")
    } else {
        (m, "minutes")
    }
}

fn parse_dynamic_group_usernames(combined: &str) -> Result<Vec<String>, String> {
    let mut seen = std::collections::HashSet::new();
    let unique: Vec<String> = combined
        .split('+')
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .filter(|s| seen.insert(s.clone()))
        .collect();
    if unique.len() < 2 {
        return Err("Dynamic group links require at least two usernames.".to_string());
    }
    Ok(unique)
}

/// Validate that all usernames exist, are enabled, and allow dynamic group links.
/// Returns Vec<(user_id, username, name, email)> in the same order as input.
/// Validate that all usernames exist, are enabled, and allow dynamic group links.
/// Returns Vec<(user_id, username, name, email, avatar_path)> in the same order as input.
async fn validate_dynamic_group_users(
    pool: &SqlitePool,
    usernames: &[String],
) -> Result<Vec<(String, String, String, String, Option<String>)>, String> {
    let mut users = Vec::with_capacity(usernames.len());
    for uname in usernames {
        let row: Option<(String, String, String, String, Option<String>, bool)> = sqlx::query_as(
            "SELECT id, username, name, COALESCE(booking_email, email), avatar_path, allow_dynamic_group FROM users WHERE username = ? AND enabled = 1",
        )
        .bind(uname)
        .fetch_optional(pool)
        .await
        .unwrap_or(None);
        match row {
            None => return Err(format!("User '{}' not found.", uname)),
            Some((_, _, _, _, _, false)) => {
                return Err(format!(
                    "User '{}' has not enabled dynamic group links.",
                    uname
                ))
            }
            Some((id, username, name, email, avatar_path, _)) => {
                users.push((id, username, name, email, avatar_path));
            }
        }
    }
    Ok(users)
}

fn admin_sidebar_context(user: &crate::models::User, active: &str) -> minijinja::Value {
    context! {
        user_name => user.name,
        user_title => user.title.as_deref().unwrap_or(""),
        user_id => user.id,
        user_role => "admin",
        user_timezone => user.timezone,
        has_avatar => user.avatar_path.is_some(),
        user_initials => compute_initials(&user.name),
        active => active,
        version => env!("CARGO_PKG_VERSION"),
    }
}

async fn show_team_form(
    State(state): State<Arc<AppState>>,
    admin: crate::auth::AdminUser,
) -> impl IntoResponse {
    let user = &admin.0;

    // Fetch all enabled users
    let all_users: Vec<(String, String, String, Option<String>)> = sqlx::query_as(
        "SELECT id, name, email, avatar_path FROM users WHERE enabled = 1 ORDER BY name",
    )
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    let users_ctx: Vec<minijinja::Value> = all_users
        .iter()
        .map(|(id, name, email, avatar_path)| {
            context! {
                id => id,
                name => name,
                email => email,
                is_self => id == &user.id,
                has_avatar => avatar_path.is_some(),
                initials => compute_initials(name),
            }
        })
        .collect();

    // Fetch OIDC groups with member details (for stacked avatars)
    let oidc_groups: Vec<(String, String, i64)> = sqlx::query_as(
        "SELECT g.id, g.name, COUNT(ug.user_id) as member_count \
         FROM groups g LEFT JOIN user_groups ug ON ug.group_id = g.id \
         GROUP BY g.id ORDER BY g.name",
    )
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    let groups_ctx =
        build_groups_ctx(&state.pool, &oidc_groups, &std::collections::HashSet::new()).await;

    let tmpl = match state.templates.get_template("team_form.html") {
        Ok(t) => t,
        Err(e) => return internal_error_html("template render", &e),
    };

    Html(
        tmpl.render(context! {
            sidebar => admin_sidebar_context(user, "teams"),
            users => users_ctx,
            oidc_groups => if groups_ctx.is_empty() { None } else { Some(groups_ctx) },
            form_name => "",
            form_slug => "",
            form_description => "",
            form_visibility => "public",
        })
        .unwrap_or_else(|e| internal_error_body("template render", &e)),
    )
}

async fn create_team(
    State(state): State<Arc<AppState>>,
    admin: crate::auth::AdminUser,
    headers: HeaderMap,
    Form(form): Form<TeamForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }
    let user = &admin.0;

    let name = form.name.trim().to_string();
    let slug = form.slug.trim().to_lowercase();
    let description = form
        .description
        .as_deref()
        .map(|d| d.trim().to_string())
        .filter(|d| !d.is_empty());
    let visibility = form.visibility.as_deref().unwrap_or("public");

    // Validate
    if name.is_empty() || slug.is_empty() {
        return render_team_form_error(&state, user, "Name and slug are required.", &form)
            .await
            .into_response();
    }

    if name.len() > 255 {
        return render_team_form_error(&state, user, "Name must be at most 255 characters.", &form)
            .await
            .into_response();
    }

    if let Some(ref d) = description {
        if d.len() > 5000 {
            return render_team_form_error(
                &state,
                user,
                "Description must be at most 5000 characters.",
                &form,
            )
            .await
            .into_response();
        }
    }

    if !slug
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return render_team_form_error(
            &state,
            user,
            "Slug must contain only lowercase letters, numbers, and dashes.",
            &form,
        )
        .await
        .into_response();
    }

    // Check slug against reserved names
    const RESERVED_SLUGS: &[&str] = &["new", "settings", "admin", "api"];
    if RESERVED_SLUGS.contains(&slug.as_str()) {
        return render_team_form_error(
            &state,
            user,
            "This slug is reserved. Please choose a different one.",
            &form,
        )
        .await
        .into_response();
    }

    // Check slug uniqueness
    let existing: Option<String> = sqlx::query_scalar("SELECT id FROM teams WHERE slug = ?")
        .bind(&slug)
        .fetch_optional(&state.pool)
        .await
        .unwrap_or(None);
    if existing.is_some() {
        return render_team_form_error(
            &state,
            user,
            "A team with this slug already exists.",
            &form,
        )
        .await
        .into_response();
    }

    let team_id = uuid::Uuid::new_v4().to_string();
    let invite_token = if visibility == "private" {
        Some(uuid::Uuid::new_v4().to_string())
    } else {
        None
    };

    // Insert team
    let _ = sqlx::query(
        "INSERT INTO teams (id, name, slug, description, visibility, invite_token, created_by) VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&team_id)
    .bind(&name)
    .bind(&slug)
    .bind(&description)
    .bind(visibility)
    .bind(&invite_token)
    .bind(&user.id)
    .execute(&state.pool)
    .await;

    // Add creator as admin member
    let _ = sqlx::query(
        "INSERT INTO team_members (team_id, user_id, role, source) VALUES (?, ?, 'admin', 'direct')",
    )
    .bind(&team_id)
    .bind(&user.id)
    .execute(&state.pool)
    .await;

    // Add selected members (skip creator, already added)
    let member_ids = split_csv_ids(&form.members);
    for member_id in &member_ids {
        if member_id == &user.id {
            continue;
        }
        let _ = sqlx::query(
            "INSERT OR IGNORE INTO team_members (team_id, user_id, role, source) VALUES (?, ?, 'member', 'direct')",
        )
        .bind(&team_id)
        .bind(member_id)
        .execute(&state.pool)
        .await;
    }

    // Link OIDC groups and add their members
    let group_ids = split_csv_ids(&form.group_ids);
    for group_id in &group_ids {
        let _ = sqlx::query("INSERT OR IGNORE INTO team_groups (team_id, group_id) VALUES (?, ?)")
            .bind(&team_id)
            .bind(group_id)
            .execute(&state.pool)
            .await;

        // Add group members to team
        let group_members: Vec<(String,)> =
            sqlx::query_as("SELECT user_id FROM user_groups WHERE group_id = ?")
                .bind(group_id)
                .fetch_all(&state.pool)
                .await
                .unwrap_or_default();

        for (member_user_id,) in &group_members {
            let _ = sqlx::query(
                "INSERT OR IGNORE INTO team_members (team_id, user_id, role, source) VALUES (?, ?, 'member', 'group')",
            )
            .bind(&team_id)
            .bind(member_user_id)
            .execute(&state.pool)
            .await;
        }
    }

    tracing::info!(team_id = %team_id, name = %name, slug = %slug, "Team created");

    Redirect::to("/dashboard/teams").into_response()
}

async fn render_team_form_error(
    state: &AppState,
    user: &crate::models::User,
    error: &str,
    form: &TeamForm,
) -> Html<String> {
    let all_users: Vec<(String, String, String, Option<String>)> = sqlx::query_as(
        "SELECT id, name, email, avatar_path FROM users WHERE enabled = 1 ORDER BY name",
    )
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    let users_ctx: Vec<minijinja::Value> = all_users
        .iter()
        .map(|(id, name, email, avatar_path)| {
            context! {
                id => id,
                name => name,
                email => email,
                is_self => id == &user.id,
                has_avatar => avatar_path.is_some(),
                initials => compute_initials(name),
            }
        })
        .collect();

    let oidc_groups: Vec<(String, String, i64)> = sqlx::query_as(
        "SELECT g.id, g.name, COUNT(ug.user_id) as member_count \
         FROM groups g LEFT JOIN user_groups ug ON ug.group_id = g.id \
         GROUP BY g.id ORDER BY g.name",
    )
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    let groups_ctx =
        build_groups_ctx(&state.pool, &oidc_groups, &std::collections::HashSet::new()).await;

    let tmpl = match state.templates.get_template("team_form.html") {
        Ok(t) => t,
        Err(e) => return internal_error_html("template render", &e),
    };

    Html(
        tmpl.render(context! {
            sidebar => admin_sidebar_context(user, "teams"),
            users => users_ctx,
            oidc_groups => if groups_ctx.is_empty() { None } else { Some(groups_ctx) },
            form_name => &form.name,
            form_slug => &form.slug,
            form_description => form.description.as_deref().unwrap_or(""),
            form_visibility => form.visibility.as_deref().unwrap_or("public"),
            error => error,
        })
        .unwrap_or_else(|e| internal_error_body("template render", &e)),
    )
}

// --- Dashboard: Sources ---

async fn dashboard_organization(
    State(state): State<Arc<AppState>>,
    auth_user: crate::auth::AuthUser,
) -> impl IntoResponse {
    let internal_ets: Vec<(
        String,
        String,
        String,
        i32,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        String,
    )> = sqlx::query_as(
        "SELECT et.id, et.slug, et.title, et.duration_min, u.name,
                u.username,
                CASE WHEN et.team_id IS NOT NULL THEN t.name ELSE NULL END,
                CASE WHEN et.team_id IS NOT NULL THEN t.slug ELSE NULL END,
                et.visibility
         FROM event_types et
         JOIN accounts a ON a.id = et.account_id
         JOIN users u ON u.id = a.user_id
         LEFT JOIN teams t ON t.id = et.team_id
         WHERE et.visibility = 'internal' AND et.enabled = 1
         ORDER BY et.created_at",
    )
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    let ets_ctx: Vec<minijinja::Value> = internal_ets
        .iter()
        .map(
            |(id, slug, title, duration, host_name, username, team_name, team_slug, visibility)| {
                context! {
                    id => id,
                    slug => slug,
                    title => title,
                    duration_min => duration,
                    host_name => host_name,
                    username => username,
                    team_name => team_name,
                    team_slug => team_slug,
                    visibility => visibility,
                }
            },
        )
        .collect();

    let tmpl = match state.templates.get_template("dashboard_internal.html") {
        Ok(t) => t,
        Err(e) => return internal_error_html("template render", &e),
    };

    let (impersonating, impersonating_name, _) = impersonation_ctx(&auth_user);

    Html(
        tmpl.render(context! {
            sidebar => sidebar_context(&auth_user, "organization"),
            event_types => ets_ctx,
            impersonating => impersonating,
            impersonating_name => impersonating_name,
        })
        .unwrap_or_default(),
    )
}

#[derive(Deserialize)]
struct PriorityForm {
    _csrf: Option<String>,
    priority: String,
}

async fn dashboard_sources(
    State(state): State<Arc<AppState>>,
    auth_user: crate::auth::AuthUser,
) -> impl IntoResponse {
    let user = &auth_user.user;

    let sources: Vec<(
        String,
        String,
        String,
        String,
        Option<String>,
        bool,
        Option<String>,
        String,
        String,
    )> = sqlx::query_as(
        "SELECT cs.id, cs.name, cs.url, cs.username, cs.last_synced, cs.enabled, cs.write_calendar_href, cs.auth_type, cs.provider_type
         FROM caldav_sources cs
         JOIN accounts a ON a.id = cs.account_id
         WHERE a.user_id = ?
         ORDER BY cs.created_at",
    )
    .bind(&user.id)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    let all_calendars: Vec<(String, String, Option<String>)> = sqlx::query_as(
        "SELECT c.source_id, c.href, c.display_name
         FROM calendars c
         JOIN caldav_sources cs ON cs.id = c.source_id
         JOIN accounts a ON a.id = cs.account_id
         WHERE a.user_id = ?
         ORDER BY c.display_name",
    )
    .bind(&user.id)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    let sources_ctx: Vec<minijinja::Value> = sources
        .iter()
        .map(
            |(
                id,
                name,
                url,
                username,
                last_synced,
                enabled,
                write_cal,
                auth_type,
                provider_type,
            )| {
                let cals: Vec<minijinja::Value> = all_calendars
                    .iter()
                    .filter(|(sid, _, _)| sid == id)
                    .map(|(_, href, display)| {
                        context! {
                            href => href,
                            name => display.as_deref().unwrap_or(href),
                        }
                    })
                    .collect();
                context! {
                    id => id,
                    id_short => &id[..8.min(id.len())],
                    name => name,
                    url => url,
                    username => username,
                    last_synced => last_synced.as_deref().unwrap_or("never"),
                    enabled => enabled,
                    write_calendar_href => write_cal.as_deref().unwrap_or(""),
                    auth_type => auth_type,
                    provider_type => provider_type,
                    provider_label => crate::providers::factory::label(provider_type),
                    calendars => cals,
                }
            },
        )
        .collect();

    let tmpl = match state.templates.get_template("dashboard_sources.html") {
        Ok(t) => t,
        Err(e) => return internal_error_html("template render", &e),
    };

    let (impersonating, impersonating_name, _) = impersonation_ctx(&auth_user);

    Html(
        tmpl.render(context! {
            sidebar => sidebar_context(&auth_user, "sources"),
            sources => sources_ctx,
            impersonating => impersonating,
            impersonating_name => impersonating_name,
        })
        .unwrap_or_else(|e| internal_error_body("template render", &e)),
    )
}

// --- Settings ---

#[derive(Deserialize)]
struct SettingsForm {
    _csrf: Option<String>,
    name: String,
    username: Option<String>,
    title: Option<String>,
    bio: Option<String>,
    booking_email: Option<String>,
    timezone: Option<String>,
    language: Option<String>,
    allow_dynamic_group: Option<String>,
    #[serde(default)]
    avail_schedule: String,
}

async fn settings_page(
    State(state): State<Arc<AppState>>,
    auth_user: crate::auth::AuthUser,
) -> impl IntoResponse {
    let sidebar = sidebar_context(&auth_user, "settings");
    let (impersonating, impersonating_name, _) = impersonation_ctx(&auth_user);
    ensure_user_avail_seeded(&state.pool, &auth_user.user.id).await;
    let avail = load_user_avail_schedule(&state.pool, &auth_user.user.id).await;
    settings_render(
        &state,
        &auth_user.user,
        None,
        None,
        sidebar,
        impersonating,
        &impersonating_name,
        &avail,
    )
}

/// Convert a user's default availability rules into "busy" times for hours OUTSIDE
/// their available windows. This lets us constrain dynamic group link participants
/// by their working hours without changing the slot computation engine.
/// Convert a user's default availability rules into "busy" times for hours OUTSIDE
/// their available windows. Times are converted from the participant's timezone to
/// the host's timezone so they integrate correctly with the slot computation.
async fn user_avail_as_busy(
    pool: &SqlitePool,
    user_id: &str,
    window_start: NaiveDateTime,
    window_end: NaiveDateTime,
    host_tz: chrono_tz::Tz,
) -> Vec<(NaiveDateTime, NaiveDateTime)> {
    let rules: Vec<(i32, String, String)> = sqlx::query_as(
        "SELECT day_of_week, start_time, end_time FROM user_availability_rules WHERE user_id = ? ORDER BY day_of_week, start_time",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    // No rules = no constraint (user hasn't set default availability)
    if rules.is_empty() {
        return vec![];
    }

    // Get the participant's timezone
    let user_tz_str: String = sqlx::query_scalar("SELECT timezone FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .unwrap_or_else(|_| "UTC".to_string());
    let user_tz: chrono_tz::Tz = user_tz_str.parse().unwrap_or(chrono_tz::Tz::UTC);

    // Work in the participant's timezone: convert window bounds from host TZ to user TZ
    let window_start_user = host_tz
        .from_local_datetime(&window_start)
        .earliest()
        .map(|dt| dt.with_timezone(&user_tz).naive_local())
        .unwrap_or(window_start);
    let window_end_user = host_tz
        .from_local_datetime(&window_end)
        .earliest()
        .map(|dt| dt.with_timezone(&user_tz).naive_local())
        .unwrap_or(window_end);

    let mut busy = Vec::new();
    let mut date = window_start_user.date();
    let end_date = window_end_user.date();
    while date <= end_date {
        let weekday = date.weekday().num_days_from_sunday() as i32;
        let mut windows: Vec<(NaiveTime, NaiveTime)> = rules
            .iter()
            .filter(|(d, _, _)| *d == weekday)
            .filter_map(|(_, s, e)| {
                let start = NaiveTime::parse_from_str(s, "%H:%M").ok()?;
                let end = NaiveTime::parse_from_str(e, "%H:%M").ok()?;
                Some((start, end))
            })
            .collect();
        windows.sort_by_key(|(s, _)| *s);

        if windows.is_empty() {
            // Entire day is unavailable
            let day_start = date.and_hms_opt(0, 0, 0).unwrap();
            let day_end = date.and_hms_opt(23, 59, 59).unwrap();
            busy.push((day_start, day_end));
        } else {
            // Block hours outside available windows
            let day_start = date.and_hms_opt(0, 0, 0).unwrap();
            let first_avail = date.and_time(windows[0].0);
            if first_avail > day_start {
                busy.push((day_start, first_avail));
            }
            for i in 0..windows.len() - 1 {
                let gap_start = date.and_time(windows[i].1);
                let gap_end = date.and_time(windows[i + 1].0);
                if gap_end > gap_start {
                    busy.push((gap_start, gap_end));
                }
            }
            let last_avail_end = date.and_time(windows.last().unwrap().1);
            let day_end = date.and_hms_opt(23, 59, 59).unwrap();
            if day_end > last_avail_end {
                busy.push((last_avail_end, day_end));
            }
        }
        date = date.succ_opt().unwrap_or(date);
    }

    // Convert busy times from participant's TZ back to host's TZ
    busy.into_iter()
        .filter_map(|(start, end)| {
            let start_host = user_tz
                .from_local_datetime(&start)
                .earliest()
                .map(|dt| dt.with_timezone(&host_tz).naive_local())?;
            let end_host = user_tz
                .from_local_datetime(&end)
                .earliest()
                .map(|dt| dt.with_timezone(&host_tz).naive_local())?;
            Some((start_host, end_host))
        })
        .collect()
}

/// Load a user's default availability rules as a serialized schedule string.
/// Format: "1:09:00-17:00;2:09:00-12:00,13:00-17:00" (day:start-end,start-end;...)
async fn load_user_avail_schedule(pool: &SqlitePool, user_id: &str) -> String {
    let rules: Vec<(i32, String, String)> = sqlx::query_as(
        "SELECT day_of_week, start_time, end_time FROM user_availability_rules WHERE user_id = ? ORDER BY day_of_week, start_time",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let mut parts = Vec::new();
    let mut current_day: Option<i32> = None;
    let mut windows = Vec::new();
    for (day, start, end) in &rules {
        if current_day != Some(*day) {
            if let Some(d) = current_day {
                parts.push(format!("{}:{}", d, windows.join(",")));
            }
            current_day = Some(*day);
            windows.clear();
        }
        windows.push(format!("{}-{}", start, end));
    }
    if let Some(d) = current_day {
        parts.push(format!("{}:{}", d, windows.join(",")));
    }
    parts.join(";")
}

/// Save a user's default availability rules from a serialized schedule string.
async fn save_user_avail_schedule(pool: &SqlitePool, user_id: &str, schedule: &str) {
    // Delete existing rules
    let _ = sqlx::query("DELETE FROM user_availability_rules WHERE user_id = ?")
        .bind(user_id)
        .execute(pool)
        .await;

    // Parse and insert new rules
    for seg in schedule.split(';') {
        let seg = seg.trim();
        if seg.is_empty() {
            continue;
        }
        let parts: Vec<&str> = seg.splitn(2, ':').collect();
        if parts.len() < 2 {
            continue;
        }
        let day: i32 = match parts[0].parse() {
            Ok(d) if (0..=6).contains(&d) => d,
            _ => continue,
        };
        for window in parts[1].split(',') {
            let times: Vec<&str> = window.trim().split('-').collect();
            if times.len() != 2 {
                continue;
            }
            let id = uuid::Uuid::new_v4().to_string();
            let _ = sqlx::query(
                "INSERT INTO user_availability_rules (id, user_id, day_of_week, start_time, end_time) VALUES (?, ?, ?, ?, ?)",
            )
            .bind(&id)
            .bind(user_id)
            .bind(day)
            .bind(times[0].trim())
            .bind(times[1].trim())
            .execute(pool)
            .await;
        }
    }
}

/// Ensure a user has default availability rules. If none exist, insert Mon-Fri 9:00-17:00.
async fn ensure_user_avail_seeded(pool: &SqlitePool, user_id: &str) {
    let count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM user_availability_rules WHERE user_id = ?")
            .bind(user_id)
            .fetch_one(pool)
            .await
            .unwrap_or((0,));
    if count.0 > 0 {
        return;
    }
    // Seed Mon(1)-Fri(5) 09:00-17:00
    for day in 1..=5 {
        let id = uuid::Uuid::new_v4().to_string();
        let _ = sqlx::query(
            "INSERT INTO user_availability_rules (id, user_id, day_of_week, start_time, end_time) VALUES (?, ?, ?, '09:00', '17:00')",
        )
        .bind(&id)
        .bind(user_id)
        .bind(day)
        .execute(pool)
        .await;
    }
}

/// Returns the authenticated user's profile-default availability schedule
/// as JSON. Used by the event-type form's "Reset to my default" button.
async fn dashboard_availability_default(
    State(state): State<Arc<AppState>>,
    auth_user: crate::auth::AuthUser,
) -> impl IntoResponse {
    ensure_user_avail_seeded(&state.pool, &auth_user.user.id).await;
    let schedule = load_user_avail_schedule(&state.pool, &auth_user.user.id).await;
    axum::Json(serde_json::json!({ "schedule": schedule }))
}

fn settings_render(
    state: &AppState,
    user: &crate::models::User,
    success: Option<&str>,
    error: Option<&str>,
    sidebar: minijinja::Value,
    impersonating: bool,
    impersonating_name: &str,
    avail_schedule: &str,
) -> Html<String> {
    let tmpl = match state.templates.get_template("settings.html") {
        Ok(t) => t,
        Err(e) => return internal_error_html("internal", &e),
    };
    let tz_options: Vec<minijinja::Value> = common_timezones_with("")
        .iter()
        .map(|(iana, label)| {
            context! { value => iana, label => label }
        })
        .collect();
    let lang_options: Vec<minijinja::Value> = crate::i18n::supported_with_labels()
        .map(|(code, label)| context! { value => code, label => label })
        .collect();
    Html(
        tmpl.render(context! {
            sidebar => sidebar,
            form_name => user.name,
            form_initials => compute_initials(&user.name),
            form_title => user.title.as_deref().unwrap_or(""),
            form_bio => user.bio.as_deref().unwrap_or(""),
            form_booking_email => user.booking_email.as_deref().unwrap_or(""),
            form_timezone => user.timezone,
            tz_options => tz_options,
            form_language => user.language.as_deref().unwrap_or(""),
            lang_options => lang_options,
            user_email => user.email,
            user_id => user.id,
            has_avatar => user.avatar_path.is_some(),
            username => user.username.as_deref().unwrap_or(""),
            allow_dynamic_group => user.allow_dynamic_group,
            form_avail_schedule => avail_schedule,
            success => success.unwrap_or(""),
            error => error.unwrap_or(""),
            impersonating => impersonating,
            impersonating_name => impersonating_name,
        })
        .unwrap_or_else(|e| internal_error_body("template render", &e)),
    )
}

async fn settings_save(
    State(state): State<Arc<AppState>>,
    auth_user: crate::auth::AuthUser,
    headers: HeaderMap,
    Form(form): Form<SettingsForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }
    let user = &auth_user.user;
    let name = form.name.trim().to_string();
    let sidebar = sidebar_context(&auth_user, "settings");
    let (imp, imp_name, _) = impersonation_ctx(&auth_user);

    if name.is_empty() || name.len() > 255 {
        return settings_render(
            &state,
            user,
            None,
            Some("Name must be between 1 and 255 characters."),
            sidebar,
            imp,
            &imp_name,
            &form.avail_schedule,
        )
        .into_response();
    }

    // Validate and update username if provided
    let new_username = form
        .username
        .as_deref()
        .map(|s| {
            s.trim()
                .to_lowercase()
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
                .take(100)
                .collect::<String>()
        })
        .filter(|s| !s.is_empty());

    if let Some(ref uname) = new_username {
        if uname.len() < 2 {
            return settings_render(
                &state,
                user,
                None,
                Some("Username must be at least 2 characters."),
                sidebar,
                imp,
                &imp_name,
                &form.avail_schedule,
            )
            .into_response();
        }
        // Check uniqueness (only if different from current)
        if user.username.as_deref() != Some(uname.as_str()) {
            let taken: Option<(String,)> =
                sqlx::query_as("SELECT id FROM users WHERE username = ? AND id != ?")
                    .bind(uname)
                    .bind(&user.id)
                    .fetch_optional(&state.pool)
                    .await
                    .unwrap_or(None);
            if taken.is_some() {
                return settings_render(
                    &state,
                    user,
                    None,
                    Some("This username is already taken."),
                    sidebar,
                    imp,
                    &imp_name,
                    &form.avail_schedule,
                )
                .into_response();
            }
            let _ = sqlx::query("UPDATE users SET username = ? WHERE id = ?")
                .bind(uname)
                .bind(&user.id)
                .execute(&state.pool)
                .await;
        }
    }

    let title = form
        .title
        .as_deref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    let bio = form
        .bio
        .as_deref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    let booking_email = form
        .booking_email
        .as_deref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    if let Some(ref be) = booking_email {
        if be.len() > 255
            || !be.contains('@')
            || be
                .rsplit('@')
                .next()
                .is_none_or(|domain| !domain.contains('.'))
        {
            return settings_render(
                &state,
                user,
                None,
                Some("Please enter a valid booking email address."),
                sidebar,
                imp,
                &imp_name,
                &form.avail_schedule,
            )
            .into_response();
        }
    }

    let timezone = form
        .timezone
        .as_deref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty() && s.parse::<chrono_tz::Tz>().is_ok())
        .unwrap_or("UTC")
        .to_string();

    // Empty / "auto" / unsupported codes all map to NULL = follow Accept-Language.
    let language: Option<String> = form
        .language
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty() && *s != "auto")
        .filter(|s| crate::i18n::is_supported(s))
        .map(str::to_string);

    let allow_dynamic_group = form.allow_dynamic_group.as_deref() == Some("on");

    let result = sqlx::query(
        "UPDATE users SET name = ?, title = ?, bio = ?, booking_email = ?, timezone = ?, language = ?, allow_dynamic_group = ?, updated_at = datetime('now') WHERE id = ?",
    )
    .bind(&name)
    .bind(&title)
    .bind(&bio)
    .bind(&booking_email)
    .bind(&timezone)
    .bind(&language)
    .bind(allow_dynamic_group)
    .bind(&user.id)
    .execute(&state.pool)
    .await;

    match result {
        Ok(_) => {
            // Also update the linked account name
            let _ = sqlx::query("UPDATE accounts SET name = ? WHERE user_id = ?")
                .bind(&name)
                .bind(&user.id)
                .execute(&state.pool)
                .await;

            // Save default availability schedule
            save_user_avail_schedule(&state.pool, &user.id, &form.avail_schedule).await;

            // Re-fetch user to show updated values
            let updated_user = crate::auth::get_user_by_id(&state.pool, &user.id)
                .await
                .unwrap_or_else(|| user.clone());
            let sidebar = sidebar_context(&auth_user, "settings");
            settings_render(
                &state,
                &updated_user,
                Some("Settings saved."),
                None,
                sidebar,
                imp,
                &imp_name,
                &form.avail_schedule,
            )
            .into_response()
        }
        Err(_) => settings_render(
            &state,
            user,
            None,
            Some("Failed to save settings."),
            sidebar,
            imp,
            &imp_name,
            &form.avail_schedule,
        )
        .into_response(),
    }
}

// --- Quick timezone update (from banner) ---

#[derive(Deserialize)]
struct TimezoneUpdateForm {
    timezone: String,
}

async fn update_timezone(
    State(state): State<Arc<AppState>>,
    auth_user: crate::auth::AuthUser,
    headers: HeaderMap,
    axum::Json(form): axum::Json<TimezoneUpdateForm>,
) -> impl IntoResponse {
    let csrf = headers
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if let Err(resp) = verify_csrf_token(&headers, &Some(csrf.to_string())) {
        return resp;
    }
    let tz = form.timezone.trim();
    if tz.parse::<chrono_tz::Tz>().is_err() {
        return (axum::http::StatusCode::BAD_REQUEST, "Invalid timezone").into_response();
    }
    let _ = sqlx::query("UPDATE users SET timezone = ?, updated_at = datetime('now') WHERE id = ?")
        .bind(tz)
        .bind(&auth_user.user.id)
        .execute(&state.pool)
        .await;
    tracing::info!(user_id = %auth_user.user.id, timezone = %tz, "timezone updated from banner");
    (axum::http::StatusCode::OK, "OK").into_response()
}

// --- Avatar upload/serve/delete ---

/// Detect an image format by its magic bytes. Returns the canonical file
/// extension (without leading dot) or None if the bytes don't match a
/// supported format. The Content-Type from the multipart header is
/// attacker-controlled, so we validate the actual file contents instead.
fn detect_image_ext(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) {
        Some("png")
    } else if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Some("jpg")
    } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        Some("gif")
    } else if bytes.len() >= 12 && &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        Some("webp")
    } else {
        None
    }
}

async fn upload_avatar(
    State(state): State<Arc<AppState>>,
    auth_user: crate::auth::AuthUser,
    headers: HeaderMap,
    Query(csrf_query): Query<CsrfQuery>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &csrf_query._csrf) {
        return resp;
    }
    let user = &auth_user.user;
    while let Ok(Some(field)) = multipart.next_field().await {
        if field.name() == Some("avatar") {
            let content_type = field.content_type().unwrap_or("").to_string();
            if !content_type.starts_with("image/") {
                return Redirect::to("/dashboard/settings").into_response();
            }
            if let Ok(bytes) = field.bytes().await {
                if bytes.len() > 2 * 1024 * 1024 {
                    return Redirect::to("/dashboard/settings").into_response();
                }
                // Trust magic bytes, not the multipart Content-Type header.
                let ext = match detect_image_ext(&bytes) {
                    Some(e) => e,
                    None => return Redirect::to("/dashboard/settings").into_response(),
                };
                let avatars_dir = state.data_dir.join("avatars");
                let _ = tokio::fs::create_dir_all(&avatars_dir).await;
                let filename = format!("{}.{}", user.id, ext);
                let avatar_path = avatars_dir.join(&filename);

                // Remove old avatar if different extension
                if let Some(old_path) = &user.avatar_path {
                    let old_full = state.data_dir.join("avatars").join(old_path);
                    if old_full != avatar_path {
                        let _ = tokio::fs::remove_file(&old_full).await;
                    }
                }

                if tokio::fs::write(&avatar_path, &bytes).await.is_ok() {
                    let _ = sqlx::query(
                        "UPDATE users SET avatar_path = ?, updated_at = datetime('now') WHERE id = ?",
                    )
                    .bind(&filename)
                    .bind(&user.id)
                    .execute(&state.pool)
                    .await;
                }
            }
        }
    }
    Redirect::to("/dashboard/settings").into_response()
}

async fn delete_avatar(
    State(state): State<Arc<AppState>>,
    auth_user: crate::auth::AuthUser,
    headers: HeaderMap,
    Form(csrf): Form<CsrfForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &csrf._csrf) {
        return resp;
    }
    let user = &auth_user.user;
    if let Some(avatar_path) = &user.avatar_path {
        let full_path = state.data_dir.join("avatars").join(avatar_path);
        let _ = tokio::fs::remove_file(&full_path).await;
    }
    let _ = sqlx::query(
        "UPDATE users SET avatar_path = NULL, updated_at = datetime('now') WHERE id = ?",
    )
    .bind(&user.id)
    .execute(&state.pool)
    .await;
    Redirect::to("/dashboard/settings").into_response()
}

async fn serve_avatar(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<String>,
) -> impl IntoResponse {
    let avatar_path: Option<(String,)> =
        sqlx::query_as("SELECT avatar_path FROM users WHERE id = ? AND avatar_path IS NOT NULL")
            .bind(&user_id)
            .fetch_optional(&state.pool)
            .await
            .unwrap_or(None);

    let filename = match avatar_path {
        Some((f,)) => f,
        None => return (axum::http::StatusCode::NOT_FOUND, "").into_response(),
    };

    let full_path = state.data_dir.join("avatars").join(&filename);
    match tokio::fs::read(&full_path).await {
        Ok(bytes) => {
            let content_type = if filename.ends_with(".jpg") || filename.ends_with(".jpeg") {
                "image/jpeg"
            } else if filename.ends_with(".png") {
                "image/png"
            } else if filename.ends_with(".gif") {
                "image/gif"
            } else if filename.ends_with(".webp") {
                "image/webp"
            } else {
                "image/png"
            };
            axum::response::Response::builder()
                .status(200)
                .header("Content-Type", content_type)
                .header("Cache-Control", "public, max-age=3600")
                .body(axum::body::Body::from(bytes))
                .unwrap_or_else(|_| axum::response::Response::new(axum::body::Body::empty()))
                .into_response()
        }
        Err(_) => (axum::http::StatusCode::NOT_FOUND, "").into_response(),
    }
}

// --- Team settings & avatar ---

async fn is_team_member(pool: &SqlitePool, user_id: &str, team_id: &str) -> bool {
    sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM team_members WHERE user_id = ? AND team_id = ?",
    )
    .bind(user_id)
    .bind(team_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0)
        > 0
}

/// Check if a user has team-admin role for a specific team.
async fn is_team_admin(pool: &SqlitePool, user_id: &str, team_id: &str) -> bool {
    sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM team_members WHERE user_id = ? AND team_id = ? AND role = 'admin'",
    )
    .bind(user_id)
    .bind(team_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0)
        > 0
}

/// Single source of truth for "is this user allowed to manage this event type?"
/// Policy:
///   - Global admin: always yes.
///   - Personal event type (team_id IS NULL): account owner only.
///   - Team event type: team admin only (regular members cannot mutate).
///
/// Takes an event_type_id (not slug) to avoid slug-collision ambiguity.
async fn can_manage_event_type(
    pool: &SqlitePool,
    user: &crate::models::User,
    event_type_id: &str,
) -> bool {
    if user.role == "admin" {
        return true;
    }
    sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM event_types et
         LEFT JOIN accounts a ON a.id = et.account_id
         LEFT JOIN team_members tm ON tm.team_id = et.team_id AND tm.user_id = ? AND tm.role = 'admin'
         WHERE et.id = ? AND (
             (et.team_id IS NULL AND a.user_id = ?) OR
             (et.team_id IS NOT NULL AND tm.user_id IS NOT NULL)
         )",
    )
    .bind(&user.id)
    .bind(event_type_id)
    .bind(&user.id)
    .fetch_one(pool)
    .await
    .unwrap_or(0)
        > 0
}

/// Look up an event type by slug that the (non-admin) user is allowed to
/// manage. Personal events resolve via the account owner; team events resolve
/// via team admin role. Global admins should bypass this and look up by slug
/// directly. Returns (id, title, team_id).
///
/// If the user has both a personal event and a team event with the same slug,
/// the personal event wins. Branch order in `UNION ALL` is not guaranteed by
/// SQL, so we wrap it in a subquery and order by `team_id IS NULL DESC`
/// (i.e. NULLs first → personal first) to make the resolution deterministic.
async fn find_manageable_event_type_by_slug(
    pool: &SqlitePool,
    user_id: &str,
    slug: &str,
) -> Option<(String, String, Option<String>)> {
    sqlx::query_as(
        "SELECT id, title, team_id FROM (
             SELECT et.id, et.title, et.team_id FROM event_types et
             JOIN accounts a ON a.id = et.account_id
             WHERE a.user_id = ? AND et.slug = ? AND et.team_id IS NULL
             UNION ALL
             SELECT et.id, et.title, et.team_id FROM event_types et
             JOIN team_members tm ON tm.team_id = et.team_id
             WHERE tm.user_id = ? AND tm.role = 'admin' AND et.slug = ? AND et.team_id IS NOT NULL
         )
         ORDER BY (team_id IS NULL) DESC
         LIMIT 1",
    )
    .bind(user_id)
    .bind(slug)
    .bind(user_id)
    .bind(slug)
    .fetch_optional(pool)
    .await
    .unwrap_or(None)
}

#[derive(Deserialize)]
struct GroupSettingsForm {
    _csrf: Option<String>,
    name: Option<String>,
    slug: Option<String>,
    description: Option<String>,
    visibility: Option<String>,
    #[serde(default)]
    members: String,
    #[serde(default)]
    group_ids: String,
    #[serde(default)]
    admin_members: String,
}

async fn team_settings_page(
    State(state): State<Arc<AppState>>,
    auth_user: crate::auth::AuthUser,
    Path(team_id): Path<String>,
    Query(query): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let user = &auth_user.user;
    let is_admin = user.role == "admin";
    if !is_admin && !is_team_admin(&state.pool, &user.id, &team_id).await {
        return Html("Team not found or you are not a team admin.".to_string());
    }

    let team: Option<(String, String, String, Option<String>, Option<String>, String, Option<String>)> =
        sqlx::query_as("SELECT id, name, slug, description, avatar_path, visibility, invite_token FROM teams WHERE id = ?")
            .bind(&team_id)
            .fetch_optional(&state.pool)
            .await
            .unwrap_or(None);

    let (tid, team_name, team_slug, description, avatar_path, visibility, invite_token) = match team
    {
        Some(t) => t,
        None => return Html("Team not found.".to_string()),
    };

    let members: Vec<(String, String, Option<String>, String, String)> = sqlx::query_as(
        "SELECT u.id, u.name, u.avatar_path, tm.role, tm.source FROM users u \
         JOIN team_members tm ON tm.user_id = u.id \
         WHERE tm.team_id = ? AND u.enabled = 1 \
         ORDER BY u.name",
    )
    .bind(&tid)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    let members_ctx: Vec<minijinja::Value> = members
        .iter()
        .map(|(id, name, ap, role, source)| {
            context! {
                id => id,
                name => name,
                has_avatar => ap.is_some(),
                initials => compute_initials(name),
                role => role,
                source => source,
            }
        })
        .collect();

    // All enabled users for the member picker
    let all_users: Vec<(String, String, String, Option<String>)> = sqlx::query_as(
        "SELECT id, name, email, avatar_path FROM users WHERE enabled = 1 ORDER BY name",
    )
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    let member_ids: std::collections::HashSet<&str> =
        members.iter().map(|(id, _, _, _, _)| id.as_str()).collect();

    let all_users_ctx: Vec<minijinja::Value> = all_users
        .iter()
        .map(|(id, name, email, avatar_path)| {
            context! {
                id => id,
                name => name,
                email => email,
                has_avatar => avatar_path.is_some(),
                initials => compute_initials(name),
                is_member => member_ids.contains(id.as_str()),
            }
        })
        .collect();

    // OIDC groups with member counts + linked status
    let oidc_groups: Vec<(String, String, i64)> = sqlx::query_as(
        "SELECT g.id, g.name, COUNT(ug.user_id) as member_count \
         FROM groups g LEFT JOIN user_groups ug ON ug.group_id = g.id \
         GROUP BY g.id ORDER BY g.name",
    )
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    let linked_group_ids: Vec<(String,)> =
        sqlx::query_as("SELECT group_id FROM team_groups WHERE team_id = ?")
            .bind(&tid)
            .fetch_all(&state.pool)
            .await
            .unwrap_or_default();
    let linked_set: std::collections::HashSet<String> =
        linked_group_ids.into_iter().map(|(id,)| id).collect();

    let groups_ctx = build_groups_ctx(&state.pool, &oidc_groups, &linked_set).await;

    let linked_groups_only: Vec<(String, String, i64)> = oidc_groups
        .iter()
        .filter(|(id, _, _)| linked_set.contains(id))
        .cloned()
        .collect();
    let linked_groups_ctx = build_groups_ctx(
        &state.pool,
        &linked_groups_only,
        &std::collections::HashSet::new(),
    )
    .await;

    let tmpl = match state.templates.get_template("team_settings.html") {
        Ok(t) => t,
        Err(e) => return internal_error_html("template render", &e),
    };

    Html(
        tmpl.render(context! {
            sidebar => sidebar_context(&auth_user, "teams"),
            team_id => tid,
            team_name => team_name,
            team_slug => team_slug,
            team_description => description.unwrap_or_default(),
            team_has_avatar => avatar_path.is_some(),
            team_initials => compute_initials(&team_name),
            visibility => visibility,
            invite_token => invite_token,
            members => members_ctx,
            all_users => all_users_ctx,
            oidc_groups => if groups_ctx.is_empty() { None } else { Some(groups_ctx) },
            linked_groups => linked_groups_ctx,
            success => query.get("success").map(|_| "Settings saved."),
        })
        .unwrap_or_else(|e| internal_error_body("template render", &e)),
    )
}

async fn team_settings_save(
    State(state): State<Arc<AppState>>,
    auth_user: crate::auth::AuthUser,
    headers: HeaderMap,
    Path(team_id): Path<String>,
    Form(form): Form<GroupSettingsForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }
    let user = &auth_user.user;
    let is_admin = user.role == "admin";
    if !is_admin && !is_team_admin(&state.pool, &user.id, &team_id).await {
        return Redirect::to("/dashboard/event-types").into_response();
    }
    // Update name if provided
    if let Some(ref name) = form.name {
        let name = name.trim().chars().take(255).collect::<String>();
        if !name.is_empty() {
            let _ = sqlx::query("UPDATE teams SET name = ? WHERE id = ?")
                .bind(&name)
                .bind(&team_id)
                .execute(&state.pool)
                .await;
        }
    }

    // Update slug if provided (validate format and uniqueness)
    if let Some(ref slug) = form.slug {
        let slug = slug
            .trim()
            .to_lowercase()
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
            .take(100)
            .collect::<String>();
        if !slug.is_empty() {
            let conflict: Option<(String,)> =
                sqlx::query_as("SELECT id FROM teams WHERE slug = ? AND id != ?")
                    .bind(&slug)
                    .bind(&team_id)
                    .fetch_optional(&state.pool)
                    .await
                    .unwrap_or(None);
            if conflict.is_none() {
                let _ = sqlx::query("UPDATE teams SET slug = ? WHERE id = ?")
                    .bind(&slug)
                    .bind(&team_id)
                    .execute(&state.pool)
                    .await;
            }
        }
    }

    let desc = form
        .description
        .as_deref()
        .unwrap_or("")
        .trim()
        .chars()
        .take(5000)
        .collect::<String>();
    let desc = if desc.is_empty() { None } else { Some(desc) };
    let _ = sqlx::query("UPDATE teams SET description = ? WHERE id = ?")
        .bind(&desc)
        .bind(&team_id)
        .execute(&state.pool)
        .await;

    // Update visibility if provided
    if let Some(ref vis) = form.visibility {
        let vis = vis.trim();
        if vis == "public" || vis == "private" {
            let _ = sqlx::query("UPDATE teams SET visibility = ? WHERE id = ?")
                .bind(vis)
                .bind(&team_id)
                .execute(&state.pool)
                .await;
            // Generate invite token when switching to private (if none exists)
            if vis == "private" {
                let existing: Option<(Option<String>,)> =
                    sqlx::query_as("SELECT invite_token FROM teams WHERE id = ?")
                        .bind(&team_id)
                        .fetch_optional(&state.pool)
                        .await
                        .unwrap_or(None);
                if existing.map(|(t,)| t.is_none()).unwrap_or(true) {
                    let token = uuid::Uuid::new_v4().to_string();
                    let _ = sqlx::query("UPDATE teams SET invite_token = ? WHERE id = ?")
                        .bind(&token)
                        .bind(&team_id)
                        .execute(&state.pool)
                        .await;
                }
            }
        }
    }

    // Sync direct members (preserve group-synced members).
    // The hidden input is always present (populated by JS). An empty value means
    // either "remove all direct members" (valid for global admins) or JS failure.
    // We proceed either way — the safety net below re-adds non-admin users.
    let member_ids = split_csv_ids(&form.members);
    // 1. Remove direct members not in the submitted list
    let _ = sqlx::query(
        "DELETE FROM team_members WHERE team_id = ? AND source = 'direct' AND user_id NOT IN \
         (SELECT value FROM json_each(?))",
    )
    .bind(&team_id)
    .bind(serde_json::to_string(&member_ids).unwrap_or_else(|_| "[]".to_string()))
    .execute(&state.pool)
    .await;

    // 2. Add new direct members (INSERT OR IGNORE to not conflict with group-synced)
    for member_id in &member_ids {
        let _ = sqlx::query(
            "INSERT OR IGNORE INTO team_members (team_id, user_id, role, source) VALUES (?, ?, 'member', 'direct')",
        )
        .bind(&team_id)
        .bind(member_id)
        .execute(&state.pool)
        .await;
    }

    // 3. Update member roles based on admin_members list
    let admin_ids: std::collections::HashSet<String> =
        split_csv_ids(&form.admin_members).into_iter().collect();
    // Set all members to 'member' first, then promote admins
    let _ = sqlx::query("UPDATE team_members SET role = 'member' WHERE team_id = ?")
        .bind(&team_id)
        .execute(&state.pool)
        .await;
    for admin_id in &admin_ids {
        let _ =
            sqlx::query("UPDATE team_members SET role = 'admin' WHERE team_id = ? AND user_id = ?")
                .bind(&team_id)
                .bind(admin_id)
                .execute(&state.pool)
                .await;
    }

    // Ensure at least one admin remains. Global admins can remove themselves
    // (they can still manage the team via the admin panel).
    if !is_admin {
        // Re-ensure the current user stays as admin
        let _ =
            sqlx::query("UPDATE team_members SET role = 'admin' WHERE team_id = ? AND user_id = ?")
                .bind(&team_id)
                .bind(&user.id)
                .execute(&state.pool)
                .await;
        // Also ensure they remain a member (INSERT OR IGNORE in case they were removed)
        let _ = sqlx::query(
            "INSERT OR IGNORE INTO team_members (team_id, user_id, role, source) VALUES (?, ?, 'admin', 'direct')",
        )
        .bind(&team_id)
        .bind(&user.id)
        .execute(&state.pool)
        .await;
    }

    // Sync linked OIDC groups
    let group_ids = split_csv_ids(&form.group_ids);
    // 1. Remove unlinked groups
    let _ = sqlx::query(
        "DELETE FROM team_groups WHERE team_id = ? AND group_id NOT IN \
         (SELECT value FROM json_each(?))",
    )
    .bind(&team_id)
    .bind(serde_json::to_string(&group_ids).unwrap_or_else(|_| "[]".to_string()))
    .execute(&state.pool)
    .await;

    // 2. Add newly linked groups and their members
    for gid in &group_ids {
        let _ = sqlx::query("INSERT OR IGNORE INTO team_groups (team_id, group_id) VALUES (?, ?)")
            .bind(&team_id)
            .bind(gid)
            .execute(&state.pool)
            .await;

        // Add group members as team members with source='group'
        let group_members: Vec<(String,)> =
            sqlx::query_as("SELECT user_id FROM user_groups WHERE group_id = ?")
                .bind(gid)
                .fetch_all(&state.pool)
                .await
                .unwrap_or_default();
        for (uid,) in &group_members {
            let _ = sqlx::query(
                "INSERT OR IGNORE INTO team_members (team_id, user_id, role, source) VALUES (?, ?, 'member', 'group')",
            )
            .bind(&team_id)
            .bind(uid)
            .execute(&state.pool)
            .await;
        }
    }

    // 3. Remove group-sourced members whose groups are no longer linked
    let _ = sqlx::query(
        "DELETE FROM team_members WHERE team_id = ? AND source = 'group' \
         AND user_id NOT IN (SELECT ug.user_id FROM user_groups ug \
         JOIN team_groups tg ON tg.group_id = ug.group_id WHERE tg.team_id = ?)",
    )
    .bind(&team_id)
    .bind(&team_id)
    .execute(&state.pool)
    .await;

    tracing::info!(team_id = %team_id, user_id = %user.id, "team settings updated");
    Redirect::to(&format!("/dashboard/teams/{}/settings?success=1", team_id)).into_response()
}

async fn upload_team_avatar(
    State(state): State<Arc<AppState>>,
    auth_user: crate::auth::AuthUser,
    headers: HeaderMap,
    Path(team_id): Path<String>,
    Query(csrf_query): Query<CsrfQuery>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &csrf_query._csrf) {
        return resp;
    }
    let user = &auth_user.user;
    let is_admin = user.role == "admin";
    if !is_admin && !is_team_admin(&state.pool, &user.id, &team_id).await {
        return Redirect::to("/dashboard/event-types").into_response();
    }
    let redirect_url = format!("/dashboard/teams/{}/settings", team_id);
    while let Ok(Some(field)) = multipart.next_field().await {
        if field.name() == Some("avatar") {
            let content_type = field.content_type().unwrap_or("").to_string();
            if !content_type.starts_with("image/") {
                return Redirect::to(&redirect_url).into_response();
            }
            if let Ok(bytes) = field.bytes().await {
                if bytes.len() > 2 * 1024 * 1024 {
                    return Redirect::to(&redirect_url).into_response();
                }
                // Trust magic bytes, not the multipart Content-Type header.
                let ext = match detect_image_ext(&bytes) {
                    Some(e) => e,
                    None => return Redirect::to(&redirect_url).into_response(),
                };
                let avatars_dir = state.data_dir.join("avatars");
                let _ = tokio::fs::create_dir_all(&avatars_dir).await;
                let filename = format!("team_{}.{}", team_id, ext);
                let avatar_path = avatars_dir.join(&filename);

                // Remove old avatar if different extension
                let old: Option<(String,)> = sqlx::query_as(
                    "SELECT avatar_path FROM teams WHERE id = ? AND avatar_path IS NOT NULL",
                )
                .bind(&team_id)
                .fetch_optional(&state.pool)
                .await
                .unwrap_or(None);
                if let Some((old_name,)) = old {
                    let old_full = avatars_dir.join(&old_name);
                    if old_full != avatar_path {
                        let _ = tokio::fs::remove_file(&old_full).await;
                    }
                }

                if tokio::fs::write(&avatar_path, &bytes).await.is_ok() {
                    let _ = sqlx::query("UPDATE teams SET avatar_path = ? WHERE id = ?")
                        .bind(&filename)
                        .bind(&team_id)
                        .execute(&state.pool)
                        .await;
                    tracing::info!(team_id = %team_id, user_id = %user.id, "team avatar uploaded");
                }
            }
        }
    }
    Redirect::to(&redirect_url).into_response()
}

async fn delete_team_avatar(
    State(state): State<Arc<AppState>>,
    auth_user: crate::auth::AuthUser,
    headers: HeaderMap,
    Path(team_id): Path<String>,
    Form(csrf): Form<CsrfForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &csrf._csrf) {
        return resp;
    }
    let user = &auth_user.user;
    let is_admin = user.role == "admin";
    if !is_admin && !is_team_admin(&state.pool, &user.id, &team_id).await {
        return Redirect::to("/dashboard/event-types").into_response();
    }
    let old: Option<(String,)> =
        sqlx::query_as("SELECT avatar_path FROM teams WHERE id = ? AND avatar_path IS NOT NULL")
            .bind(&team_id)
            .fetch_optional(&state.pool)
            .await
            .unwrap_or(None);
    if let Some((avatar_path,)) = old {
        let full_path = state.data_dir.join("avatars").join(&avatar_path);
        let _ = tokio::fs::remove_file(&full_path).await;
    }
    let _ = sqlx::query("UPDATE teams SET avatar_path = NULL WHERE id = ?")
        .bind(&team_id)
        .execute(&state.pool)
        .await;
    tracing::info!(team_id = %team_id, user_id = %user.id, "team avatar deleted");
    Redirect::to(&format!("/dashboard/teams/{}/settings", team_id)).into_response()
}

async fn delete_team(
    State(state): State<Arc<AppState>>,
    auth_user: crate::auth::AuthUser,
    headers: HeaderMap,
    Path(team_id): Path<String>,
    Form(csrf): Form<CsrfForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &csrf._csrf) {
        return resp;
    }
    let user = &auth_user.user;
    let is_admin = user.role == "admin";
    if !is_admin && !is_team_admin(&state.pool, &user.id, &team_id).await {
        return Redirect::to("/dashboard/teams").into_response();
    }
    // Delete avatar file if present
    let old: Option<(String,)> =
        sqlx::query_as("SELECT avatar_path FROM teams WHERE id = ? AND avatar_path IS NOT NULL")
            .bind(&team_id)
            .fetch_optional(&state.pool)
            .await
            .unwrap_or(None);
    if let Some((avatar_path,)) = old {
        let full_path = state.data_dir.join("avatars").join(&avatar_path);
        let _ = tokio::fs::remove_file(&full_path).await;
    }
    // Nullify team_id on event types (don't delete them — they belong to the creator's account)
    let _ = sqlx::query("UPDATE event_types SET team_id = NULL WHERE team_id = ?")
        .bind(&team_id)
        .execute(&state.pool)
        .await;
    // Delete team (CASCADE removes team_members, team_groups)
    let _ = sqlx::query("DELETE FROM teams WHERE id = ?")
        .bind(&team_id)
        .execute(&state.pool)
        .await;
    tracing::info!(team_id = %team_id, user_id = %user.id, "team deleted");
    Redirect::to("/dashboard/teams").into_response()
}

async fn serve_team_avatar(
    State(state): State<Arc<AppState>>,
    Path(team_id): Path<String>,
) -> impl IntoResponse {
    // Team avatars are always public (they're just logos/icons, not sensitive).
    let filename: Option<(String,)> =
        sqlx::query_as("SELECT avatar_path FROM teams WHERE id = ? AND avatar_path IS NOT NULL")
            .bind(&team_id)
            .fetch_optional(&state.pool)
            .await
            .unwrap_or(None);

    let filename = match filename {
        Some((f,)) => f,
        None => return (axum::http::StatusCode::NOT_FOUND, "").into_response(),
    };

    let full_path = state.data_dir.join("avatars").join(&filename);
    match tokio::fs::read(&full_path).await {
        Ok(bytes) => {
            let content_type = if filename.ends_with(".jpg") || filename.ends_with(".jpeg") {
                "image/jpeg"
            } else if filename.ends_with(".png") {
                "image/png"
            } else if filename.ends_with(".gif") {
                "image/gif"
            } else if filename.ends_with(".webp") {
                "image/webp"
            } else {
                "image/png"
            };
            axum::response::Response::builder()
                .status(200)
                .header("Content-Type", content_type)
                .header("Cache-Control", "public, max-age=3600")
                .body(axum::body::Body::from(bytes))
                .unwrap_or_else(|_| axum::response::Response::new(axum::body::Body::empty()))
                .into_response()
        }
        Err(_) => (axum::http::StatusCode::NOT_FOUND, "").into_response(),
    }
}

// --- Cancel booking ---

#[derive(Deserialize)]
struct CancelForm {
    _csrf: Option<String>,
    reason: Option<String>,
}

async fn cancel_booking(
    State(state): State<Arc<AppState>>,
    auth_user: crate::auth::AuthUser,
    headers: HeaderMap,
    Path(booking_id): Path<String>,
    Form(form): Form<CancelForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }
    let user = &auth_user.user;

    // Verify the booking belongs to this user and is confirmed or pending.
    // Pending bookings are "declined" (no CalDAV event was ever pushed); confirmed ones are "cancelled".
    let booking: Option<(
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
    )> = sqlx::query_as(
        "SELECT b.id, b.uid, b.guest_name, b.guest_email, b.start_at, b.end_at, et.title, et.id, COALESCE(b.guest_timezone, 'UTC'), b.status
             FROM bookings b
             JOIN event_types et ON et.id = b.event_type_id
             JOIN accounts a ON a.id = et.account_id
             WHERE b.id = ? AND a.user_id = ? AND b.status IN ('confirmed', 'pending')",
    )
    .bind(&booking_id)
    .bind(&user.id)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    let (
        bid,
        uid,
        guest_name,
        guest_email,
        start_at,
        end_at,
        event_title,
        et_id,
        guest_timezone,
        prev_status,
    ) = match booking {
        Some(b) => b,
        None => return Redirect::to("/dashboard/bookings").into_response(),
    };

    let was_pending = prev_status == "pending";
    let new_status = if was_pending { "declined" } else { "cancelled" };

    let _ = sqlx::query("UPDATE bookings SET status = ? WHERE id = ?")
        .bind(new_status)
        .bind(&bid)
        .execute(&state.pool)
        .await;

    tracing::info!(booking_id = %bid, status = new_status, "booking {}", new_status);

    if !was_pending {
        caldav_delete_booking(&state.pool, &state.secret_key, &user.id, &uid).await;
    }

    if let Ok(Some(smtp_config)) =
        crate::email::load_smtp_config(&state.pool, &state.secret_key).await
    {
        // Convert event-type-local stored times into the guest's tz; see #101.
        let stored_tz = get_host_tz(&state.pool, &et_id).await;
        let guest_tz_parsed = guest_timezone.parse::<Tz>().unwrap_or(Tz::UTC);
        let (date, start_time, end_time) =
            booking_strings_in_guest_tz(&start_at, &end_at, stored_tz, guest_tz_parsed);

        let reason = form.reason.filter(|r| !r.trim().is_empty());

        let details = crate::email::CancellationDetails {
            event_title: event_title.clone(),
            date: date.clone(),
            start_time: start_time.clone(),
            end_time: end_time.clone(),
            guest_name,
            guest_email,
            guest_timezone,
            host_name: user.name.clone(),
            host_email: user
                .booking_email
                .clone()
                .unwrap_or_else(|| user.email.clone()),
            uid,
            reason,
            cancelled_by_host: true,
            host_timezone: stored_tz.name().to_string(),
            ..Default::default()
        };

        if was_pending {
            let _ = crate::email::send_guest_decline_notice(&smtp_config, &details).await;
        } else {
            let _ = crate::email::send_guest_cancellation(&smtp_config, &details).await;
            let _ = crate::email::send_host_cancellation(&smtp_config, &details).await;
        }
    }

    Redirect::to("/dashboard/bookings").into_response()
}

// --- Confirm pending booking ---

async fn confirm_booking(
    State(state): State<Arc<AppState>>,
    auth_user: crate::auth::AuthUser,
    headers: HeaderMap,
    Path(booking_id): Path<String>,
    Form(csrf): Form<CsrfForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &csrf._csrf) {
        return resp;
    }
    let user = &auth_user.user;

    // Verify the booking belongs to this user and is pending
    let booking: Option<(
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        Option<String>,
        Option<String>,
        String,
        Option<String>,
        String,
    )> = sqlx::query_as(
        "SELECT b.id, b.uid, b.guest_name, b.guest_email, b.start_at, b.end_at, et.title, COALESCE(NULLIF(b.meeting_url, ''), et.location_value), b.cancel_token, COALESCE(b.guest_timezone, 'UTC'), b.reschedule_token, et.id
             FROM bookings b
             JOIN event_types et ON et.id = b.event_type_id
             JOIN accounts a ON a.id = et.account_id
             WHERE b.id = ? AND a.user_id = ? AND b.status = 'pending'",
    )
    .bind(&booking_id)
    .bind(&user.id)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    let (
        bid,
        uid,
        guest_name,
        guest_email,
        start_at,
        end_at,
        event_title,
        location_value,
        cancel_token,
        guest_timezone,
        reschedule_token,
        et_id,
    ) = match booking {
        Some(b) => b,
        None => return Redirect::to("/dashboard/bookings").into_response(),
    };

    // Confirm the booking
    let _ = sqlx::query("UPDATE bookings SET status = 'confirmed' WHERE id = ?")
        .bind(&bid)
        .execute(&state.pool)
        .await;

    tracing::info!(booking_id = %bid, "booking confirmed by host");

    // Mirror the email-token approve path: now that the booking is confirmed,
    // generate (or load via idempotency) the auto meeting URL so the host
    // notification email, ICS attachment, and CalDAV push all carry the link
    // for jitsi_auto/webhook_auto event types. Falls back to location_value
    // for static providers.
    let location_display = resolve_booking_location(
        &state,
        &bid,
        &et_id,
        Some(&user.id),
        location_value.as_deref(),
        &guest_name,
        &guest_email,
        true,
    )
    .await;

    // start_at/end_at are naive in the event type's timezone; convert to the
    // guest's tz so the confirmation email body and the ICS attachment match
    // what the guest booked. See #101.
    let stored_tz = get_host_tz(&state.pool, &et_id).await;
    let guest_tz_parsed = guest_timezone.parse::<Tz>().unwrap_or(Tz::UTC);
    let (date, start_time, end_time) =
        booking_strings_in_guest_tz(&start_at, &end_at, stored_tz, guest_tz_parsed);

    let details = crate::email::BookingDetails {
        event_title,
        date,
        start_time,
        end_time,
        guest_name,
        guest_email,
        guest_timezone,
        host_name: user.name.clone(),
        host_email: user
            .booking_email
            .clone()
            .unwrap_or_else(|| user.email.clone()),
        uid: uid.clone(),
        notes: None,
        location: location_display,
        reminder_minutes: None,
        additional_attendees: vec![],
        host_timezone: stored_tz.name().to_string(),
        ..Default::default()
    };

    // Push to CalDAV calendar
    caldav_push_booking(&state.pool, &state.secret_key, &user.id, &uid, &details).await;

    // Send confirmation emails
    if let Ok(Some(smtp_config)) =
        crate::email::load_smtp_config(&state.pool, &state.secret_key).await
    {
        let base_url = std::env::var("CALRS_BASE_URL").ok();
        let guest_cancel_url = cancel_token.as_ref().and_then(|t| {
            base_url
                .as_ref()
                .map(|base| format!("{}/booking/cancel/{}", base.trim_end_matches('/'), t))
        });
        let guest_reschedule_url = reschedule_token.as_ref().and_then(|t| {
            base_url
                .as_ref()
                .map(|base| format!("{}/booking/reschedule/{}", base.trim_end_matches('/'), t))
        });
        let (cancel_notice_min, reschedule_notice_min) =
            fetch_event_type_notice_minutes(&state.pool, &et_id).await;
        let _ = crate::email::send_guest_confirmation_ex(
            &smtp_config,
            &details,
            guest_cancel_url.as_deref(),
            guest_reschedule_url.as_deref(),
            cancel_notice_min,
            reschedule_notice_min,
        )
        .await;

        // Also send host a confirmation email (no ICS, event pushed via CalDAV)
        if let Err(e) = crate::email::send_host_booking_confirmed(&smtp_config, &details).await {
            tracing::error!(error = %e, host_email = %details.host_email, "host confirmation email failed");
        }
    }

    Redirect::to("/dashboard/bookings").into_response()
}

