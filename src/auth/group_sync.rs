// --- OIDC group sync ---

/// Extract the `groups` claim from a raw JWT ID token.
/// Decodes the payload (middle part) as base64 and parses JSON.
/// Returns None if the token has no groups claim or cannot be parsed.
/// Parsed claims from an OIDC ID token JWT payload.
struct OidcClaims {
    groups: Option<Vec<String>>,
    title: Option<String>,
}

fn extract_claims_from_id_token(raw_token: &str) -> OidcClaims {
    let parts: Vec<&str> = raw_token.split('.').collect();
    if parts.len() != 3 {
        return OidcClaims {
            groups: None,
            title: None,
        };
    }
    let payload_bytes = match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[1]) {
        Ok(b) => b,
        Err(_) => {
            return OidcClaims {
                groups: None,
                title: None,
            }
        }
    };
    let payload: serde_json::Value = match serde_json::from_slice(&payload_bytes) {
        Ok(v) => v,
        Err(_) => {
            return OidcClaims {
                groups: None,
                title: None,
            }
        }
    };

    let groups = payload.get("groups").and_then(|g| {
        let arr = g.as_array()?;
        let group_strings: Vec<String> = arr
            .iter()
            .filter_map(|v| {
                v.as_str()
                    .map(|s| s.strip_prefix('/').unwrap_or(s).to_string())
            })
            .collect();
        if group_strings.is_empty() {
            None
        } else {
            Some(group_strings)
        }
    });

    let title = payload
        .get("title")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    OidcClaims { groups, title }
}

/// Backward-compatible wrapper for tests.
fn extract_groups_from_id_token(raw_token: &str) -> Option<Vec<String>> {
    extract_claims_from_id_token(raw_token).groups
}

/// Sync a user's group memberships from OIDC groups claim.
/// Creates any missing groups and replaces the user's memberships.
pub async fn sync_user_groups(pool: &SqlitePool, user_id: &str, groups: &[String]) -> Result<()> {
    // Delete existing OIDC group memberships for this user
    sqlx::query(
        "DELETE FROM user_groups WHERE user_id = ? AND group_id IN (SELECT id FROM groups WHERE source = 'oidc')",
    )
    .bind(user_id)
    .execute(pool)
    .await
    .context("Failed to clear user OIDC groups")?;

    // Collect the group IDs the user currently belongs to (for team sync)
    let mut current_group_ids: Vec<String> = Vec::new();

    for group_path in groups {
        let group_id = uuid::Uuid::new_v4().to_string();
        let slug = generate_group_slug(group_path);

        // Upsert group: insert if not exists (keyed on name + source=oidc)
        sqlx::query(
            "INSERT INTO groups (id, name, source, oidc_id, slug, created_at) \
             VALUES (?, ?, 'oidc', ?, ?, datetime('now')) \
             ON CONFLICT(name) DO UPDATE SET oidc_id = excluded.oidc_id, slug = excluded.slug",
        )
        .bind(&group_id)
        .bind(group_path)
        .bind(group_path)
        .bind(&slug)
        .execute(pool)
        .await
        .context("Failed to upsert group")?;

        // Get the actual group ID (may differ if it already existed)
        let (actual_group_id,): (String,) = sqlx::query_as("SELECT id FROM groups WHERE name = ?")
            .bind(group_path)
            .fetch_one(pool)
            .await
            .context("Failed to fetch group id")?;

        // Insert membership
        sqlx::query("INSERT OR IGNORE INTO user_groups (user_id, group_id) VALUES (?, ?)")
            .bind(user_id)
            .bind(&actual_group_id)
            .execute(pool)
            .await
            .context("Failed to insert user_group")?;

        current_group_ids.push(actual_group_id);
    }

    // --- Sync team memberships via team_groups ---

    // Add user to teams linked to their current OIDC groups
    for group_id in &current_group_ids {
        let team_ids: Vec<(String,)> =
            sqlx::query_as("SELECT team_id FROM team_groups WHERE group_id = ?")
                .bind(group_id)
                .fetch_all(pool)
                .await
                .context("Failed to fetch team_groups")?;

        for (team_id,) in team_ids {
            sqlx::query(
                "INSERT OR IGNORE INTO team_members (team_id, user_id, role, source) VALUES (?, ?, 'member', 'group')",
            )
            .bind(&team_id)
            .bind(user_id)
            .execute(pool)
            .await
            .context("Failed to insert team_member from group")?;
        }
    }

    // Remove user from teams where they were added via group sync but no longer belong
    // to any linked OIDC group. Only remove source='group' rows (not 'direct').
    sqlx::query(
        "DELETE FROM team_members WHERE user_id = ? AND source = 'group' \
         AND team_id NOT IN ( \
             SELECT tg.team_id FROM team_groups tg \
             WHERE tg.group_id IN (SELECT group_id FROM user_groups WHERE user_id = ?) \
         )",
    )
    .bind(user_id)
    .bind(user_id)
    .execute(pool)
    .await
    .context("Failed to clean up stale team memberships")?;

    Ok(())
}

/// Generate a URL-friendly slug from a group name.
/// "Demo Team" -> "demo-team", "engineering/backend" -> "engineering-backend"
pub fn generate_group_slug(name: &str) -> String {
    let slug: String = name
        .to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect();
    // Collapse multiple dashes and trim leading/trailing dashes
    let mut result = String::new();
    let mut prev_dash = true; // start true to skip leading dashes
    for c in slug.chars() {
        if c == '-' {
            if !prev_dash {
                result.push('-');
            }
            prev_dash = true;
        } else {
            result.push(c);
            prev_dash = false;
        }
    }
    // Trim trailing dash
    if result.ends_with('-') {
        result.pop();
    }
    if result.is_empty() {
        "group".to_string()
    } else {
        result
    }
}
