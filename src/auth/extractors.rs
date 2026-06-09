// --- Axum extractors ---

/// Info about an active impersonation session.
#[derive(Clone)]
pub struct ImpersonationInfo {
    pub admin_name: String,
    pub target_name: String,
}

/// Validate the session cookie and resolve admin impersonation in one place,
/// so AuthUser/OptionalAuthUser stay in sync. Returns None when there is no
/// valid session.
async fn resolve_session_user(
    pool: &SqlitePool,
    jar: &CookieJar,
) -> Option<(User, Option<ImpersonationInfo>)> {
    let token = jar.get(SESSION_COOKIE).map(|c| c.value().to_string())?;
    let real_user = validate_session(pool, &token).await?;

    if real_user.role == "admin" {
        if let Some(target_id) = jar.get(IMPERSONATE_COOKIE).map(|c| c.value().to_string()) {
            if target_id != real_user.id {
                if let Some(target_user) = get_user_by_id(pool, &target_id).await {
                    let info = ImpersonationInfo {
                        admin_name: real_user.name.clone(),
                        target_name: target_user.name.clone(),
                    };
                    return Some((target_user, Some(info)));
                }
            }
        }
    }

    Some((real_user, None))
}

/// Extractor that requires an authenticated user. Redirects to /auth/login if not authenticated.
/// Supports admin impersonation: if the `__Host-calrs_impersonate` cookie is set and the real user is
/// an admin, returns the impersonated user instead.
pub struct AuthUser {
    pub user: User,
    pub impersonation: Option<ImpersonationInfo>,
}

impl FromRequestParts<Arc<AppState>> for AuthUser {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let jar = CookieJar::from_headers(&parts.headers);
        match resolve_session_user(&state.pool, &jar).await {
            Some((user, impersonation)) => Ok(AuthUser {
                user,
                impersonation,
            }),
            None => Err(Redirect::to("/auth/login").into_response()),
        }
    }
}

/// Extractor that does NOT require authentication. Returns Some(user) for
/// authenticated requests (mirroring AuthUser's impersonation resolution) and
/// None for anonymous/invalid sessions — never redirects.
pub struct OptionalAuthUser {
    pub user: Option<User>,
    pub impersonation: Option<ImpersonationInfo>,
}

impl FromRequestParts<Arc<AppState>> for OptionalAuthUser {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let jar = CookieJar::from_headers(&parts.headers);
        let (user, impersonation) = match resolve_session_user(&state.pool, &jar).await {
            Some((u, info)) => (Some(u), info),
            None => (None, None),
        };
        Ok(OptionalAuthUser {
            user,
            impersonation,
        })
    }
}

/// Extractor that requires an admin user. Returns 403 if not admin.
/// Always uses the real session user, ignoring impersonation.
pub struct AdminUser(pub User);

impl FromRequestParts<Arc<AppState>> for AdminUser {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let jar = CookieJar::from_headers(&parts.headers);
        let token = jar.get(SESSION_COOKIE).map(|c| c.value().to_string());

        let real_user = match token {
            Some(ref token) => validate_session(&state.pool, token).await,
            None => None,
        };

        match real_user {
            Some(user) if user.role == "admin" => Ok(AdminUser(user)),
            Some(_) => Err((StatusCode::FORBIDDEN, "Admin access required").into_response()),
            None => Err(Redirect::to("/auth/login").into_response()),
        }
    }
}

