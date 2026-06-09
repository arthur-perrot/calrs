# calrs — plan de nettoyage (audit & découpes)

Branche : `refactor/cleanup` (issue de `main` à `5e36a06`, release 1.13.0).

Ce document trace les découpes structurelles à appliquer à `main`. Le code lui-même n'est *pas* modifié : on déplace des fonctions et on isole les tests, sans changer le comportement. Un commit = une étape.

---

## État initial (`main` 1.13.0)

| Fichier | Lignes | Tests embarqués | Code | Remarques |
|---|---:|---:|---:|---|
| `src/web/mod.rs` | **25 585** | **7 820 (30 %)** | ~17 765 | Monolithe — toutes les routes web |
| `src/email.rs` | 5 711 | ~1 100 | ~4 600 | 18 fonctions `send_*` quasi identiques |
| `src/auth.rs` | 2 714 | ~430 | ~2 280 | Extractors + handlers + OIDC mélangés |
| `src/commands/sync.rs` | 1 687 | ~490 | ~1 200 | `sync_source` + `sync_ews_source` dupliqués |
| `src/caldav/mod.rs` | 1 571 | ~660 | ~910 | Client CalDAV + templates XML |
| `src/commands/config.rs` | 1 365 | ~530 | ~830 | Handlers config CLI |
| `src/db.rs` | 1 202 | ~420 | ~780 | Migrations registrées + tests |
| `src/web/meeting.rs` | 857 | ~330 | ~530 | Génération de liens de visio |
| `src/rrule.rs` | 839 | ~465 | ~370 | Expansion des RRULE |

**Total Rust :** 48 852 lignes, dont **~12 000 sont des tests embarqués dans `src/`** répartis sur 22 fichiers (759 fonctions). Aucun dossier `tests/`, dev-deps minimalistes (`tower`, `http-body-util`).

---

## `src/web/mod.rs` — carte du monolithe

| Bloc | Lignes | Contenu |
|---|---|---|
| Préambule | 1 – 1 600 | `AppState`, CSRF, CSP, `RateLimiter`, `create_router()` |
| Dashboard | 1 600 – 4 060 | Overview, event-types list, bookings list, teams list, sources list, settings, avatars |
| Event-types CRUD | 4 060 – 7 290 | + invites + availability overrides + embed |
| Groupes/Teams publics | 7 570 – 10 430 | Slots, book, dynamic group, profil user |
| Booking user-scope + slots | 10 430 – 13 290 | `show_slots*`, `handle_booking*`, tokens, reschedule, claim, CalDAV write-back |
| Troubleshoot + Admin | 13 295 – 15 180 | Auth/OIDC/Google OAuth/captcha/jitsi/logo/impersonate |
| Reschedule + claim handlers | 15 180 – 17 765 | + CalDAV push/delete + watchers |
| Tests embarqués | 17 766 – 25 585 | ~7 800 lignes, ~301 fonctions |

### Découpage cible (`src/web/`)

```
src/web/
├── mod.rs            ~500   (router, AppState, middleware CSRF/CSP)
├── dashboard.rs      ~650   (overview/event_types/bookings/teams + settings + avatars)
├── event_types.rs    ~650   (CRUD event types, invites, overrides, embed)
├── sources.rs        ~700   (CRUD sources, test, sync, Google OAuth flow)
├── public_booking.rs ~1100  (show_slots*, show_book_form*, handle_booking*, tokens, reschedule, claim, caldav_push)
├── group_booking.rs  ~900   (team_profile, group + dynamic_group flows, legacy redirects /g/ /t/)
├── admin.rs          ~750   (admin dashboard, auth/OIDC/captcha/jitsi/logo/impersonate)
├── slots.rs          ~1500  (compute_slots, busy times, timezone helpers, frequency limits)
├── theme.rs          ~400   (preset_theme_css, build_theme_css, hex_to_rgb, initials, etc.)
├── captcha.rs        254    (déjà séparé)
└── meeting.rs        857    (déjà séparé)
```

---

## `src/email.rs` — 18 envois quasi identiques

Pattern commun pour chaque `send_*` :
1. traduire les clés i18n
2. construire le corps plain-text
3. construire la table HTML
4. `render_html_email[_with_actions]` (template global unique, l.221–250)
5. pièce jointe `.ics` éventuelle
6. `send_message(transport, msg)`

### Découpage cible (`src/email/`)

```
src/email/
├── mod.rs            (SMTP, send_message, render_html_email, load_smtp_config)
├── templates.rs      (build_multipart_body + rows + variantes ICS)
├── booking.rs        (guest_confirmation/cancellation/pending/decline/reminder/pick_new_time)
├── host.rs           (host_booking_confirmed/cancellation/approval_request/reschedule_request)
└── invite.rs         (invite, watcher_claim, claim_confirmation)
```

---

## `src/auth.rs` — extractors / handlers / OIDC mélangés

### Découpage cible (`src/auth/`)

```
src/auth/
├── mod.rs            (constantes, hash, sessions, delete_user, resolve_session_user)
├── extractors.rs     (AuthUser, OptionalAuthUser, AdminUser — FromRequestParts)
├── handlers.rs       (login_handler, register_handler, logout_handler, renders d'erreur)
└── oidc.rs           (build_oidc_client, oidc_callback, find_or_create_oidc_user)
```

---

## Duplication & lignes denses (pour mémoire — pas dans ce PR)

Ces points sont identifiés mais ne sont **pas** traités dans le PR de découpe (le code reste tel quel) :

- **`COALESCE(NULLIF(et.timezone, ''), u.timezone)`** : dupliqué 6× dans `web/mod.rs` (lignes 417, 1632, 1895, 1912, 1933, 12263) — candidat pour un `const BOOKING_DETAIL_SQL` ou `fetch_booking_details()`.
- **`chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string()`** : 19 occurrences — helper `now_sqlite()`.
- **`date.and_hms_opt(0, 0, 0).unwrap()`** : 38 occurrences — helper `start_of_day(date)`.
- **`create_event_type` / `update_event_type`** (`web/mod.rs` l.4692 et l.5246) : 24 colonnes répétées dans l'INSERT et 21 dans l'UPDATE. Candidat pour une struct `EventTypeFields`.
- **`sync_source` / `sync_ews_source`** (`commands/sync.rs` l.129 et l.491) : structurellement identiques — le trait `CalendarProvider` introduit en migration 055 existe déjà mais n'est pas utilisé ici.
- **4 handlers `handle_*booking*`** (`web/mod.rs`, ~400 lignes chacun, ~1 670 lignes au total) : 18 étapes identiques. **Refactor explicitement reporté** (cf. mémoire `booking-handler-duplication-plan.md` et branche `feat/lead-capture`).

---

## Plan (un commit par étape, branche unique `refactor/cleanup`)

| # | Étape | Effet attendu | Risque |
|---|---|---|---|
| 1 | Ajouter `CLEANUP.md` | 0 ligne de code touchée | Nul |
| 2 | Extraire tests de `web/mod.rs` vers `src/web/tests/*.rs` (via `#[path]`) | -7 800 lignes sur le fichier critique | Très faible |
| 3 | Extraire tests de `email.rs` vers `src/email_tests.rs` | -1 100 lignes | Très faible |
| 4 | Extraire tests de `auth.rs` vers `src/auth_tests.rs` | -430 lignes | Très faible |
| 5 | Extraire tests des autres fichiers (caldav, commands/*, db, rrule, utils, i18n, crypto, ews/*, web/meeting, web/captcha) | -2 700 lignes | Très faible |
| 6 | Découper `web/mod.rs` en sous-modules | 17 765 → ~7 fichiers de 500–1500 lignes | Moyen (re-export + visibilités) |
| 7 | Découper `email.rs` en sous-modules | 4 600 → 4–5 fichiers ~1k | Faible |
| 8 | Découper `auth.rs` en sous-modules | 2 280 → 3 fichiers ~700 | Faible |

**Hors-scope** (volontairement, code non modifié sur cette branche) : helpers `now_sqlite`/`start_of_day`, `BOOKING_DETAIL_SQL`, fusion `create_event_type`/`update_event_type`, unification `sync_source`/`sync_ews_source` via `CalendarProvider`, refactor `BookingFlow`.

---

## Protocole de validation entre chaque commit

1. `cargo fmt`
2. `cargo check`
3. `cargo test --bins` (toute la suite — 758 passed, 1 ignored)
4. `cargo build --release`
5. À partir de l'étape 6 : démarrage local sur port 3001 avec `CALRS_DATA_DIR=/tmp/calrs-cleanup` + smoke tests Chromium headless (login `toi@example.com`, dashboard, slot picker, booking, admin).

---

## Status (après exécution)

Toutes les étapes 1–8 ont été appliquées sur la branche `refactor/cleanup`. À chaque commit : `cargo fmt`, `cargo check`, `cargo test --bins` (758 passed, 1 ignored, identique au baseline), `cargo build --release`. Smoke tests Chromium headless sur port 3001 vert pour `/auth/login`, `/dashboard`, `/dashboard/event-types`, `/dashboard/bookings`, `/dashboard/teams`, `/dashboard/sources`, `/dashboard/settings`, `/dashboard/invite-links`, `/dashboard/admin`, `/u/toi`, `/u/toi/test`, `/u/toi/phone`, `/team/all-team`, `/test`, `/test/book`, `/booking/approve/{token}`.

### `src/web/` (était 25 585 lignes en un seul `mod.rs`)

| Fichier | Lignes | Rôle |
|---|---:|---|
| `src/web/mod.rs` | **1 609** | `AppState`, `RateLimiter`, CSRF, CSP, error sanitization, `create_router()`, 7 `include!` |
| `src/web/dashboard.rs` | 2 730 | Pages dashboard + settings + avatars + cancel/confirm booking |
| `src/web/event_types.rs` | 3 241 | CRUD event types + invites + overrides |
| `src/web/group_booking.rs` | 2 860 | Group event types + legacy redirects + group public pages + dynamic groups |
| `src/web/public_booking.rs` | 2 014 | User-scoped + public booking handlers (handle_booking*, show_slots*) |
| `src/web/slots.rs` | 852 | `compute_slots`, busy times, `BusySource` |
| `src/web/troubleshoot.rs` | 583 | Page de troubleshoot availability |
| `src/web/admin.rs` | 1 300 | Admin dashboard + Google OAuth + captcha/meeting/logo/impersonate |
| `src/web/booking_tokens.rs` | 2 586 | Tokens approve/decline/cancel/reschedule + CalDAV write-back + watchers + claim |
| `src/web/tests.rs` | 7 805 | Tests (déplacés en étape 2) |
| `src/web/captcha.rs` | 165 | (déjà séparé avant ce PR) |
| `src/web/meeting.rs` | 528 | (déjà séparé avant ce PR) |

### `src/email/` (était 5 711 lignes en un seul fichier)

| Fichier | Lignes |
|---|---:|
| `src/email.rs` | **154** |
| `src/email/templates.rs` | 118 |
| `src/email/ics.rs` | 288 |
| `src/email/senders.rs` | 1 226 |
| `src/email/utility.rs` | 277 |
| `src/email/reschedule.rs` | 384 |
| `src/email/claim.rs` | 173 |
| `src/email/tests.rs` | 3 091 |

### `src/auth/` (était 2 714 lignes en un seul fichier)

| Fichier | Lignes |
|---|---:|
| `src/auth.rs` | **441** |
| `src/auth/extractors.rs` | 116 |
| `src/auth/handlers.rs` | 333 |
| `src/auth/oidc.rs` | 454 |
| `src/auth/group_sync.rs` | 191 |
| `src/auth/tests.rs` | 1 175 |

### Notes sur la mécanique

- Les découpes utilisent `include!("file.rs")` plutôt que `mod file;`, ce qui préserve l'identité du module parent et évite toute modification de visibilité (`pub`/`pub(super)`/`pub(crate)`). Le code reste byte-for-byte identique à l'original.
- Conséquence : `cargo fmt` ne reformate pas les fichiers inclus. Les fichiers extraits sont déjà au format `rustfmt` au moment de l'extraction. Toute édition ultérieure devra être formatée à la main (ou convertir vers `mod` proper, ce qui demande un cycle de visibilité).
- Les tests embarqués sont en revanche exposés via `mod tests;` standard (et non `include!`), car ils étaient déjà dans un sous-module et bénéficient du formatage automatique.
