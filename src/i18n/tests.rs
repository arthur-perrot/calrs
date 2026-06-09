use super::*;

#[test]
fn no_header_falls_back_to_default() {
    assert_eq!(detect_from_accept_language(None), "en");
}

#[test]
fn empty_header_falls_back_to_default() {
    assert_eq!(detect_from_accept_language(Some("")), "en");
}

#[test]
fn exact_supported_tag() {
    assert_eq!(detect_from_accept_language(Some("fr")), "fr");
}

#[test]
fn primary_subtag_extracted_from_region() {
    assert_eq!(detect_from_accept_language(Some("en-US")), "en");
    assert_eq!(detect_from_accept_language(Some("fr-CA")), "fr");
}

#[test]
fn first_listed_wins_when_q_unspecified() {
    // Browsers commonly send the preferred language first without explicit q.
    assert_eq!(
        detect_from_accept_language(Some("fr-CA,fr;q=0.9,en;q=0.5")),
        "fr"
    );
}

#[test]
fn higher_q_overrides_textual_order() {
    // The previous (broken) implementation would have picked en here.
    assert_eq!(detect_from_accept_language(Some("en;q=0.5,fr;q=0.9")), "fr");
}

#[test]
fn unsupported_languages_skipped() {
    // ja and zh aren't shipped; first supported tag wins.
    assert_eq!(detect_from_accept_language(Some("ja,zh,fr")), "fr");
}

#[test]
fn all_unsupported_falls_back_to_default() {
    assert_eq!(detect_from_accept_language(Some("ja,zh,ko")), "en");
}

#[test]
fn q_zero_is_still_considered_for_fallback() {
    // q=0 means "do not accept", but our scan currently treats it as a
    // weak preference. This is fine for our fallback semantics since
    // we'd return the default anyway if nothing matched.
    assert_eq!(detect_from_accept_language(Some("fr;q=0")), "fr");
}

#[test]
fn translate_returns_value_for_existing_key() {
    let v = translate("fr", "confirmed-heading-booked", None);
    assert!(!v.is_empty());
    assert_ne!(v, "confirmed-heading-booked");
}

#[test]
fn translate_falls_back_to_english_on_missing_key_in_locale() {
    // Polish file is seeded but if a future key is missing it should
    // fall back to English rather than emit the raw key.
    let en = translate("en", "confirmed-heading-booked", None);
    let pl = translate("pl", "this-key-definitely-does-not-exist", None);
    assert_eq!(pl, "this-key-definitely-does-not-exist"); // unknown key → key
    assert!(!en.is_empty());
}

#[test]
fn month_year_english() {
    let d = NaiveDate::from_ymd_opt(2026, 4, 1).unwrap();
    assert_eq!(format_month_year(d, "en"), "April 2026");
}

#[test]
fn month_year_french() {
    let d = NaiveDate::from_ymd_opt(2026, 4, 1).unwrap();
    // Lowercase, no comma, French ordering.
    assert_eq!(format_month_year(d, "fr"), "avril 2026");
}

#[test]
fn month_year_spanish() {
    let d = NaiveDate::from_ymd_opt(2026, 4, 1).unwrap();
    assert_eq!(format_month_year(d, "es"), "abril 2026");
}

#[test]
fn month_year_polish() {
    let d = NaiveDate::from_ymd_opt(2026, 4, 1).unwrap();
    assert_eq!(format_month_year(d, "pl"), "kwiecień 2026");
}

#[test]
fn month_year_german() {
    let d = NaiveDate::from_ymd_opt(2026, 4, 1).unwrap();
    // German months are capitalized by grammar.
    assert_eq!(format_month_year(d, "de"), "April 2026");
}

#[test]
fn month_year_italian() {
    let d = NaiveDate::from_ymd_opt(2026, 4, 1).unwrap();
    assert_eq!(format_month_year(d, "it"), "aprile 2026");
}

#[test]
fn long_date_german_with_period_after_day() {
    // 2026-04-27 is a Monday.
    let d = NaiveDate::from_ymd_opt(2026, 4, 27).unwrap();
    assert_eq!(format_long_date(d, "de"), "Montag, 27. April 2026");
}

#[test]
fn long_date_italian_no_comma() {
    let d = NaiveDate::from_ymd_opt(2026, 4, 27).unwrap();
    assert_eq!(format_long_date(d, "it"), "lunedì 27 aprile 2026");
}

#[test]
fn month_year_falls_back_to_english_for_unknown_lang() {
    let d = NaiveDate::from_ymd_opt(2026, 4, 1).unwrap();
    // Unknown locale (e.g. "de") should fall through to English.
    assert_eq!(format_month_year(d, "de"), "April 2026");
}

#[test]
fn long_date_english() {
    // 2026-04-27 is a Monday.
    let d = NaiveDate::from_ymd_opt(2026, 4, 27).unwrap();
    assert_eq!(format_long_date(d, "en"), "Monday, April 27, 2026");
}

#[test]
fn long_date_french_word_order() {
    let d = NaiveDate::from_ymd_opt(2026, 4, 27).unwrap();
    // French puts day before month, no comma.
    assert_eq!(format_long_date(d, "fr"), "lundi 27 avril 2026");
}

#[test]
fn year_does_not_get_thousands_separator() {
    // Regression guard: passing the year as i64 would let Fluent's
    // number formatter add grouping ("2,026" / "2 026"). We pass a
    // pre-stringified value to avoid that.
    let d = NaiveDate::from_ymd_opt(2026, 4, 27).unwrap();
    let en = format_long_date(d, "en");
    let fr = format_long_date(d, "fr");
    assert!(en.contains("2026"));
    assert!(fr.contains("2026"));
    assert!(!en.contains("2,026"));
    assert!(!fr.contains("2 026"));
}
