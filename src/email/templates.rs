// --- HTML email template helpers ---

fn h(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

struct EmailRow {
    label: String,
    value: String,
}

struct EmailAction {
    label: String,
    url: String,
    color: String,
}

fn render_html_email(
    greeting: &str,
    message: &str,
    accent: &str,
    rows: &[EmailRow],
    footer_note: Option<&str>,
) -> String {
    render_html_email_with_actions(greeting, message, accent, rows, footer_note, &[])
}

fn render_html_email_with_actions(
    greeting: &str,
    message: &str,
    accent: &str,
    rows: &[EmailRow],
    footer_note: Option<&str>,
    actions: &[EmailAction],
) -> String {
    let mut detail_rows = String::new();
    for (i, row) in rows.iter().enumerate() {
        let bg = if i % 2 == 0 { "#f8f9fa" } else { "#ffffff" };
        detail_rows.push_str(&format!(
            "<tr>\
               <td style=\"padding:8px 12px;color:#6b7280;font-size:13px;white-space:nowrap;vertical-align:top;\">{}</td>\
               <td style=\"padding:8px 12px;color:#111827;font-size:14px;background:{bg};\">{}</td>\
             </tr>",
            row.label, h(&row.value),
        ));
    }

    let actions_html = if actions.is_empty() {
        String::new()
    } else {
        let buttons: Vec<String> = actions.iter().map(|a| {
            format!(
                "<a href=\"{}\" style=\"display:inline-block;padding:12px 28px;background:{};color:#ffffff;text-decoration:none;border-radius:6px;font-weight:600;font-size:14px;margin:0 6px;\">{}</a>",
                h(&a.url), a.color, h(&a.label)
            )
        }).collect();
        format!(
            "<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" style=\"margin:20px 0 0;\"><tr><td align=\"center\">{}</td></tr></table>",
            buttons.join(" ")
        )
    };

    let footer_html = footer_note
        .map(|n| {
            format!(
                "<p style=\"margin:16px 0 0;font-size:13px;color:#6b7280;\">{}</p>",
                h(n)
            )
        })
        .unwrap_or_default();

    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"></head>
<body style="margin:0;padding:0;background:#f4f4f7;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f4f4f7;">
<tr><td align="center" style="padding:32px 16px;">
  <table role="presentation" width="520" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:8px;border:1px solid #e5e7eb;max-width:520px;width:100%;">
    <!-- Accent bar -->
    <tr><td style="height:4px;background:{accent};border-radius:8px 8px 0 0;"></td></tr>
    <!-- Content -->
    <tr><td style="padding:32px 28px;">
      <p style="margin:0 0 4px;font-size:15px;color:#374151;">{greeting}</p>
      <p style="margin:0 0 20px;font-size:15px;color:#111827;font-weight:500;">{message}</p>
      <!-- Details table -->
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #e5e7eb;border-radius:6px;overflow:hidden;">
        {detail_rows}
      </table>
      {actions_html}
      {footer_html}
    </td></tr>
    <!-- Footer -->
    <tr><td style="padding:16px 28px;border-top:1px solid #f0f0f3;text-align:center;">
      <span style="font-size:12px;color:#9ca3af;">Sent by </span>
      <a href="https://cal.rs" style="font-size:12px;color:#6b7280;font-weight:600;text-decoration:none;">calrs</a>
    </td></tr>
  </table>
</td></tr>
</table>
</body>
</html>"##
    )
}

fn build_multipart_body(plain: &str, html: &str) -> MultiPart {
    MultiPart::alternative()
        .singlepart(SinglePart::plain(plain.to_string()))
        .singlepart(
            SinglePart::builder()
                .header(ContentType::parse("text/html; charset=UTF-8").unwrap())
                .body(html.to_string()),
        )
}

