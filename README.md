# CF7 Spam Plugin

Layered spam filtering for [Contact Form 7](https://contactform7.com/). It hooks `wpcf7_spam` (similar in spirit to Gravity Forms’ `gform_entry_is_spam`): if a check fails, the submission is treated as spam, mail is not sent, and a spam log entry is added for tools like Flamingo.

## Requirements

- WordPress 6.0+
- PHP 8.1+
- Contact Form 7 (`WPCF7` class present)

## Installation

1. Ensure this directory exists at `web/app/plugins/cf7-spam-plugin/`.
2. In **Plugins**, activate **CF7 Spam Plugin** (after Contact Form 7).

On Bedrock sites, plugins under `web/app/plugins/` are usually ignored by Git except allowlisted paths; this repo includes `cf7-spam-plugin` in `.gitignore` exceptions.

## What it checks (in order)

1. **Honeypot** – Hidden field `_cf7sp_hp` must remain empty.
2. **Minimum elapsed time** – Hidden `_cf7sp_started` (Unix time when the form HTML was built) must be at least N seconds before submit (default `2`).
3. **IP format** – Remote IP must pass `FILTER_VALIDATE_IP` when validation is enabled.
4. **Rate limit** – Per IP + form ID, stored in transients (default `8` submissions per `HOUR_IN_SECONDS`).
5. **User-Agent** – Rejects empty UA and common script/bot tokens (extendable via filter).
6. **URLs in text-like fields** – Same style of pattern as Gravity Forms docs (plain URLs, `href=`, markdown links) on `text`, `textarea`, `hidden`, `name`, and `address` tags only.
7. **Australian phone (`tel` fields)** – If the form includes any `[tel]` / `[tel*]` field, every non-empty submitted value on those fields must match a supported Australian pattern (see below). Empty optional phone fields are skipped.
8. **Name field** – For multipart `name` fields with `first` + `last` keys, spam if both non-empty and equal (case-insensitive).
9. **Repeated long values** – If the same long string (more than 6 characters) appears in at least N separate field values (default `4`), mark spam.
10. **Character repetition** – Very long runs of the same character in combined user text.
11. **Keyword blocklist** – Default conservative list; replace/extend with filters.
12. **Domain blocklist** – Empty by default; supply domains via filter.

### Australian phone formats accepted

Spaces, dots, dashes, and parentheses are ignored; `0061` international prefix is normalised like `+61`.

- **Mobile:** `04XX XXX XXX` (10 digits) or `+61 4XX XXX XXX` / `614XXXXXXXX`
- **Geographic:** `02`, `03`, `07`, `08` + 8 digits (10 digits national) or matching `+61` / `61` forms
- **1300 / 1800:** 10-digit national or `+61 1300 …` / `+61 1800 …` (12 digits with `61`)
- **13 numbers:** six-digit `13XXXX` (e.g. `13 14 50`)

Numbers outside these shapes are treated as spam (with log reason `phone_au`). To allow extra patterns after normalisation to digits, use the `cf7_spam_filter_is_valid_australian_phone` filter.

If another filter already set `$spam` to true, this plugin does nothing further.

## Spam logging

When a rule triggers, the plugin calls `WPCF7_Submission::add_spam_log()` with:

- `agent`: `cf7_spam_filter:{rule_id}`
- `reason`: Short explanation (suitable for Flamingo / CF7 spam log UI)

## Filters (tuning)

| Filter | Default / purpose |
|--------|---------------------|
| `cf7_spam_filter_skip_all_checks` | `false` – return `true` to disable every check (e.g. staging). |
| `cf7_spam_filter_min_elapsed_seconds` | `2` – minimum seconds between form render and submit. |
| `cf7_spam_filter_validate_ip` | `true` – set `false` if behind a proxy and IP handling breaks. |
| `cf7_spam_filter_rate_limit_max` | `8` – max submissions per window per IP + form. |
| `cf7_spam_filter_rate_limit_window` | `HOUR_IN_SECONDS` – transient TTL / window. |
| `cf7_spam_filter_check_user_agent` | `true` – disable UA checks if needed. |
| `cf7_spam_filter_user_agent_spam_tokens` | Array of substrings; matched case-insensitively. |
| `cf7_spam_filter_enable_url_check` | `true` – disable URL-in-field checks if too aggressive for your forms. |
| `cf7_spam_filter_duplicate_field_threshold` | `4` – how many identical long strings trigger repetition rule. |
| `cf7_spam_filter_blocked_keywords` | Array of phrases (case-insensitive substring match on combined user text). |
| `cf7_spam_filter_blocked_domains` | Array of domain strings (case-insensitive substring match). |
| `cf7_spam_filter_require_australian_phone` | `true` – set `false` to disable AU phone checks entirely. |
| `cf7_spam_filter_au_phone_basetypes` | `array( 'tel' )` – add basetypes (e.g. `text`) if a “phone” field is not a `tel` tag. |
| `cf7_spam_filter_is_valid_australian_phone` | Fires only when built-in patterns did not match. Callback receives `( $is_valid, $digits, $original_input )`; return `true` to accept a number the built-in rules do not cover. |

### Example: allow only administrators to bypass checks

```php
add_filter( 'cf7_spam_filter_skip_all_checks', function ( $skip, $submission ) {
	if ( current_user_can( 'manage_options' ) ) {
		return true;
	}
	return $skip;
}, 10, 2 );
```

### Example: block extra domains

```php
add_filter( 'cf7_spam_filter_blocked_domains', function ( $domains, $form_id, $submission ) {
	$domains[] = 'spam-example.net';
	return $domains;
}, 10, 3 );
```

## Testing ideas

- Normal submit after a few seconds → should succeed.
- Submit with `_cf7sp_hp` filled (e.g. tampered POST) → spam.
- Submit immediately after load (faster than min elapsed) → spam.
- Paste `https://example.com` into a message `textarea` → spam (unless URL checks disabled).
- Many rapid submits from same IP → spam after threshold.
- `tel` field with `+1 555 0100` or other non-AU numbers → spam; `0412 345 678` or `+61 412 345 678` → should succeed.

## Version

See plugin header in `cf7-spam-plugin.php` (`cf7_spam_filter_VERSION`).
