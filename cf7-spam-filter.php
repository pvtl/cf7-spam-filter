<?php
/**
 * Plugin Name:       CF7 Spam Plugin
 * Description:       Layered spam filtering for Contact Form 7 (honeypot, rate limits, URL checks, blocklists, and more).
 * Version:           1.0.1
 * Requires at least:   6.0
 * Requires PHP:        8.1
 * Author:              Pivotal Agency
 * License:             GPL-2.0-or-later
 * License URI:         https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:         cf7-spam-filter
 *
 * @package cf7_spam_filter
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'cf7_spam_filter_VERSION', '1.0.1' );

/**
 * Bootstrap when Contact Form 7 is available.
 */
function cf7_spam_filter_bootstrap() {
	if ( ! class_exists( 'WPCF7' ) ) {
		return;
	}

	add_filter( 'wpcf7_form_hidden_fields', 'cf7_spam_filter_register_hidden_fields', 5, 1 );
	add_filter( 'wpcf7_spam', 'cf7_spam_filter_filter_spam', 10, 2 );
}
add_action( 'plugins_loaded', 'cf7_spam_filter_bootstrap', 20 );

/**
 * Add honeypot and timing hidden fields to every CF7 form.
 *
 * @param array<string, string> $fields Hidden field name => value.
 * @return array<string, string>
 */
function cf7_spam_filter_register_hidden_fields( $fields ) {
	if ( ! is_array( $fields ) ) {
		$fields = array();
	}

	$fields['_cf7sp_hp']      = '';
	$fields['_cf7sp_started'] = (string) time();

	return $fields;
}

/**
 * Mark submission as spam and log reason (CF7 spam log / Flamingo compatible).
 *
 * @param WPCF7_Submission $submission Submission instance.
 * @param string           $agent      Short agent id for the check.
 * @param string           $reason     Human-readable reason.
 * @return true
 */
function cf7_spam_filter_mark_spam( $submission, $agent, $reason ) {
	if ( $submission instanceof WPCF7_Submission && method_exists( $submission, 'add_spam_log' ) ) {
		$submission->add_spam_log(
			array(
				'agent'  => 'cf7_spam_filter:' . sanitize_key( $agent ),
				'reason' => wp_strip_all_tags( $reason ),
			)
		);
	}

	return true;
}

/**
 * Flatten posted values to strings for scanning.
 *
 * @param mixed $value Posted value.
 * @return list<string>
 */
function cf7_spam_filter_flatten_values( $value ) {
	$out = array();
	if ( is_array( $value ) ) {
		foreach ( $value as $inner ) {
			$out = array_merge( $out, cf7_spam_filter_flatten_values( $inner ) );
		}
	} elseif ( is_string( $value ) ) {
		$out[] = $value;
	}

	return $out;
}

/**
 * Lowercase helper (UTF-8 when mbstring is available).
 *
 * @param string $text Input.
 * @return string
 */
function cf7_spam_filter_lower( $text ) {
	$text = (string) $text;

	if ( function_exists( 'mb_strtolower' ) ) {
		return mb_strtolower( $text, 'UTF-8' );
	}

	return strtolower( $text );
}

/**
 * Collect text from posted data for keyword / repetition checks.
 *
 * @param array<string, mixed> $posted Posted data.
 * @return string
 */
function cf7_spam_filter_collect_user_text( $posted ) {
	$parts = array();
	foreach ( $posted as $key => $value ) {
		if ( ! is_string( $key ) || str_starts_with( $key, '_' ) ) {
			continue;
		}
		foreach ( cf7_spam_filter_flatten_values( $value ) as $chunk ) {
			$chunk = trim( $chunk );
			if ( '' !== $chunk ) {
				$parts[] = $chunk;
			}
		}
	}

	return implode( "\n", $parts );
}

/**
 * URL / link pattern (based on Gravity Forms doc examples).
 *
 * @return string PCRE pattern without delimiters.
 */
function cf7_spam_filter_url_pattern() {
	return '(?:' .
		'(?:https?:\\/\\/|www\\.)[^\\s<>\\)\\]]+' .
		'|' .
		'<a\\b[^>]*\\bhref\\s*=\\s*(?:"[^"]*"|\'[^\']*\'|[^\\s>]+)[^>]*>' .
		'|' .
		'\\[[^\\]]+\\]\\(\\s*(?:https?:\\/\\/|www\\.)[^\\s\\)]+\\s*\\)' .
		')';
}

/**
 * Whether a form tag should be scanned for unsolicited URLs.
 *
 * @param WPCF7_FormTag $tag Form tag.
 */
function cf7_spam_filter_should_check_urls_for_tag( $tag ) {
	if ( ! is_object( $tag ) || ! isset( $tag->basetype ) ) {
		return false;
	}

	$allowed = array( 'text', 'textarea', 'hidden', 'name', 'address' );

	return in_array( $tag->basetype, $allowed, true );
}

/**
 * Digits-only representation of a phone string.
 *
 * @param string $input Raw input.
 * @return string
 */
function cf7_spam_filter_phone_digits_only( $input ) {
	return preg_replace( '/\D/', '', (string) $input );
}

/**
 * Whether the value looks like a valid Australian phone number.
 *
 * Accepts common national and international shapes after stripping separators:
 * mobile 04xx xxx xxx; geographic 02/03/07/08; 1300/1800; six-digit 13 xx xx;
 * +61 / 0061 international for mobile, landline, 1300, and 1800.
 *
 * @param string $input Raw user input.
 * @return bool
 */
function cf7_spam_filter_is_valid_australian_phone( $input ) {
	$d = cf7_spam_filter_phone_digits_only( $input );

	if ( '' === $d ) {
		return false;
	}

	// Some handsets / PBXs prefix international access 00.
	if ( str_starts_with( $d, '0061' ) ) {
		$d = '61' . substr( $d, 4 );
	}

	// 1300 / 1800 with +61 (12 digits: 61 + 1300/1800 + 6).
	if ( preg_match( '/^611300\d{6}$/', $d ) || preg_match( '/^611800\d{6}$/', $d ) ) {
		return true;
	}

	// Mobile or geographic with country code 61 (11 digits).
	if ( preg_match( '/^614\d{8}$/', $d ) || preg_match( '/^61[2378]\d{8}$/', $d ) ) {
		return true;
	}

	// National formats (10 digits).
	if ( preg_match( '/^04\d{8}$/', $d ) ) {
		return true;
	}
	if ( preg_match( '/^0[2378]\d{8}$/', $d ) ) {
		return true;
	}
	if ( preg_match( '/^1300\d{6}$/', $d ) || preg_match( '/^1800\d{6}$/', $d ) ) {
		return true;
	}

	// Six-digit 13 xx xx numbers.
	if ( preg_match( '/^13\d{4}$/', $d ) ) {
		return true;
	}

	return (bool) apply_filters( 'cf7_spam_filter_is_valid_australian_phone', false, $d, $input );
}

/**
 * Main spam filter.
 *
 * @param bool             $spam       Prior spam flag.
 * @param WPCF7_Submission $submission Submission.
 * @return bool
 */
function cf7_spam_filter_filter_spam( $spam, $submission ) {
	if ( $spam ) {
		return $spam;
	}

	if ( ! $submission instanceof WPCF7_Submission ) {
		return $spam;
	}

	if ( apply_filters( 'cf7_spam_filter_skip_all_checks', false, $submission ) ) {
		return false;
	}

	$form = $submission->get_contact_form();
	if ( ! $form ) {
		return $spam;
	}

	$form_id = (int) $form->id();
	$posted  = $submission->get_posted_data();
	if ( ! is_array( $posted ) ) {
		$posted = array();
	}

	// Honeypot: must stay empty (only when the field is present in POST).
	$hp = $submission->get_posted_data( '_cf7sp_hp' );
	if ( null !== $hp ) {
		$flat = cf7_spam_filter_flatten_values( $hp );
		$flat = array_filter( array_map( 'trim', $flat ) );
		if ( ! empty( $flat ) ) {
			return cf7_spam_filter_mark_spam( $submission, 'honeypot', __( 'Honeypot field was filled.', 'cf7-spam-plugin' ) );
		}
	}

	// Minimum time on page (seconds).
	$started = $submission->get_posted_data( '_cf7sp_started' );
	if ( null !== $started ) {
		$started_ts = absint( is_array( $started ) ? reset( $started ) : $started );
		$min_elapsed = (int) apply_filters( 'cf7_spam_filter_min_elapsed_seconds', 2, $submission, $form_id );
		if ( $started_ts > 0 && ( time() - $started_ts ) < $min_elapsed ) {
			return cf7_spam_filter_mark_spam(
				$submission,
				'timing',
				sprintf(
					/* translators: %d: minimum seconds */
					__( 'Form submitted faster than %d seconds (likely bot).', 'cf7-spam-plugin' ),
					$min_elapsed
				)
			);
		}
	}

	$ip = (string) $submission->get_meta( 'remote_ip' );
	if ( apply_filters( 'cf7_spam_filter_validate_ip', true, $submission ) && '' !== $ip && ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
		return cf7_spam_filter_mark_spam( $submission, 'ip_invalid', __( 'Submitter IP failed validation.', 'cf7-spam-plugin' ) );
	}

	// Rate limit per IP + form.
	$rate_max   = (int) apply_filters( 'cf7_spam_filter_rate_limit_max', 8, $form_id, $submission );
	$rate_window = (int) apply_filters( 'cf7_spam_filter_rate_limit_window', HOUR_IN_SECONDS, $form_id, $submission );

	if ( $rate_max > 0 && '' !== $ip ) {
		$key   = 'cf7sp_rl_' . md5( wp_hash( $ip . '|' . $form_id, 'cf7_spam_rate' ) );
		$count = (int) get_transient( $key );

		if ( $count >= $rate_max ) {
			return cf7_spam_filter_mark_spam(
				$submission,
				'rate_limit',
				__( 'Too many submissions from this address in a short period.', 'cf7-spam-plugin' )
			);
		}

		set_transient( $key, $count + 1, $rate_window );
	}

	// User-Agent checks (CF7 already flags unnaturally short UA).
	$ua = (string) $submission->get_meta( 'user_agent' );
	if ( apply_filters( 'cf7_spam_filter_check_user_agent', true, $submission ) ) {
		if ( '' === trim( $ua ) ) {
			return cf7_spam_filter_mark_spam( $submission, 'user_agent_empty', __( 'User-Agent header was empty.', 'cf7-spam-plugin' ) );
		}

		$ua_tokens = (array) apply_filters(
			'cf7_spam_filter_user_agent_spam_tokens',
			array(
				'curl/',
				'wget/',
				'python-requests',
				'httpclient',
				'go-http-client',
				'java/',
				'scrapy',
				'httpunit',
				'libwww-perl',
				'winhttp',
				'axios/',
			),
			$submission
		);

		foreach ( $ua_tokens as $token ) {
			if ( is_string( $token ) && '' !== $token && false !== stripos( $ua, $token ) ) {
				return cf7_spam_filter_mark_spam(
					$submission,
					'user_agent_token',
					sprintf(
						/* translators: %s: matched token */
						__( 'User-Agent matched blocked token: %s', 'cf7-spam-plugin' ),
						$token
					)
				);
			}
		}
	}

	// URL in text-like fields (GF-style).
	$url_check = apply_filters( 'cf7_spam_filter_enable_url_check', true, $submission );
	if ( $url_check ) {
		$pattern = '/' . cf7_spam_filter_url_pattern() . '/i';

		foreach ( (array) $form->scan_form_tags() as $tag ) {
			if ( ! cf7_spam_filter_should_check_urls_for_tag( $tag ) ) {
				continue;
			}

			$name = isset( $tag->name ) ? (string) $tag->name : '';
			if ( '' === $name ) {
				continue;
			}

			$value = $submission->get_posted_data( $name );
			if ( null === $value ) {
				continue;
			}

			foreach ( cf7_spam_filter_flatten_values( $value ) as $chunk ) {
				$chunk = trim( $chunk );
				if ( '' === $chunk ) {
					continue;
				}

				if ( preg_match( $pattern, $chunk ) ) {
					return cf7_spam_filter_mark_spam(
						$submission,
						'url_in_field',
						sprintf(
							/* translators: %s: field name */
							__( 'A URL or link pattern was found in field "%s".', 'cf7-spam-plugin' ),
							$name
						)
					);
				}
			}
		}
	}

	// Australian phone numbers only when a tel field exists on the form.
	if ( apply_filters( 'cf7_spam_filter_require_australian_phone', true, $form_id, $submission ) ) {
		$phone_basetypes = (array) apply_filters(
			'cf7_spam_filter_au_phone_basetypes',
			array( 'tel' ),
			$form_id,
			$submission
		);

		foreach ( (array) $form->scan_form_tags() as $tag ) {
			if ( ! is_object( $tag ) || empty( $tag->basetype ) ) {
				continue;
			}

			if ( ! in_array( $tag->basetype, $phone_basetypes, true ) ) {
				continue;
			}

			$name = isset( $tag->name ) ? (string) $tag->name : '';
			if ( '' === $name ) {
				continue;
			}

			$value = $submission->get_posted_data( $name );
			if ( null === $value ) {
				continue;
			}

			$chunks = array();
			foreach ( cf7_spam_filter_flatten_values( $value ) as $chunk ) {
				$chunk = trim( (string) $chunk );
				if ( '' !== $chunk ) {
					$chunks[] = $chunk;
				}
			}

			if ( empty( $chunks ) ) {
				continue;
			}

			foreach ( $chunks as $chunk ) {
				if ( ! cf7_spam_filter_is_valid_australian_phone( $chunk ) ) {
					return cf7_spam_filter_mark_spam(
						$submission,
						'phone_au',
						sprintf(
							/* translators: %s: field name */
							__( 'Telephone field "%s" must be a valid Australian phone number.', 'cf7-spam-plugin' ),
							$name
						)
					);
				}
			}
		}
	}

	// Identical first/last name parts (GF-style) for name fields.
	foreach ( (array) $form->scan_form_tags() as $tag ) {
		if ( ! is_object( $tag ) || empty( $tag->basetype ) || 'name' !== $tag->basetype ) {
			continue;
		}

		$name = isset( $tag->name ) ? (string) $tag->name : '';
		if ( '' === $name ) {
			continue;
		}

		$raw = $submission->get_posted_data( $name );
		if ( ! is_array( $raw ) ) {
			continue;
		}

		// CF7 multi-part name fields use "first" and "last" keys; skip otherwise.
		if ( ! array_key_exists( 'first', $raw ) || ! array_key_exists( 'last', $raw ) ) {
			continue;
		}

		$first = trim( (string) $raw['first'] );
		$last  = trim( (string) $raw['last'] );

		if ( '' !== $first && '' !== $last && cf7_spam_filter_lower( $first ) === cf7_spam_filter_lower( $last ) ) {
			return cf7_spam_filter_mark_spam(
				$submission,
				'name_duplicate',
				__( 'First and last name fields contained the same value.', 'cf7-spam-plugin' )
			);
		}
	}

	// Repeated identical non-meta string fields (simple bot pattern).
	$string_values = array();
	foreach ( $posted as $key => $value ) {
		if ( ! is_string( $key ) || str_starts_with( $key, '_' ) ) {
			continue;
		}
		foreach ( cf7_spam_filter_flatten_values( $value ) as $chunk ) {
			$chunk = trim( $chunk );
			if ( strlen( $chunk ) < 4 ) {
				continue;
			}
			$string_values[] = cf7_spam_filter_lower( $chunk );
		}
	}

	$dup_threshold = (int) apply_filters( 'cf7_spam_filter_duplicate_field_threshold', 4, $submission );
	if ( $dup_threshold > 0 && count( $string_values ) >= $dup_threshold ) {
		$counts = array_count_values( $string_values );
		foreach ( $counts as $val => $num ) {
			if ( $num >= $dup_threshold && strlen( $val ) > 6 ) {
				return cf7_spam_filter_mark_spam(
					$submission,
					'repeated_values',
					__( 'Multiple fields contained the same long text (automated pattern).', 'cf7-spam-plugin' )
				);
			}
		}
	}

	// Excessive repeated characters.
	$blob = cf7_spam_filter_collect_user_text( $posted );
	if ( preg_match( '/(.)\1{30,}/u', $blob ) ) {
		return cf7_spam_filter_mark_spam( $submission, 'char_repeat', __( 'Excessive repeated characters detected.', 'cf7-spam-plugin' ) );
	}

	// Keyword blocklist (substring, case-insensitive).
	$keywords = (array) apply_filters(
		'cf7_spam_filter_blocked_keywords',
		array(
			'viagra',
			'cialis',
			'seo service',
			'guest post',
			'link building',
			'cryptocurrency investment',
			'telegram:',
			'whatsapp:',
		),
		$form_id,
		$submission
	);

	$blob_lower = cf7_spam_filter_lower( $blob );
	foreach ( $keywords as $kw ) {
		if ( ! is_string( $kw ) || '' === $kw ) {
			continue;
		}
		$kw_lower = cf7_spam_filter_lower( $kw );
		if ( function_exists( 'mb_strpos' ) ) {
			$found = false !== mb_strpos( $blob_lower, $kw_lower, 0, 'UTF-8' );
		} else {
			$found = false !== strpos( $blob_lower, $kw_lower );
		}
		if ( $found ) {
			$kw_show = function_exists( 'mb_substr' ) ? mb_substr( $kw, 0, 40, 'UTF-8' ) : substr( $kw, 0, 40 );
			return cf7_spam_filter_mark_spam(
				$submission,
				'keyword',
				sprintf(
					/* translators: %s: matched keyword (may be truncated) */
					__( 'Blocked keyword or phrase matched: %s', 'cf7-spam-plugin' ),
					$kw_show
				)
			);
		}
	}

	// Domain blocklist in any submitted text.
	$domains = (array) apply_filters(
		'cf7_spam_filter_blocked_domains',
		array(),
		$form_id,
		$submission
	);

	foreach ( $domains as $domain ) {
		if ( ! is_string( $domain ) || '' === $domain ) {
			continue;
		}
		$domain = strtolower( trim( $domain ) );
		if ( false !== stripos( $blob_lower, $domain ) ) {
			return cf7_spam_filter_mark_spam(
				$submission,
				'domain',
				sprintf(
					/* translators: %s: domain */
					__( 'Blocked domain matched: %s', 'cf7-spam-plugin' ),
					$domain
				)
			);
		}
	}

	return false;
}
