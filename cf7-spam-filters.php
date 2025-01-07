<?php
/*
 * Plugin Name: CF7 Spam Filter
 * Description: A Contact Form 7 add-on to validate Australian phone numbers and block non-Australian IP addresses.
 * Author:          Pivotal Agency
 * Author URI:      http://pivotal.agency
 * Text Domain:     cf7-spam-filter
 * Domain Path:     /languages
 * Version:         1.0.2
 * License: GPL2
*/


// Prevent direct access
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

// Hook into Contact Form 7 validation for telephone fields
add_filter( 'wpcf7_validate_tel', 'cf7_validate_australian_phone', 20, 2 );
add_filter( 'wpcf7_validate_tel*', 'cf7_validate_australian_phone', 20, 2 );

function cf7_validate_australian_phone( $result, $tag ) {
    $tag_name = $tag['name'];

    // Ensure the validation applies only to the "phone" field
    if ( 'phone' === $tag_name ) {
        $phone = isset( $_POST[$tag_name] ) ? sanitize_text_field( $_POST[$tag_name] ) : '';

        // Validate the phone number
        if ( ! preg_match( '/^(04|02|03|05|07|08)\d{8}$/', $phone ) ) {
            $result->invalidate( $tag, 'Please enter a valid Australian phone number.' );
        }
    }

    return $result;
}

// Hook to block international IPs
add_action( 'wpcf7_before_send_mail', 'cf7_block_non_australian_ips' );

function cf7_block_non_australian_ips( $contact_form ) {
    $submission = WPCF7_Submission::get_instance();

    if ( $submission ) {
        // Get the client's IP address
        $client_ip = $_SERVER['REMOTE_ADDR'];
        $access_token = 'fe2074f59b77cf'; // Your ipinfo.io access token

        // Use the ipinfo.io API with the access token
        $ip_info_url = "https://ipinfo.io/{$client_ip}/json?token={$access_token}";
        $ip_info = wp_remote_get( $ip_info_url );

        if ( is_wp_error( $ip_info ) ) {
            return; // Fail silently if the API call fails
        }

        $ip_data = json_decode( wp_remote_retrieve_body( $ip_info ), true );

        // Check if the country is Australia (AU)
        if ( isset( $ip_data['country'] ) && $ip_data['country'] !== 'AU' ) {
            $submission->set_status( 'validation_failed' );
            $submission->set_response( array(
                'message' => 'Submission blocked: Non-Australian IP addresses are not allowed.',
            ) );
            wp_die( __( 'Submission blocked: Non-Australian IP addresses are not allowed.', 'wpcf7' ) );
        }
    }
}
