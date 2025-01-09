# Contact Form 7 Spam Filters by Pivotal Agency

A Contact Form 7 add-on to validate Australian phone numbers and block non-Australian IP addresses.

## Installation

```bash
# 1. Get it ready (to use a repo outside of packagist)
composer config repositories.cf7-spam-filter git https://github.com/pvtl/cf7-spam-filter.git

# 2. Install the Plugin - we want all updates from this major version (while non-breaking)
composer require pvtl/cf7-spam-filter
```

## Dynamically Adding Nonce to Contact Form 7
Add this PHP code to the themes functions.php:

```
add_action( 'wpcf7_init', function () {
    wpcf7_add_form_tag( 'nonce', 'cf7_add_nonce_field', true );
});

function cf7_add_nonce_field( $tag ) {
    return wp_nonce_field( 'cf7_form_submission', 'cf7_nonce', true, false );
}
```

Add in the shortcode to your Contact Form 7 Form:
```
[nonce]
```

## IP Token Generation

In order for the International IPs to be blocked please go to https://ipinfo.io/ and generate a new access token.

Add the token into the .env file
```
IPINFO_TOKEN='ACCESS_TOKEN'
```