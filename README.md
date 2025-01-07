# Contact Form 7 Spam Filters by Pivotal Agency

A Contact Form 7 add-on to validate Australian phone numbers and block non-Australian IP addresses.

## Installation

```bash
# 1. Get it ready (to use a repo outside of packagist)
composer config repositories.cf7-spam-filter git https://github.com/pvtl/cf7-spam-filter.git

# 2. Install the Plugin - we want all updates from this major version (while non-breaking)
composer require "pvtl/cf7-spam-filter:~1.0"
```

## Versioning

_Do not manually create tags_.

Versioning comprises of 2 things:

- Wordpress plugin version
    - The version number used by Wordpress on the plugins screen (and various other peices of functionality to track the version number)
    - Controlled in `./cf7-spam-filter.php` by `* Version: x.x.x` (line 11)
- Composer dependency version
    - The version Composer uses to know which version of the plugin to install
    - Controlled by Git tags

Versioning for this plugin is automated using a Github Action (`./.github/workflows/version-update.yml`).
To release a new version, simply change the `* Version: x.x.x` (line 11) in `./training.php` - the Github Action will take care of the rest.
