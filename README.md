# WebDecoy Bot Detection

[![WordPress Version](https://img.shields.io/badge/WordPress-5.6%2B-blue.svg)](https://wordpress.org/)
[![PHP Version](https://img.shields.io/badge/PHP-7.4%2B-8892BF.svg)](https://php.net/)
[![License](https://img.shields.io/badge/License-GPLv2%2B-green.svg)](https://www.gnu.org/licenses/gpl-2.0.html)
[![CI](https://github.com/WebDecoy/wordpress-plugin/actions/workflows/ci.yml/badge.svg)](https://github.com/WebDecoy/wordpress-plugin/actions)

Zero-configuration bot protection for WordPress. Works immediately on activation with no account, no API key, and no external dependencies. Multi-layer detection uses invisible proof-of-work challenges so legitimate visitors are never interrupted.

## Features

- **Zero friction** -- Humans never see CAPTCHAs or challenges
- **Zero configuration** -- Install, activate, done
- **Multi-layer detection** -- Server-side analysis, client-side fingerprinting, and proof-of-work challenges
- **Good bot verification** -- Reverse DNS verification for Googlebot, Bingbot, and other legitimate crawlers
- **MITRE ATT&CK path analysis** -- Detects admin probing and config file access attempts
- **Rate limiting** -- Automatic blocking with configurable thresholds
- **IP blocking** -- Individual and CIDR ranges, IPv4/IPv6, with optional expiration
- **WooCommerce integration** -- Checkout protection against carding attacks
- **Dashboard & statistics** -- Detection trends, threat breakdown, and recent activity

## Installation

### From WordPress.org

1. Go to **Plugins > Add New** in your WordPress admin
2. Search for "WebDecoy Bot Detection"
3. Click **Install Now**, then **Activate**

### Manual Installation

1. Download the latest release ZIP from the [Releases](https://github.com/WebDecoy/wordpress-plugin/releases) page
2. Go to **Plugins > Add New > Upload Plugin**
3. Upload the ZIP file and click **Install Now**
4. Activate the plugin

## Development

### Prerequisites

- PHP 7.4+
- [Composer](https://getcomposer.org/)

### Setup

```bash
composer install
```

### Coding Standards

```bash
composer run phpcs
```

### Static Analysis

```bash
composer run phpstan
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed contribution guidelines.

## License

This project is licensed under the GPL v2 or later. See [license.txt](license.txt) for details.
