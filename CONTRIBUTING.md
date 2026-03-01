# Contributing to WebDecoy

Thank you for your interest in contributing to WebDecoy! This guide covers setup, coding standards, and the pull request process.

## Development Environment

1. A local WordPress installation (5.6+) with PHP 7.4 or higher.
2. [WooCommerce](https://woocommerce.com/) installed if working on payment protection features.
3. Clone or symlink this plugin into `wp-content/plugins/webdecoy/`.
4. Install dev dependencies:

```bash
composer install
```

## Code Style

This project follows the [WordPress Coding Standards](https://developer.wordpress.org/coding-standards/wordpress-coding-standards/php/). All PHP files are checked automatically by PHPCS.

Run the linter:

```bash
vendor/bin/phpcs
```

Auto-fix what can be fixed:

```bash
vendor/bin/phpcbf
```

## Static Analysis

PHPStan is configured at level 5. Run it with:

```bash
vendor/bin/phpstan analyse
```

## PHP Compatibility

The plugin supports PHP 7.4 and above. Check compatibility with:

```bash
vendor/bin/phpcs --standard=PHPCompatibilityWP --runtime-set testVersion 7.4- .
```

## Submitting a Pull Request

1. Fork the repository and create a feature branch from `main`.
2. Make your changes, keeping commits focused and well-described.
3. Ensure all checks pass: PHPCS, PHPStan, and PHP compatibility.
4. Open a pull request against `main` with a clear description of the change.

## Testing Checklist

Before submitting, manually verify:

- [ ] Plugin activates and deactivates without errors.
- [ ] Settings page loads and saves correctly.
- [ ] Detections page displays data properly.
- [ ] Dashboard widget renders without errors.
- [ ] No PHP notices, warnings, or errors in the debug log.
- [ ] If WooCommerce-related: checkout and order flow work normally.

## Reporting Issues

Open an issue with:

- WordPress and PHP versions.
- Steps to reproduce.
- Expected vs. actual behavior.
- Any relevant error log output.
