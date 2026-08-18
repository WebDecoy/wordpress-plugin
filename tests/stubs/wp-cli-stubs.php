<?php
/**
 * Minimal WP-CLI stubs for static analysis only.
 *
 * WP-CLI's classes exist only when the CLI is running, so phpstan cannot see
 * them. This declares just the symbols class-webdecoy-cli.php uses. Never
 * loaded at runtime; referenced from phpstan.neon bootstrapFiles.
 */

// phpcs:ignoreFile

namespace {
    class WP_CLI
    {
        public static function add_command(string $name, $callable): void
        {
        }

        public static function log(string $message): void
        {
        }

        public static function warning(string $message): void
        {
        }

        public static function success(string $message): void
        {
        }

        /**
         * @return never
         */
        public static function error(string $message)
        {
            exit(1);
        }

        /**
         * @param array<string, mixed> $assoc_args
         */
        public static function confirm(string $question, array $assoc_args = []): void
        {
        }
    }
}

namespace WP_CLI\Utils {
    /**
     * @param array<int, array<string, mixed>> $items
     * @param array<int, string>               $fields
     */
    function format_items(string $format, array $items, array $fields): void
    {
    }
}
