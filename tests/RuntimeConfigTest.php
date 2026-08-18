<?php

declare(strict_types=1);

/**
 * Tests for the wp-config constant parsing (WebDecoy_Runtime_Config) and the
 * WP-CLI command's pure value handling. No WordPress or WP-CLI required.
 *
 * Run: php tests/run.php
 */

if (!defined('ABSPATH')) {
    define('ABSPATH', '/tmp/');
}
require_once dirname(__DIR__) . '/includes/class-webdecoy-runtime-config.php';
require_once dirname(__DIR__) . '/includes/class-webdecoy-cli.php';

$t = ['TestRunner', 'test'];
$same = ['TestRunner', 'assertSame'];
$true = ['TestRunner', 'assertTrue'];

echo "\nRuntime config: WEBDECOY_DEFAULT_MODE parsing\n";

$t('monitor and block parse, case- and space-insensitively', function () use ($same) {
    $same(true, WebDecoy_Runtime_Config::forced_monitor_mode('monitor'));
    $same(true, WebDecoy_Runtime_Config::forced_monitor_mode(' Monitor '));
    $same(false, WebDecoy_Runtime_Config::forced_monitor_mode('block'));
    $same(false, WebDecoy_Runtime_Config::forced_monitor_mode('BLOCK'));
});

$t('an unrecognized mode is ignored, never guessed', function () use ($same) {
    // A typo must not pick a side: forcing 'block' would enforce on a site
    // that asked to watch; forcing 'monitor' would disarm one that asked to
    // enforce.
    $same(null, WebDecoy_Runtime_Config::forced_monitor_mode('monitoring'));
    $same(null, WebDecoy_Runtime_Config::forced_monitor_mode(''));
    $same(null, WebDecoy_Runtime_Config::forced_monitor_mode(true));
    $same(null, WebDecoy_Runtime_Config::forced_monitor_mode(1));
});

echo "\nRuntime config: WEBDECOY_MAX_LOG_RETENTION bounds\n";

$t('retention clamps instead of rejecting', function () use ($same) {
    $same(30, WebDecoy_Runtime_Config::log_retention_days('not a number'));
    $same(7, WebDecoy_Runtime_Config::log_retention_days(7));
    $same(7, WebDecoy_Runtime_Config::log_retention_days('7'));
    $same(1, WebDecoy_Runtime_Config::log_retention_days(0));
    $same(1, WebDecoy_Runtime_Config::log_retention_days(-5));
    $same(3650, WebDecoy_Runtime_Config::log_retention_days(999999));
});

echo "\nRuntime config: allowlist entry validation\n";

$t('valid IPs and CIDRs pass, junk does not', function () use ($same) {
    $same('203.0.113.7', WebDecoy_Runtime_Config::validate_ip_or_cidr(' 203.0.113.7 '));
    $same('2001:db8::1', WebDecoy_Runtime_Config::validate_ip_or_cidr('2001:db8::1'));
    $same('10.0.0.0/8', WebDecoy_Runtime_Config::validate_ip_or_cidr('10.0.0.0/8'));
    $same('2001:db8::/48', WebDecoy_Runtime_Config::validate_ip_or_cidr('2001:db8::/48'));
    $same(null, WebDecoy_Runtime_Config::validate_ip_or_cidr('example.com'));
    $same(null, WebDecoy_Runtime_Config::validate_ip_or_cidr('10.0.0.0/999'));
    $same(null, WebDecoy_Runtime_Config::validate_ip_or_cidr('10.0.0.0/-1'));
    $same(null, WebDecoy_Runtime_Config::validate_ip_or_cidr(''));
});

echo "\nWP-CLI: config value parsing\n";

$t('mode maps to monitor_mode with the same strictness as the constant', function () use ($same) {
    $same(['monitor_mode', true], WebDecoy_CLI_Command::parse_config_value('mode', 'monitor'));
    $same(['monitor_mode', false], WebDecoy_CLI_Command::parse_config_value('mode', 'block'));
    $same(null, WebDecoy_CLI_Command::parse_config_value('mode', 'off'));
});

$t('booleans accept the usual spellings and nothing else', function () use ($same) {
    $same(['block_ai_crawlers', true], WebDecoy_CLI_Command::parse_config_value('block_ai_crawlers', 'true'));
    $same(['block_ai_crawlers', true], WebDecoy_CLI_Command::parse_config_value('block_ai_crawlers', 'ON'));
    $same(['block_ai_crawlers', false], WebDecoy_CLI_Command::parse_config_value('block_ai_crawlers', '0'));
    $same(null, WebDecoy_CLI_Command::parse_config_value('block_ai_crawlers', 'maybe'));
});

$t('ints enforce their ranges', function () use ($same) {
    $same(['min_score_to_block', 75], WebDecoy_CLI_Command::parse_config_value('min_score_to_block', '75'));
    $same(null, WebDecoy_CLI_Command::parse_config_value('min_score_to_block', '101'));
    $same(null, WebDecoy_CLI_Command::parse_config_value('min_score_to_block', '-1'));
    $same(null, WebDecoy_CLI_Command::parse_config_value('min_score_to_block', 'high'));
});

$t('enums are closed sets', function () use ($same) {
    $same(['sensitivity', 'high'], WebDecoy_CLI_Command::parse_config_value('sensitivity', 'High'));
    $same(null, WebDecoy_CLI_Command::parse_config_value('sensitivity', 'paranoid'));
    $same(['block_action', 'challenge'], WebDecoy_CLI_Command::parse_config_value('block_action', 'challenge'));
});

$t('keys outside the whitelist are rejected, including the dangerous ones', function () use ($same) {
    // api_key is stored encrypted; a raw CLI write would corrupt it. The
    // org fields belong to the connect flow.
    $same(null, WebDecoy_CLI_Command::parse_config_value('api_key', 'sk_live_x'));
    $same(null, WebDecoy_CLI_Command::parse_config_value('organization_id', 'abc'));
    $same(null, WebDecoy_CLI_Command::parse_config_value('nonsense', '1'));
});

$t('display_value renders mode and booleans for humans', function () use ($same) {
    $same('monitor', WebDecoy_CLI_Command::display_value('mode', ['monitor_mode' => true]));
    $same('block', WebDecoy_CLI_Command::display_value('mode', ['monitor_mode' => false]));
    $same('true', WebDecoy_CLI_Command::display_value('protect_login', ['protect_login' => true]));
    $same('75', WebDecoy_CLI_Command::display_value('min_score_to_block', ['min_score_to_block' => 75]));
});
