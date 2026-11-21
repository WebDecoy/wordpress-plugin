<?php

declare(strict_types=1);

/**
 * One sentence for what a detection was, shared by the Detections page and the
 * post-CRITICAL admin notice. The notice used to say "a deception trap was just
 * tripped" for every CRITICAL row; a visitor claiming to be Googlebot from the
 * wrong address produced it. Run: php tests/run.php
 */

require_once dirname(__DIR__) . '/sdk/src/HitExplanation.php';
require_once dirname(__DIR__) . '/includes/class-webdecoy-detection-summary.php';
require_once dirname(__DIR__) . '/includes/class-webdecoy-critical-moment.php';

$t = ['TestRunner', 'test'];
$true = ['TestRunner', 'assertTrue'];
$same = ['TestRunner', 'assertSame'];

echo "\nDetection summary: one sentence for what happened\n";

$row = static function (array $flags, array $meta = []): string {
    return (string) json_encode(['flags' => $flags, 'metadata' => $meta]);
};

$t('a fake crawler is named as a claim, not a trap', function () use ($row, $true) {
    $s = WebDecoy_Detection_Summary::sentence($row(['fake_bot', 'bot_verification_failed'], ['claimed_bot' => 'Googlebot']));
    $true(strpos($s, 'claimed to be Googlebot') !== false, $s);
    $true(stripos($s, 'trap') === false, 'a fake crawler is not a trap: ' . $s);
});

$t('a decoy hit keeps the digest wording', function () use ($row, $true) {
    $s = WebDecoy_Detection_Summary::sentence($row(['tripwire_rule'], ['path' => '/wp-admin/backup.zip']));
    $true($s !== '' && $s === \WebDecoy\HitExplanation::forLocalFlags($row(['tripwire_rule'], ['path' => '/wp-admin/backup.zip'])), 'same words as HitExplanation: ' . $s);
});

$t('the common server findings each get a sentence', function () use ($row, $true) {
    foreach ([
        [['canary_credential_use'], [], 'decoy password'],
        [['ai_crawler_blocked'], ['bot_info' => ['name' => 'GPTBot']], 'GPTBot'],
        [['crawler_refused'], ['bot_info' => ['name' => 'CCBot']], 'CCBot'],
        [['honeypot_triggered'], [], 'hidden field'],
        [['headless'], [], 'automated browser'],
        [['cli_tool'], [], 'command-line'],
        [['empty_user_agent'], [], 'did not say'],
    ] as [$flags, $meta, $needle]) {
        $s = WebDecoy_Detection_Summary::sentence($row($flags, $meta));
        $true(strpos($s, $needle) !== false, implode(',', $flags) . ' -> ' . $s);
    }
});

$t('nothing to say stays empty, and junk never breaks it', function () use ($row, $same) {
    $same('', WebDecoy_Detection_Summary::sentence($row(['missing_accept_language'])), 'no specific sentence');
    $same('', WebDecoy_Detection_Summary::sentence(null), 'null');
    $same('', WebDecoy_Detection_Summary::sentence('not json'), 'not json');
    // How rows from the in-page check are now stored: a plain list.
    $same('', WebDecoy_Detection_Summary::sentence('["canary_credential_use","tripwire_rule"]'), 'a plain list is never put into words');
});

$t('a crawler name is printed safely', function () use ($row, $true) {
    $s = WebDecoy_Detection_Summary::sentence($row(['fake_bot'], ['claimed_bot' => '<script>x</script>Googlebot']));
    $true(strpos($s, '<') === false && strpos($s, '>') === false, $s);
});

echo "\nCritical moment headline\n";

$t('the notice says what happened, and only a trap is called a trap', function () use ($row, $true, $same) {
    $fake = WebDecoy_Critical_Moment::headline(WebDecoy_Detection_Summary::sentence($row(['fake_bot'], ['claimed_bot' => 'Googlebot'])));
    $true(strpos($fake, 'Googlebot') !== false && stripos($fake, 'trap') === false, $fake);
    $same('A CRITICAL detection was recorded on your site.', WebDecoy_Critical_Moment::headline(''), 'no sentence');
    $src = (string) file_get_contents(dirname(__DIR__) . '/includes/class-webdecoy-critical-moment.php');
    $true(strpos($src, 'deception trap was just tripped') === false, 'the blanket trap claim is gone');
});

// Read from source: these are inside methods that need a full WordPress.
$t('a browser-reported row can neither raise the notice nor be put into words', function () use ($true) {
    $src = (string) file_get_contents(dirname(__DIR__) . '/webdecoy.php');
    $a = strpos($src, 'private function log_client_detection');
    $b = $a === false ? false : strpos($src, "\n    }\n", $a);
    $body = ($a === false || $b === false) ? '' : substr($src, $a, $b - $a);
    $true($body !== '', 'found log_client_detection');
    $true(strpos($body, 'flag_critical_moment(') === false, 'client rows must not queue the CRITICAL notice');
    $true(strpos($body, "array_filter(\$client_flags, 'is_string')") !== false, 'client flags are stored as a plain list');
});

$t('first activation opens the AI Traffic page once, and never for bulk or CLI', function () use ($true) {
    $src = (string) file_get_contents(dirname(__DIR__) . '/webdecoy.php');
    $a = strpos($src, 'public function maybe_first_run_redirect');
    $body = $a === false ? '' : substr($src, $a, 1200);
    foreach (["delete_transient(self::FIRST_RUN_REDIRECT)", "activate-multi", "wp_doing_ajax()", "WP_CLI", "current_user_can('manage_options')"] as $guard) {
        $true(strpos($body, $guard) !== false, 'redirect guard missing: ' . $guard);
    }
    $true(strpos($body, 'delete_transient') < strpos($body, 'wp_safe_redirect'), 'the flag is consumed before redirecting, so it can never loop');
});
