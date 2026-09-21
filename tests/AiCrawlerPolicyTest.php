<?php

declare(strict_types=1);

/**
 * The "Block AI crawlers" setting is an instruction, not a scoring hint.
 *
 * It used to withdraw the crawler's good-bot pass and leave the outcome to
 * heuristic scoring, where a recognised bot earns no user-agent points. A
 * well-behaved AI crawler could therefore finish under the block threshold.
 * These tests pin the behaviour: on means refused, at any threshold; off means
 * a good bot; other categories and the custom allowlist are unaffected.
 *
 * Run: php tests/run.php
 */

if (!defined('ABSPATH')) {
    define('ABSPATH', '/tmp/');
}
if (!function_exists('get_transient')) {
    function get_transient($key) { return false; }
}
if (!function_exists('set_transient')) {
    function set_transient($key, $value, $ttl = 0) { return true; }
}
foreach (['DetectionResult', 'GoodBotList', 'SignalCollector', 'MitreMapping', 'BotDetector'] as $class) {
    $file = dirname(__DIR__) . '/sdk/src/' . $class . '.php';
    if (is_file($file)) {
        require_once $file;
    }
}

$t = ['TestRunner', 'test'];
$same = ['TestRunner', 'assertSame'];
$true = ['TestRunner', 'assertTrue'];

const AI_POLICY_DEFAULT_THRESHOLD = 75;

function ai_policy_analyze(string $userAgent, array $options, bool $browserHeaders = true): \WebDecoy\DetectionResult
{
    $_SERVER = [
        'HTTP_USER_AGENT' => $userAgent,
        'REMOTE_ADDR' => '203.0.113.9',
        'REQUEST_URI' => '/premium/article',
        'REQUEST_METHOD' => 'GET',
    ];
    if ($browserHeaders) {
        $_SERVER += ['HTTP_ACCEPT' => '*/*', 'HTTP_ACCEPT_ENCODING' => 'gzip', 'HTTP_ACCEPT_LANGUAGE' => 'en'];
    }
    return (new \WebDecoy\BotDetector($options))->analyze();
}

const AI_POLICY_GPTBOT = 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)';
const AI_POLICY_CLAUDEBOT = 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +claudebot@anthropic.com)';
const AI_POLICY_GOOGLEBOT = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';

echo "\nAI crawler policy: the block setting blocks\n";

$t('with the setting on, an AI crawler is blocked at the default threshold', function () use ($true, $same) {
    foreach ([AI_POLICY_GPTBOT, AI_POLICY_CLAUDEBOT] as $ua) {
        $result = ai_policy_analyze($ua, ['block_ai_crawlers' => true]);
        $true($result->shouldBlock(AI_POLICY_DEFAULT_THRESHOLD), 'served despite the setting: ' . $ua);
        $true(in_array('ai_crawler_blocked', $result->getFlags(), true), 'the reason must be visible in the log');
        $same(false, $result->isGoodBot());
    }
});

$t('it clears even the strictest threshold a site can set', function () use ($true) {
    $true(ai_policy_analyze(AI_POLICY_GPTBOT, ['block_ai_crawlers' => true])->shouldBlock(100));
});

$t('with the setting off, an AI crawler is still a good bot', function () use ($same) {
    $result = ai_policy_analyze(AI_POLICY_GPTBOT, ['block_ai_crawlers' => false]);
    $same(0, $result->getScore());
    $same(true, $result->isGoodBot());
});

$t('the setting does not touch search engines', function () use ($same) {
    $result = ai_policy_analyze(AI_POLICY_GOOGLEBOT, ['block_ai_crawlers' => true, 'verify_bot_ips' => false]);
    $same(false, $result->shouldBlock(AI_POLICY_DEFAULT_THRESHOLD));
    $same(false, in_array('ai_crawler_blocked', $result->getFlags(), true));
});

$t('a crawler on the custom allowlist is not blocked by the category setting', function () use ($same) {
    $result = ai_policy_analyze(AI_POLICY_GPTBOT, ['block_ai_crawlers' => true, 'custom_allowlist' => ['GPTBot']]);
    $same(false, $result->shouldBlock(AI_POLICY_DEFAULT_THRESHOLD));
    $same(true, $result->isGoodBot());
});
