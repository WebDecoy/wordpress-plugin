<?php

declare(strict_types=1);

/**
 * Crawler visit counters: which agent a request is, how sure we are, and how
 * the counters fold into the widget's summary. Also pins the two promises the
 * feature makes: only requests naming a known agent are counted, and nothing
 * about a request but the agent and its verification state is stored.
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
foreach (['DetectionResult', 'AgentRegistry', 'GoodBotList', 'SignalCollector', 'MitreMapping', 'BotDetector'] as $class) {
    $file = dirname(__DIR__) . '/sdk/src/' . $class . '.php';
    if (is_file($file)) {
        require_once $file;
    }
}
require_once dirname(__DIR__) . '/includes/class-webdecoy-crawler-visits.php';

$t = ['TestRunner', 'test'];
$same = ['TestRunner', 'assertSame'];
$true = ['TestRunner', 'assertTrue'];

const CV_GPTBOT = 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)';
const CV_GOOGLEBOT = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
const CV_CHROME = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36';
const CV_SAFARI_IPHONE = 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1';

echo "\nCrawler visits: classify\n";

$t('a browser User-Agent is not counted at all', function () use ($same) {
    $same(null, WebDecoy_Crawler_Visits::classify(CV_CHROME, [], false), 'desktop Chrome');
    $same(null, WebDecoy_Crawler_Visits::classify(CV_SAFARI_IPHONE, [], false), 'iPhone Safari');
    $same(null, WebDecoy_Crawler_Visits::classify('', [], false), 'empty User-Agent');
});

$t('a known agent with no verification result is claimed', function () use ($same) {
    $same(
        ['agent_id' => 'gptbot', 'verification' => 'claimed'],
        WebDecoy_Crawler_Visits::classify(CV_GPTBOT, ['good_bot'], false)
    );
});

$t('the detector\'s DNS verdict decides verified and failed', function () use ($same) {
    $same('verified', WebDecoy_Crawler_Visits::classify(CV_GOOGLEBOT, ['verified_good_bot'], false)['verification']);
    $same('failed', WebDecoy_Crawler_Visits::classify(CV_GOOGLEBOT, ['fake_bot', 'bot_verification_failed'], false)['verification']);
    $same('googlebot', WebDecoy_Crawler_Visits::classify(CV_GOOGLEBOT, [], false)['agent_id']);
});

$t('behind an unconfigured proxy a failed check is only a claim', function () use ($same) {
    $same('claimed', WebDecoy_Crawler_Visits::classify(CV_GOOGLEBOT, ['fake_bot', 'bot_verification_failed'], true)['verification']);
    // A pass is still a pass: the proxy's address cannot verify as Googlebot.
    $same('verified', WebDecoy_Crawler_Visits::classify(CV_GOOGLEBOT, ['verified_good_bot'], true)['verification']);
});

$t('classification reads the real detector\'s flags', function () use ($same) {
    $_SERVER = [
        'HTTP_USER_AGENT' => CV_GPTBOT,
        'REMOTE_ADDR' => '203.0.113.9',
        'REQUEST_URI' => '/',
        'REQUEST_METHOD' => 'GET',
        'HTTP_ACCEPT' => '*/*',
    ];
    $result = (new \WebDecoy\BotDetector([]))->analyze();
    $same('claimed', WebDecoy_Crawler_Visits::classify(CV_GPTBOT, $result->getFlags(), false)['verification']);

    // Block AI crawlers on: still counted, the refusal changes nothing here.
    $refused = (new \WebDecoy\BotDetector(['block_ai_crawlers' => true]))->analyze();
    $same('claimed', WebDecoy_Crawler_Visits::classify(CV_GPTBOT, $refused->getFlags(), false)['verification']);
});

$t('the flag names classify depends on are the ones BotDetector sets', function () use ($true) {
    $src = (string) file_get_contents(dirname(__DIR__) . '/sdk/src/BotDetector.php');
    $true(strpos($src, "addFlag('verified_good_bot')") !== false, 'verified_good_bot');
    $true(strpos($src, "addFlag('bot_verification_failed')") !== false, 'bot_verification_failed');
});

echo "\nCrawler visits: summary\n";

$t('rows fold into totals, groups and a busiest-first agent list', function () use ($same) {
    $s = WebDecoy_Crawler_Visits::summarize([
        ['agent_id' => 'googlebot', 'verification' => 'verified', 'hits' => '40'],
        ['agent_id' => 'googlebot', 'verification' => 'failed', 'hits' => 3],
        ['agent_id' => 'gptbot', 'verification' => 'claimed', 'hits' => 12],
        ['agent_id' => 'claudebot', 'verification' => 'claimed', 'hits' => 50],
    ]);
    $same(105, $s['total']);
    $same(40, $s['verified']);
    $same(62, $s['claimed']);
    $same(3, $s['failed']);
    $same(['ai' => 62, 'search' => 43, 'other' => 0], $s['groups']);
    $same(['claudebot', 'googlebot', 'gptbot'], array_column($s['agents'], 'id'));
    $same(43, $s['agents'][1]['hits']);
    $same(3, $s['agents'][1]['failed']);
    $same('Anthropic', $s['agents'][0]['organization']);
});

$t('unknown states, empty ids and zero counts are ignored', function () use ($same) {
    $s = WebDecoy_Crawler_Visits::summarize([
        ['agent_id' => 'gptbot', 'verification' => 'bogus', 'hits' => 9],
        ['agent_id' => '', 'verification' => 'claimed', 'hits' => 9],
        ['agent_id' => 'gptbot', 'verification' => 'claimed', 'hits' => 0],
    ]);
    $same(0, $s['total']);
    $same([], $s['agents']);
});

$t('an id the registry no longer has still shows, under its id', function () use ($same) {
    $s = WebDecoy_Crawler_Visits::summarize([
        ['agent_id' => 'retired-bot', 'verification' => 'claimed', 'hits' => 2],
    ]);
    $same('retired-bot', $s['agents'][0]['name']);
    $same('other', $s['agents'][0]['group']);
    $same(2, $s['groups']['other']);
});

$t('every registry category has a label and a group', function () use ($true) {
    foreach (\WebDecoy\AgentRegistry::categories() as $category) {
        if ($category === 'none') {
            continue;
        }
        $true(WebDecoy_Crawler_Visits::category_label($category) !== 'Other bot', 'label for ' . $category);
        $true(in_array(WebDecoy_Crawler_Visits::group($category), ['ai', 'search', 'other'], true), 'group for ' . $category);
    }
});

$t('counters are bucketed by the UTC hour', function () use ($same) {
    $same('2026-11-10 13:00:00', WebDecoy_Crawler_Visits::bucket(gmmktime(13, 59, 59, 11, 10, 2026)));
    $same('2026-11-10 14:00:00', WebDecoy_Crawler_Visits::bucket(gmmktime(14, 0, 0, 11, 10, 2026)));
});

echo "\nCrawler visits: what is stored\n";

$t('the counter table holds no address, User-Agent or path', function () use ($true) {
    $src = (string) file_get_contents(dirname(__DIR__) . '/includes/class-webdecoy-activator.php');
    $start = strpos($src, 'webdecoy_crawler_visits (');
    $true($start !== false, 'table definition present');
    $ddl = substr($src, $start, (int) strpos($src, ') $charset_collate', $start) - $start);
    foreach (['ip', 'user_agent', 'path', 'url', 'referer', 'host'] as $column) {
        $true(preg_match('/\b' . $column . '\b/i', $ddl) === 0, 'no ' . $column . ' column');
    }
});

$t('the only write is the four-column counter upsert', function () use ($true, $same) {
    $src = (string) file_get_contents(dirname(__DIR__) . '/includes/class-webdecoy-crawler-visits.php');
    $same(1, preg_match_all('/INSERT INTO/', $src), 'one INSERT');
    $true(strpos($src, '(bucket, agent_id, verification, hits) VALUES (%s, %s, %s, 1)') !== false, 'columns');
});

$t('early_check counts before the good-bot exit', function () use ($true) {
    $src = (string) file_get_contents(dirname(__DIR__) . '/webdecoy.php');
    $observe = strpos($src, 'WebDecoy_Crawler_Visits::observe(');
    $exit = strpos($src, 'if ($result->isGoodBot()) {');
    $true($observe !== false && $exit !== false, 'both present');
    $true($observe < $exit, 'observe precedes the good-bot return');
});
