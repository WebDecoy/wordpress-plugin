<?php

declare(strict_types=1);

/**
 * Violation delivery when WebDecoy is unavailable or two drains overlap
 * (WebDecoy/app#1245).
 *
 * Every request that records a violation drains the spool at shutdown, and the
 * cron drains it too. Two drains at once read the same oldest rows and sent
 * them twice; a refusal spent the rows' attempts, so an outage of two drains
 * discarded them. Named to load after HoneytokenTest and IpEnrichmentBackoffTest,
 * whose option and HTTP stubs this uses.
 *
 * Run: php tests/run.php
 */

if (!defined('ABSPATH')) {
    define('ABSPATH', '/tmp/');
}
require_once dirname(__DIR__) . '/includes/class-webdecoy-detection-sender.php';
require_once dirname(__DIR__) . '/includes/class-webdecoy-violation-reporter.php';

if (!function_exists('delete_option')) {
    function delete_option($k) { unset($GLOBALS['__wd_opts'][$k]); return true; }
}
if (!function_exists('wp_json_encode')) {
    function wp_json_encode($v) { return json_encode($v); }
}
if (!function_exists('wp_remote_post')) {
    function wp_remote_post($url, $args = []) {
        $GLOBALS['wd_test_post']['calls']++;
        return ['code' => $GLOBALS['wd_test_post']['code']];
    }
}

/** Just enough of $wpdb for the spool queries. */
final class WdFakeSpool
{
    public $prefix = 'wp_';
    /** @var array<int,array{id:int,payload:string,attempts:int}> */
    public $rows = [];

    public function prepare($sql, ...$args) { return vsprintf(str_replace(['%d', '%s'], ['%d', "'%s'"], $sql), $args); }
    public function get_var($sql) { return count($this->rows); }
    public function get_results($sql)
    {
        $out = [];
        foreach (array_slice($this->rows, 0, 100) as $r) {
            $out[] = (object) ['id' => $r['id'], 'payload' => $r['payload']];
        }
        return $out;
    }
    public function delete($table, $where) { $this->rows = array_values(array_filter($this->rows, fn($r) => $r['id'] !== $where['id'])); }
    public function query($sql)
    {
        if (preg_match('/DELETE FROM \S+ WHERE id IN \(([\d,]+)\)/', $sql, $m)) {
            $ids = array_map('intval', explode(',', $m[1]));
            $this->rows = array_values(array_filter($this->rows, fn($r) => !in_array($r['id'], $ids, true)));
        } elseif (preg_match('/SET attempts = attempts \+ 1 WHERE id IN \(([\d,]+)\)/', $sql, $m)) {
            $ids = array_map('intval', explode(',', $m[1]));
            foreach ($this->rows as &$r) {
                if (in_array($r['id'], $ids, true)) $r['attempts']++;
            }
        } elseif (preg_match('/WHERE attempts >= (\d+)/', $sql, $m)) {
            $max = (int) $m[1];
            $this->rows = array_values(array_filter($this->rows, fn($r) => $r['attempts'] < $max));
        }
        return true;
    }
}

function wd_spool(int $n): WdFakeSpool
{
    $db = new WdFakeSpool();
    for ($i = 1; $i <= $n; $i++) {
        $db->rows[] = ['id' => $i, 'payload' => json_encode(['rule' => 'tripwire', 'i' => $i]), 'attempts' => 0];
    }
    $GLOBALS['wpdb'] = $db;
    $GLOBALS['wd_test_post'] = ['calls' => 0, 'code' => 202];
    unset($GLOBALS['__wd_opts']['webdecoy_violation_drain_lock']);
    WebDecoy_Detection_Sender::reset();
    return $db;
}

$t = ['TestRunner', 'test'];
$same = ['TestRunner', 'assertSame'];
$true = ['TestRunner', 'assertTrue'];

$t('a delivered batch is removed from the spool', function () use ($same) {
    $db = wd_spool(3);
    WebDecoy_Violation_Reporter::drain_queue('key');
    $same(1, $GLOBALS['wd_test_post']['calls']);
    $same(0, count($db->rows));
});

$t('a drain does not run while another holds the lock', function () use ($same) {
    $db = wd_spool(3);
    $GLOBALS['__wd_opts']['webdecoy_violation_drain_lock'] = (string) time();
    WebDecoy_Violation_Reporter::drain_queue('key');
    $same(0, $GLOBALS['wd_test_post']['calls'], 'the second drain sends nothing');
    $same(3, count($db->rows));
});

$t('a lock left by a request that died is taken over', function () use ($same) {
    $db = wd_spool(2);
    $GLOBALS['__wd_opts']['webdecoy_violation_drain_lock'] = (string) (time() - 120);
    WebDecoy_Violation_Reporter::drain_queue('key');
    $same(1, $GLOBALS['wd_test_post']['calls']);
    $same(0, count($db->rows));
});

$t('the lock is released after a drain', function () use ($true) {
    wd_spool(1);
    WebDecoy_Violation_Reporter::drain_queue('key');
    $true(!isset($GLOBALS['__wd_opts']['webdecoy_violation_drain_lock']));
});

$t('a refusal keeps the rows and their attempts, and pauses further drains', function () use ($same, $true) {
    $db = wd_spool(3);
    $GLOBALS['wd_test_post']['code'] = 503;
    WebDecoy_Violation_Reporter::drain_queue('key');
    WebDecoy_Violation_Reporter::drain_queue('key');
    WebDecoy_Violation_Reporter::drain_queue('key');
    $same(1, $GLOBALS['wd_test_post']['calls'], 'paused after the first refusal');
    $same(3, count($db->rows), 'nothing is discarded during an outage');
    $same(0, $db->rows[0]['attempts'], 'a refusal does not spend an attempt');
    $true(WebDecoy_Detection_Sender::backing_off());
});

$t('a rejected batch still spends its attempts and is dropped at the limit', function () use ($same) {
    $db = wd_spool(1);
    $GLOBALS['wd_test_post']['code'] = 400;
    WebDecoy_Violation_Reporter::drain_queue('key');
    WebDecoy_Violation_Reporter::drain_queue('key');
    $same(0, count($db->rows));
    WebDecoy_Detection_Sender::reset();
});

require_once dirname(__DIR__) . '/includes/class-webdecoy-ai-referrals.php';

$t('an AI referral batch refused with 429 is kept for retry and pauses cloud calls', function () use ($same, $true) {
    $send = new ReflectionMethod('WebDecoy_AI_Referrals', 'send');
    $send->setAccessible(true);
    WebDecoy_Detection_Sender::reset();
    $GLOBALS['wd_test_post'] = ['calls' => 0, 'code' => 429];
    $same(false, $send->invoke(null, 'key', 'batch-1', [['platform' => 'chatgpt', 'path' => '/', 'count' => 1]]), '429 is not delivered');
    $true(WebDecoy_Detection_Sender::backing_off());
    WebDecoy_Detection_Sender::reset();
    $GLOBALS['wd_test_post']['code'] = 400;
    $same(true, $send->invoke(null, 'key', 'batch-1', []), 'a 4xx other than 429 cannot be fixed by retrying');
    $GLOBALS['wd_test_post']['code'] = 202;
    $same(true, $send->invoke(null, 'key', 'batch-1', []));
});
