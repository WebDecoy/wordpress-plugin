<?php
declare(strict_types=1);
define('ABSPATH', '/tmp/');
define('ARRAY_A', 'ARRAY_A');
define('OBJECT_K', 'OBJECT_K');
require dirname(__DIR__) . '/bootstrap.php';
$GLOBALS['wd_blog'] = 1;
$GLOBALS['wd_cache'] = [];
$GLOBALS['wd_clock'] = 0;
function wp_cache_get($key, $group) {
    $entry = $GLOBALS['wd_cache'][$GLOBALS['wd_blog']][$group][$key] ?? null;
    return $entry && $entry[1] > $GLOBALS['wd_clock'] ? $entry[0] : false;
}
function wp_cache_set($key, $value, $group, $ttl) {
    TestRunner::assertSame(60, $ttl);
    $GLOBALS['wd_cache'][$GLOBALS['wd_blog']][$group][$key] = [$value, $GLOBALS['wd_clock'] + $ttl];
}
function add_filter($hook, $callback, $priority = 10, $args = 1) {}
function add_action($hook, $callback, $priority = 10, $args = 1) {}
function esc_sql($value) { return $value; }
class WD_Stats_DB {
    public $prefix = 'wp_'; public $calls = 0;
    public function prepare($sql, ...$args) { return $sql; }
    public function get_var($sql) { $this->calls++; return 10; }
    public function get_results($sql, $type) { $this->calls++; return []; }
}
require dirname(__DIR__, 2) . '/includes/class-webdecoy-detector.php';
require dirname(__DIR__, 2) . '/includes/class-webdecoy-blocker.php';
require dirname(__DIR__, 2) . '/includes/class-webdecoy-woocommerce.php';
foreach (['WebDecoy_Detector', 'WebDecoy_Blocker', 'WebDecoy_WooCommerce'] as $class) {
    TestRunner::test($class . ' analytics reuse, expiration and site isolation', function () use ($class) {
        global $wpdb;
        $wpdb = new WD_Stats_DB();
        $GLOBALS['wd_blog'] = 1; $GLOBALS['wd_cache'] = []; $GLOBALS['wd_clock'] = 0;
        $object = (new ReflectionClass($class))->newInstanceWithoutConstructor();
        $expected = $object->get_stats();
        $first = $wpdb->calls;
        TestRunner::assertTrue($first > 0);
        TestRunner::assertSame($expected, $object->get_stats());
        TestRunner::assertSame($first, $wpdb->calls, 'repeated display avoids all aggregate queries');
        $GLOBALS['wd_blog'] = 2;
        $object->get_stats();
        TestRunner::assertSame($first * 2, $wpdb->calls, 'another site cannot reuse the first site cache');
        $GLOBALS['wd_blog'] = 1;
        $GLOBALS['wd_clock'] = 61;
        $object->get_stats();
        TestRunner::assertSame($first * 3, $wpdb->calls, 'expired presentation data is queried again');
    });
}
exit(TestRunner::summary());
