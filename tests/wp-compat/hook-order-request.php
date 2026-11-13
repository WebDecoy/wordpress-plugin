<?php
declare(strict_types=1);
/**
 * Isolated request fixture for hook-order.py, not a full WordPress bootstrap.
 * Uses the supplied WordPress hook dispatcher and unmodified WebDecoy source.
 * Options, cache and SQL storage below are deterministic in-memory adapters.
 * The reserved Test UA is only the control; redirect cases use normal scoring.
 */
$case = $argv[1] ?? 'baseline';
$repo = dirname(__DIR__, 2);
$wpIncludes = $argv[2] ?? '';
if (!is_file($wpIncludes . '/plugin.php')) {
    fwrite(STDERR, "Supply the WordPress wp-includes directory.\n");
    exit(2);
}
$state = ['case' => $case, 'rows' => [], 'redirect' => null, 'reached' => []];
define('ABSPATH', __DIR__.'/');
define('WP_PLUGIN_DIR', dirname($repo));
define('WPMU_PLUGIN_DIR', __DIR__ . '/mu');
$wp_plugin_paths = [];
require $wpIncludes . '/plugin.php';

// Stand-ins for WordPress services outside the hook dispatcher.
function wp_normalize_path($p) { return str_replace('\\','/',$p); }
function trailingslashit($p) { return rtrim($p,'/').'/'; }
function plugins_url($p='',$file='') { return 'https://fixture.invalid/plugins/'.$p; }
function get_option($key, $default = false) {
    if ($key !== 'webdecoy_options') {
        return $default;
    }
    return [
        'monitor_mode' => true,
        'tripwire_enabled' => false,
        'traps_fake_plugins' => false,
        'traps_xmlrpc' => false,
        'honeytoken_enabled' => false,
        'rate_limit_enabled' => false,
        'filter_rules' => [],
        'api_key' => '',
    ];
}
function is_admin() { return in_array($GLOBALS['case'],['admin','ajax'],true); }
function wp_doing_ajax() { return $GLOBALS['case']==='ajax'; }
function is_user_logged_in() { return false; }
function wp_doing_cron() { return false; }
function sanitize_text_field($v) { return strip_tags((string)$v); }
function wp_unslash($v) { return $v; }
function wp_json_encode($v) { return json_encode($v); }
function nocache_headers() {}
function status_header($c) { http_response_code($c); }
function __($s,$domain='') { return $s; }
function wp_cache_get($k,$g='') { return false; }
function wp_cache_set($k,$v,$g='',$ttl=0) { return true; }
function esc_sql($v) { return $v; }
function esc_url_raw($v) { return $v; }
function get_transient($k) { return false; }
function set_transient($k,$v,$ttl=0) { return true; }
function delete_transient($k) { return true; }
function get_current_user_id() { return 0; }
function wp_parse_url($url,$component=-1) { return parse_url($url,$component); }
function home_url($p='') { return 'https://fixture.invalid'.$p; }
function site_url($p='') { return 'https://fixture.invalid'.$p; }
class FixtureDatabase {
 public $prefix='wp_'; public $insert_id=0;
 function insert($t,$row) { $GLOBALS['state']['rows'][]=['table'=>$t,'row'=>$row];$this->insert_id++;return 1; }
 function prepare($q,...$a) { return $q; }
 function get_var($q) { return null; }
 function get_col($q) { return []; }
 function get_row($q) { return null; }
 function get_results($q,$mode=null) { return []; }
 function query($q) { return 0; }
}
$wpdb=new FixtureDatabase();
$_COOKIE=[]; $_REQUEST=[];
$_SERVER = [
    'REMOTE_ADDR' => '192.0.2.42',
    'REQUEST_URI' => '/compat-check/',
    'REQUEST_METHOD' => 'GET',
    'HTTP_HOST' => 'fixture.invalid',
    'SERVER_NAME' => 'fixture.invalid',
    'SERVER_PORT' => '443',
    'HTTPS' => 'on',
    'HTTP_USER_AGENT' => 'python-requests/2.32.3',
];
if ($case==='reserved-test') $_SERVER['HTTP_USER_AGENT']='WebDecoy-Test/1.0 Compatibility';
if ($case==='login') $_SERVER['REQUEST_URI']='/wp-login.php';
if ($case==='admin') $_SERVER['REQUEST_URI']='/wp-admin/index.php';
if ($case==='ajax') $_SERVER['REQUEST_URI']='/wp-admin/admin-ajax.php';
ob_start();
register_shutdown_function(static function () {
    $body = ob_get_clean();
    $summary = $GLOBALS['state'];
    $summary['status'] = http_response_code();
    $summary['body_is_reserved_test'] = strpos($body, 'webdecoy_test') !== false;
    $error = error_get_last();
    if ($error && in_array($error['type'], [E_ERROR, E_PARSE, E_COMPILE_ERROR], true)) {
        $summary['fatal'] = $error['message'];
    }
    echo json_encode($summary, JSON_UNESCAPED_SLASHES) . "\n";
});
$redirect = static function () {
    $GLOBALS['state']['redirect'] = 'https://fixture.invalid/destination/';
    http_response_code(302);
    exit;
};
if($case==='mu-plugin-exit') { $redirect(); }
if($case==='plugins-loaded-exit') add_action('plugins_loaded',$redirect,10);
if($case==='init-0-exit') add_action('init',$redirect,0);
if($case==='init-1-before-exit') add_action('init',$redirect,1);
require $repo.'/includes/class-webdecoy-runtime-config.php';
require $repo.'/webdecoy.php';
require $repo.'/includes/class-webdecoy-blocker.php';
require $repo.'/includes/class-webdecoy-detector.php';
// Only this plugin's bootstrap callbacks are omitted: companion classes have
// already been required above. The actual constructor, detection methods and
// WordPress hook dispatcher are unmodified.
if($case==='plugins-loaded-exit') do_action('plugins_loaded');
$state['login_filter_registered'] = has_filter('authenticate', [webdecoy(), 'check_login']) === 30;
$state['ajax_handler_registered'] = has_action('wp_ajax_nopriv_webdecoy_client_detection', [webdecoy(), 'ajax_client_detection']) !== false;
if($case==='init-1-after-exit') add_action('init',$redirect,1);
if($case==='init-2-exit') add_action('init',$redirect,2);
if($case==='init-10-exit') add_action('init',$redirect,10);
if($case==='wp-loaded-exit') add_action('wp_loaded',$redirect,10);
if($case==='template-redirect-exit') add_action('template_redirect',$redirect,0);
if($case==='login') add_action('login_init',$redirect,10);
do_action('init');
$state['reached'][] = 'after_init';
do_action('wp_loaded');
$state['reached'][] = 'after_wp_loaded';
if($case==='login')do_action('login_init');
if(!is_admin()&&$case!=='login')do_action('template_redirect');
