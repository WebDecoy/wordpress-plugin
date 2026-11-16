<?php

declare(strict_types=1);

/**
 * Automatic robots.txt: which agents a category selection names, how the
 * selection is cleaned, and how the block joins the robots.txt that WordPress
 * and other plugins already produce.
 *
 * Run: php tests/run.php
 */

if (!defined('ABSPATH')) {
    define('ABSPATH', '/tmp/');
}
if (!function_exists('wp_parse_url')) {
    function wp_parse_url($url, $component = -1) { return parse_url($url, $component); }
}
// Records registrations so register() can be checked. Guarded so it never
// replaces a real WordPress, and compatible with the other tests' stubs.
if (!function_exists('add_filter')) {
    function add_filter($hook, $cb, $priority = 10, $args = 1)
    {
        $GLOBALS['__wd_filters'][$hook][] = ['cb' => $cb, 'priority' => $priority, 'args' => $args];
        return true;
    }
}
require_once dirname(__DIR__) . '/sdk/src/AgentRegistry.php';
require_once dirname(__DIR__) . '/includes/class-webdecoy-robots-txt.php';
require_once dirname(__DIR__) . '/includes/class-webdecoy-runtime-config.php';
require_once dirname(__DIR__) . '/includes/class-webdecoy-cli.php';

$t = ['TestRunner', 'test'];
$same = ['TestRunner', 'assertSame'];
$true = ['TestRunner', 'assertTrue'];

/** A small registry in the generated file's shape. */
function robots_fixture(): array
{
    $agent = function (string $id, string $category, string $robots) {
        return ['id' => $id, 'name' => $id, 'category' => $category, 'robots_name' => $robots, 'patterns' => [strtolower($id)]];
    };
    return [
        $agent('gptbot', 'training_crawler', 'GPTBot'),
        $agent('claudebot', 'training_crawler', 'ClaudeBot'),
        $agent('nameless', 'training_crawler', ''),
        $agent('gptbot-alt', 'training_crawler', 'gptbot'),
        $agent('ahrefs', 'seo_crawler', 'AhrefsBot'),
        $agent('perplexity', 'ai_search_crawler', 'PerplexityBot'),
        $agent('dup-across', 'ai_search_crawler', 'ClaudeBot'),
        $agent('injected', 'seo_crawler', "Evil\nDisallow: /"),
        $agent('headless', 'headless_browser', ''),
        $agent('other', 'none', 'OtherBot'),
    ];
}

const ROBOTS_WP_DEFAULT = "User-agent: *\nDisallow: /wp-admin/\nAllow: /wp-admin/admin-ajax.php\n\nSitemap: https://example.com/wp-sitemap.xml\n";

echo "\nAutomatic robots.txt: generation\n";

$t('names each robots token once, in registry order, first spelling kept', function () use ($same) {
    $same(['GPTBot', 'ClaudeBot'], WebDecoy_Robots_Txt::agent_names(['training_crawler'], robots_fixture()));
});

$t('dedupes across categories too, and order follows the registry not the selection', function () use ($same) {
    $same(
        ['GPTBot', 'ClaudeBot', 'AhrefsBot', 'PerplexityBot'],
        WebDecoy_Robots_Txt::agent_names(['seo_crawler', 'ai_search_crawler', 'training_crawler'], robots_fixture())
    );
});

$t('agents without a robots token, unknown categories and the none bucket add nothing', function () use ($same) {
    $same([], WebDecoy_Robots_Txt::agent_names(['headless_browser', 'made_up', 'none'], robots_fixture()));
});

$t('a token that could break out of its line is never written', function () use ($same) {
    $same(['AhrefsBot'], WebDecoy_Robots_Txt::agent_names(['seo_crawler'], robots_fixture()));
});

$t('the block is one group ending in Disallow: /, between markers', function () use ($same) {
    $same(
        "# WebDecoy: AI and bot rules (2 agents, updated with plugin version 9.9.9)\n"
        . "User-agent: GPTBot\nUser-agent: ClaudeBot\nDisallow: /\n# End of WebDecoy rules\n",
        WebDecoy_Robots_Txt::block(['training_crawler'], '9.9.9', robots_fixture())
    );
});

$t('an empty selection, or one that names no agent, is no block at all', function () use ($same) {
    $same('', WebDecoy_Robots_Txt::block([], '9.9.9', robots_fixture()));
    $same('', WebDecoy_Robots_Txt::block(['headless_browser'], '9.9.9', robots_fixture()));
});

echo "\nAutomatic robots.txt: choices and sanitizing\n";

$t('choices are categories with at least one token, counted after dedupe, none excluded', function () use ($same) {
    $same(
        ['training_crawler' => 2, 'seo_crawler' => 1, 'ai_search_crawler' => 2],
        WebDecoy_Robots_Txt::choices(robots_fixture())
    );
});

$t('sanitizing keeps known choices only, in choice order, once each', function () use ($same) {
    $same(
        ['training_crawler', 'seo_crawler'],
        WebDecoy_Robots_Txt::sanitize_categories(['seo_crawler', 'none', 'nope', 'Training_Crawler ', 'seo_crawler', 'headless_browser', 7], robots_fixture())
    );
});

$t('a comma-separated string is accepted; anything else is an empty selection', function () use ($same) {
    $same(['training_crawler', 'ai_search_crawler'], WebDecoy_Robots_Txt::sanitize_categories('ai_search_crawler, training_crawler', robots_fixture()));
    $same([], WebDecoy_Robots_Txt::sanitize_categories(null, robots_fixture()));
    $same([], WebDecoy_Robots_Txt::sanitize_categories(true, robots_fixture()));
});

$t('the bundled registry offers AI training crawlers and search engines, never none', function () use ($true) {
    $choices = WebDecoy_Robots_Txt::choices();
    $true(($choices['training_crawler'] ?? 0) > 0, 'training_crawler must be offered');
    $true(isset($choices['search_crawler']), 'search engines are selectable');
    $true(!isset($choices['none']), 'none is never offered');
    $true(!isset($choices['headless_browser']), 'a category with no robots token has nothing to offer');
});

$t('with the bundled registry, AI training crawlers include GPTBot and ClaudeBot', function () use ($true) {
    $names = WebDecoy_Robots_Txt::agent_names(['training_crawler']);
    $true(in_array('GPTBot', $names, true) && in_array('ClaudeBot', $names, true));
    $true(!in_array('Googlebot', $names, true), 'search engines are not training crawlers');
});

echo "\nAutomatic robots.txt: joining WordPress's output\n";

$t('the block is appended after the existing output, which is kept byte for byte', function () use ($same, $true) {
    $out = WebDecoy_Robots_Txt::append(ROBOTS_WP_DEFAULT, ['training_crawler'], '9.9.9', robots_fixture());
    $same(0, strpos($out, ROBOTS_WP_DEFAULT), 'existing rules and sitemap line come first, unchanged');
    $same(
        ROBOTS_WP_DEFAULT . "\n" . WebDecoy_Robots_Txt::block(['training_crawler'], '9.9.9', robots_fixture()),
        $out
    );
});

$t('output without a trailing newline still gets a blank line before the block', function () use ($true) {
    $out = WebDecoy_Robots_Txt::append("User-agent: *\nDisallow:", ['training_crawler'], '9.9.9', robots_fixture());
    $true(strpos($out, "Disallow:\n\n# WebDecoy: AI and bot rules") !== false, $out);
});

$t('nothing is added with no selection', function () use ($same) {
    $same(ROBOTS_WP_DEFAULT, WebDecoy_Robots_Txt::append(ROBOTS_WP_DEFAULT, [], '9.9.9', robots_fixture()));
});

$t('running the filter twice adds the block once', function () use ($same) {
    $once = WebDecoy_Robots_Txt::append(ROBOTS_WP_DEFAULT, ['training_crawler'], '9.9.9', robots_fixture());
    $same($once, WebDecoy_Robots_Txt::append($once, ['training_crawler'], '9.9.9', robots_fixture()));
});

$t('register() hooks robots_txt late only when a category is chosen, and the hook appends', function () use ($same, $true) {
    $GLOBALS['__wd_filters'] = [];
    WebDecoy_Robots_Txt::register([]);
    WebDecoy_Robots_Txt::register(['not_a_category']);
    WebDecoy_Robots_Txt::register(null);
    $same([], $GLOBALS['__wd_filters'], 'no selection must register nothing');

    WebDecoy_Robots_Txt::register(['training_crawler']);
    $hooks = $GLOBALS['__wd_filters']['robots_txt'] ?? [];
    $same(1, count($hooks));
    $true($hooks[0]['priority'] > 10, 'runs after sitemaps and other plugins');
    $same(1, $hooks[0]['args'], 'only the output is taken: the public flag must not decide this');

    $served = ($hooks[0]['cb'])(ROBOTS_WP_DEFAULT);
    $same(0, strpos($served, ROBOTS_WP_DEFAULT));
    $true(strpos($served, "User-agent: GPTBot\n") !== false, $served);
    $GLOBALS['__wd_filters'] = [];
});

$t('a site that discourages search engines still gets the chosen rules', function () use ($true) {
    $GLOBALS['__wd_filters'] = [];
    WebDecoy_Robots_Txt::register(['training_crawler']);
    $cb = $GLOBALS['__wd_filters']['robots_txt'][0]['cb'];
    // As if a caller passed WordPress's flag anyway, in every shape it has had.
    foreach ([false, '0', 0] as $public) {
        $true(strpos($cb(ROBOTS_WP_DEFAULT, $public), "User-agent: GPTBot\n") !== false, var_export($public, true));
    }
    $GLOBALS['__wd_filters'] = [];
});

echo "\nAutomatic robots.txt: where it can apply\n";

$t('a physical robots.txt is found, and its absence is null', function () use ($same) {
    $dir = sys_get_temp_dir() . '/wd-robots-' . bin2hex(random_bytes(4));
    mkdir($dir);
    $same(null, WebDecoy_Robots_Txt::physical_file([$dir]));
    file_put_contents($dir . '/robots.txt', "User-agent: *\n");
    $same($dir . '/robots.txt', WebDecoy_Robots_Txt::physical_file([$dir . '/']));
    unlink($dir . '/robots.txt');
    rmdir($dir);
});

$t('a home address below a path is a subdirectory install', function () use ($same) {
    $same(false, WebDecoy_Robots_Txt::home_is_subdirectory('https://example.com/'));
    $same(false, WebDecoy_Robots_Txt::home_is_subdirectory('https://example.com'));
    $same(true, WebDecoy_Robots_Txt::home_is_subdirectory('https://example.com/blog/'));
});

echo "\nWP-CLI: robots_disallow_categories\n";

$t('a comma list of known categories sets them; none clears', function () use ($same) {
    $same(
        ['robots_disallow_categories', ['training_crawler', 'seo_crawler']],
        WebDecoy_CLI_Command::parse_config_value('robots_disallow_categories', 'seo_crawler, training_crawler')
    );
    $same(['robots_disallow_categories', []], WebDecoy_CLI_Command::parse_config_value('robots_disallow_categories', 'none'));
});

$t('an unknown category refuses the whole value', function () use ($same) {
    $same(null, WebDecoy_CLI_Command::parse_config_value('robots_disallow_categories', 'training_crawler,trainng_crawler'));
});

$t('the stored list displays as a comma list, or none', function () use ($same) {
    $same('training_crawler,seo_crawler', WebDecoy_CLI_Command::display_value('robots_disallow_categories', ['robots_disallow_categories' => ['training_crawler', 'seo_crawler']]));
    $same('none', WebDecoy_CLI_Command::display_value('robots_disallow_categories', ['robots_disallow_categories' => []]));
});
