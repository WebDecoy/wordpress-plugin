<?php

declare(strict_types=1);

/**
 * llms.txt generator, run in its own process (tests/LlmsTxtTest.php starts
 * it) so its WordPress stand-ins cannot collide with other tests' stubs.
 *
 * The stand-ins model just enough WordPress to run the real query, cache and
 * invalidation code: get_posts() honours post_type, post_status,
 * has_password and posts_per_page the way WP_Query does.
 */

define('ABSPATH', '/tmp/');
define('DAY_IN_SECONDS', 86400);
define('WEBDECOY_VERSION', '9.9.9');

require dirname(__DIR__) . '/bootstrap.php';

class WP_Post
{
    public $ID = 0;
    public $post_type = 'post';
    public $post_status = 'publish';
    public $post_password = '';
    public $post_title = '';
    public $post_excerpt = '';
    public $post_content = '';
    public $menu_order = 0;
    public $post_date = '';

    public function __construct(array $fields)
    {
        foreach ($fields as $key => $value) {
            $this->$key = $value;
        }
    }
}

$GLOBALS['wd'] = [];
function wd_reset(array $options = []): void
{
    $GLOBALS['wd'] = [
        'options' => ['webdecoy_options' => $options, 'blogname' => 'Example Site', 'blogdescription' => 'Notes on things'],
        'transients' => [],
        'actions' => [],
        'filters' => [],
        'posts' => [],
        'meta' => [],
        'terms' => [],
        'queries' => [],
        'purges' => [],
        'defined' => [],
    ];
}
wd_reset();

function add_action($hook, $cb, $priority = 10, $args = 1) { $GLOBALS['wd']['actions'][$hook][] = ['cb' => $cb, 'priority' => $priority]; return true; }
function add_filter($hook, $cb, $priority = 10, $args = 1) { $GLOBALS['wd']['filters'][$hook][] = $cb; return true; }
function apply_filters($hook, $value, ...$args)
{
    foreach ($GLOBALS['wd']['filters'][$hook] ?? [] as $cb) {
        $value = $cb($value, ...$args);
    }
    return $value;
}
function get_option($name, $default = false) { return array_key_exists($name, $GLOBALS['wd']['options']) ? $GLOBALS['wd']['options'][$name] : $default; }
function get_bloginfo($show) { return $show === 'name' ? get_option('blogname', '') : get_option('blogdescription', ''); }
function home_url($path = '') { return 'https://example.com' . $path; }
function get_transient($key) { return $GLOBALS['wd']['transients'][$key] ?? false; }
function set_transient($key, $value, $ttl = 0) { $GLOBALS['wd']['transients'][$key] = $value; return true; }
function delete_transient($key) { unset($GLOBALS['wd']['transients'][$key]); return true; }
function wp_json_encode($data) { return json_encode($data); }
function wp_strip_all_tags($text)
{
    $text = (string) preg_replace('@<(script|style)[^>]*?>.*?</\\1>@si', '', (string) $text);
    return trim(strip_tags($text));
}
function sanitize_text_field($text) { return trim((string) preg_replace('/[\r\n\t ]+/', ' ', wp_strip_all_tags((string) $text))); }
function sanitize_textarea_field($text) { return trim(wp_strip_all_tags((string) $text)); }
function esc_url_raw($url, $protocols = null)
{
    $url = str_replace(' ', '%20', trim((string) $url));
    $url = (string) preg_replace('|[^a-z0-9-~+_.?#=!&;,/:%@$\|*\'()\[\]\x80-\xff]|i', '', $url);
    $scheme = strtolower((string) parse_url($url, PHP_URL_SCHEME));
    return in_array($scheme, $protocols ?? ['http', 'https'], true) ? $url : '';
}
function strip_shortcodes($text) { return (string) preg_replace('/\[[^\]]*\]/', '', (string) $text); }
function excerpt_remove_blocks($text) { return (string) preg_replace('/<!--.*?-->/s', '', (string) $text); }
function get_post_types($args, $output) { return ['post' => wd_type('post'), 'page' => wd_type('page'), 'attachment' => wd_type('attachment'), 'product' => wd_type('product')]; }
function wd_type(string $name)
{
    $labels = ['post' => 'Posts', 'page' => 'Pages', 'attachment' => 'Media', 'product' => 'Products'];
    return (object) ['name' => $name, 'public' => true, 'hierarchical' => $name === 'page', 'labels' => (object) ['name' => $labels[$name] ?? ucfirst($name)]];
}
function get_post_type_object($name) { return in_array($name, ['post', 'page', 'attachment', 'product'], true) ? wd_type($name) : null; }
function get_posts(array $args)
{
    $GLOBALS['wd']['queries'][] = $args;
    $out = [];
    foreach ($GLOBALS['wd']['posts'] as $post) {
        if ($post->post_type !== $args['post_type'] || $post->post_status !== $args['post_status']) {
            continue;
        }
        if (($args['has_password'] ?? null) === false && $post->post_password !== '') {
            continue;
        }
        $out[] = $post;
    }
    return array_slice($out, 0, $args['posts_per_page']);
}
function get_post($id) { foreach ($GLOBALS['wd']['posts'] as $post) { if ($post->ID === $id) { return $post; } } return null; }
function get_post_meta($id, $key, $single) { return $GLOBALS['wd']['meta'][$id][$key] ?? ''; }
function get_permalink($post) { return 'https://example.com/?p=' . $post->ID . ($GLOBALS['wd']['url_suffix'][$post->ID] ?? ''); }
function taxonomy_exists($taxonomy) { return $taxonomy === 'product_visibility'; }
function has_term($term, $taxonomy, $post) { return in_array($term, $GLOBALS['wd']['terms'][$post->ID] ?? [], true); }
function wpvip_purge_edge_cache_for_url($url) { $GLOBALS['wd']['purges'][] = $url; }

require dirname(__DIR__, 2) . '/sdk/src/AgentRegistry.php';
require dirname(__DIR__, 2) . '/includes/class-webdecoy-robots-txt.php';
require dirname(__DIR__, 2) . '/includes/class-webdecoy-llms-txt.php';
require dirname(__DIR__, 2) . '/includes/class-webdecoy-runtime-config.php';
require dirname(__DIR__, 2) . '/includes/class-webdecoy-cli.php';

$id = 0;
function wd_post(string $type, string $title, array $extra = []): WP_Post
{
    global $id;
    $post = new WP_Post(array_merge(['ID' => ++$id, 'post_type' => $type, 'post_title' => $title], $extra));
    $GLOBALS['wd']['posts'][] = $post;
    return $post;
}

$t = ['TestRunner', 'test'];
$same = ['TestRunner', 'assertSame'];
$true = ['TestRunner', 'assertTrue'];

const LLMS_SITE = ['name' => 'Example Site', 'description' => 'Notes on things', 'home' => 'https://example.com/'];
const LLMS_SETTINGS = ['summary' => '', 'intro' => ''];

echo "\nllms.txt: off by default\n";

$t('no stored setting means off, and register() adds no request handler', function () use ($same, $true) {
    $same(false, WebDecoy_Llms_Txt::settings([])['enabled']);
    $same(false, WebDecoy_Llms_Txt::settings(null)['enabled']);
    wd_reset();
    WebDecoy_Llms_Txt::register([]);
    $true(!isset($GLOBALS['wd']['actions']['parse_request']), 'off must not touch requests');
    $true(isset($GLOBALS['wd']['actions']['clean_post_cache']), 'the preview cache is still kept fresh');
    WebDecoy_Llms_Txt::register(['llms_txt_enabled' => true]);
    $same(1, count($GLOBALS['wd']['actions']['parse_request'] ?? []));
});

$t('both default option arrays ship it off', function () use ($true) {
    foreach (['webdecoy.php', 'includes/class-webdecoy-activator.php'] as $file) {
        $source = (string) file_get_contents(dirname(__DIR__, 2) . '/' . $file);
        $true(strpos($source, "'llms_txt_enabled' => false,") !== false, $file);
    }
});

$t('defaults: pages and posts, 50 per section; the cap and floor hold', function () use ($same) {
    $settings = WebDecoy_Llms_Txt::settings([]);
    $same(['page', 'post'], $settings['post_types']);
    $same(50, $settings['max_items']);
    $same(200, WebDecoy_Llms_Txt::settings(['llms_txt_max_items' => 100000])['max_items']);
    $same(1, WebDecoy_Llms_Txt::settings(['llms_txt_max_items' => -5])['max_items']);
    $same([], WebDecoy_Llms_Txt::settings(['llms_txt_post_types' => []])['post_types'], 'an empty choice is respected');
});

echo "\nllms.txt: content follows the spec\n";

$t('H1 name, blockquote summary, intro, then H2 sections of links', function () use ($same) {
    $body = WebDecoy_Llms_Txt::build(['summary' => '', 'intro' => "We write about tea.\n\nCite us by name."], LLMS_SITE, [
        ['title' => 'Pages', 'items' => [
            ['title' => 'About', 'url' => 'https://example.com/about/', 'description' => 'Who we are.'],
        ]],
        ['title' => 'Posts', 'items' => [
            ['title' => 'Green tea', 'url' => 'https://example.com/green-tea/', 'description' => ''],
        ]],
        ['title' => 'Empty', 'items' => []],
    ]);
    $same(
        "# Example Site\n\n> Notes on things\n\nWe write about tea.\n\nCite us by name.\n\n"
        . "## Pages\n\n- [About](https://example.com/about/): Who we are.\n\n"
        . "## Posts\n\n- [Green tea](https://example.com/green-tea/)\n",
        $body
    );
});

$t('the summary setting overrides the tagline; no tagline and no setting means no blockquote', function () use ($true) {
    $body = WebDecoy_Llms_Txt::build(['summary' => 'Custom line', 'intro' => ''], LLMS_SITE, []);
    $true(strpos($body, "> Custom line\n") !== false, $body);
    $body = WebDecoy_Llms_Txt::build(LLMS_SETTINGS, ['description' => ''] + LLMS_SITE, []);
    $true(strpos($body, '>') === false, $body);
});

$t('a site with no name falls back to its host name', function () use ($same) {
    $same("# example.com\n", WebDecoy_Llms_Txt::build(LLMS_SETTINGS, ['name' => '  ', 'description' => '', 'home' => 'https://example.com/'], []));
});

echo "\nllms.txt: hostile content stays text\n";

$t('a title cannot close its link, add a link, or start a heading', function () use ($same, $true) {
    $line = WebDecoy_Llms_Txt::link_line("Foo](http://evil)\n# Injected", 'https://example.com/foo/', '');
    $same('- [Foo\\](http://evil) # Injected](https://example.com/foo/)', $line);
    $body = WebDecoy_Llms_Txt::build(LLMS_SETTINGS, ["name" => "Site\n## Fake section", 'description' => "x\n# y", 'home' => 'https://example.com/'], [
        ['title' => "Posts\n# Owned", 'items' => [['title' => "Foo](http://evil)\n# Injected", 'url' => 'https://example.com/foo/', 'description' => "Line one\r\n## Line two\u{2028}- [x](http://evil)"]]],
    ]);
    $headings = array_values(array_filter(explode("\n", $body), static function ($l) { return $l !== '' && $l[0] === '#'; }));
    $same(['# Site ## Fake section', '## Posts # Owned'], $headings, 'only our own headings start lines');
    $true(strpos($body, '\\[x\\](http://evil)') !== false, 'link syntax in a description is escaped: ' . $body);
});

$t('tags and entities in titles become plain text; inline HTML is escaped', function () use ($same) {
    $same('- [Bold \\<3 & co](https://example.com/b/)', WebDecoy_Llms_Txt::link_line('<b>Bold</b> &lt;3 &amp; co<script>alert(1)</script>', 'https://example.com/b/', ''));
});

$t('URLs: only http(s), and nothing that can end the link early', function () use ($same) {
    $same('', WebDecoy_Llms_Txt::link_line('X', 'javascript:alert(1)', ''));
    $same('', WebDecoy_Llms_Txt::link_line('X', 'data:text/html,hi', ''));
    $same('', WebDecoy_Llms_Txt::link_line('', 'https://example.com/', ''), 'an untitled post is skipped');
    $same('- [X](https://example.com/a%28b%29%20c%5Bd%5D/)', WebDecoy_Llms_Txt::link_line('X', 'https://example.com/a(b) c[d]/', ''));
    $same('https://example.com/xy%27z', WebDecoy_Llms_Txt::link_url("https://example.com/x\"y'z"));
});

$t('descriptions are one line, shortened at a word to 200 characters', function () use ($same, $true) {
    $long = str_repeat('word ', 80);
    $line = WebDecoy_Llms_Txt::link_line('T', 'https://example.com/', $long);
    $description = substr($line, strlen('- [T](https://example.com/): '));
    $true(mb_strlen($description) <= 200, (string) mb_strlen($description));
    $true(substr($description, -3) === '...' && strpos($description, 'wor...') === false, $description);
    $same('- [T](https://example.com/): a b c', WebDecoy_Llms_Txt::link_line('T', 'https://example.com/', "a\n\tb\r\n\u{00A0}c"));
});

$t('invalid UTF-8 in a title does not empty the line', function () use ($true) {
    $true(WebDecoy_Llms_Txt::link_line("Caf\xE9 menu", 'https://example.com/', '') !== '');
});

$t('the owner intro cannot open a section, and loses tags and scripts', function () use ($same) {
    $same("Intro\n\\## Not a heading\n\\# Nor this", WebDecoy_Llms_Txt::clean_block("Intro\r\n## Not a heading\n  # Nor this\n\n\n\n<script>alert(1)</script>"));
});

$t('the body never grows past the size cap', function () use ($true) {
    $items = [];
    for ($i = 0; $i < 3000; $i++) {
        $items[] = ['title' => str_repeat('t', 150) . $i, 'url' => 'https://example.com/' . $i . '/', 'description' => str_repeat('d ', 150)];
    }
    $body = WebDecoy_Llms_Txt::build(LLMS_SETTINGS, LLMS_SITE, [['title' => 'Posts', 'items' => $items]]);
    $true(strlen($body) <= WebDecoy_Llms_Txt::MAX_BYTES, (string) strlen($body));
    $true(substr_count($body, "\n- [") > 500, 'still lists as much as fits');
});

echo "\nllms.txt: what is listed\n";

function wd_site_fixture(): void
{
    wd_reset(['llms_txt_enabled' => true, 'llms_txt_post_types' => ['page', 'post', 'product'], 'llms_txt_max_items' => 3]);
    $GLOBALS['id'] = 0;
    wd_post('page', 'About', ['post_excerpt' => "Who <em>we</em> are.\nSince 2001."]);
    wd_post('page', 'Secret page', ['post_status' => 'private']);
    wd_post('page', 'Locked', ['post_password' => 'hunter2']);
    wd_post('page', 'Draft page', ['post_status' => 'draft']);
    wd_post('post', 'Hello', ['post_content' => '<!-- wp:paragraph --><p>[gallery ids="1"]First post body.</p><!-- /wp:paragraph -->']);
    $yoast = wd_post('post', 'Yoast noindex');
    $rank = wd_post('post', 'Rank Math noindex');
    $seopress = wd_post('post', 'SEOPress noindex');
    $forced = wd_post('post', 'Second');
    wd_post('post', 'Third');
    wd_post('post', 'Fourth');
    $hidden = wd_post('product', 'Hidden product');
    wd_post('product', 'Mug', ['post_excerpt' => 'A mug.']);
    wd_post('attachment', 'photo.jpg', ['post_status' => 'inherit']);
    $GLOBALS['wd']['meta'][$yoast->ID]['_yoast_wpseo_meta-robots-noindex'] = '1';
    $GLOBALS['wd']['meta'][$rank->ID]['rank_math_robots'] = ['noindex', 'nofollow'];
    $GLOBALS['wd']['meta'][$seopress->ID]['_seopress_robots_index'] = 'yes';
    $GLOBALS['wd']['meta'][$forced->ID]['_yoast_wpseo_meta-robots-noindex'] = '2';
    $GLOBALS['wd']['terms'][$hidden->ID] = ['exclude-from-catalog', 'exclude-from-search'];
}

$t('published public posts only: no private, password, draft or noindex; cap per section', function () use ($same) {
    wd_site_fixture();
    $same(
        "# Example Site\n\n> Notes on things\n\n"
        . "## Pages\n\n- [About](https://example.com/?p=1): Who we are. Since 2001.\n\n"
        . "## Posts\n\n- [Hello](https://example.com/?p=5): First post body.\n- [Second](https://example.com/?p=9)\n- [Third](https://example.com/?p=10)\n\n"
        . "## Products\n\n- [Mug](https://example.com/?p=13): A mug.\n",
        WebDecoy_Llms_Txt::body()
    );
});

$t('the query asks WordPress for published, unprotected posts with spare rows', function () use ($same) {
    wd_site_fixture();
    WebDecoy_Llms_Txt::body();
    $query = $GLOBALS['wd']['queries'][0];
    $same('publish', $query['post_status']);
    $same(false, $query['has_password']);
    $same(6, $query['posts_per_page']);
    $same(true, $query['no_found_rows']);
});

$t('a Yoast post type set to noindex is left out unless a post forces index', function () use ($same) {
    $same(true, WebDecoy_Llms_Txt::noindex_from_meta([], true));
    $same(false, WebDecoy_Llms_Txt::noindex_from_meta(['_yoast_wpseo_meta-robots-noindex' => '2'], true));
    $same(false, WebDecoy_Llms_Txt::noindex_from_meta(['rank_math_robots' => ['index']], false));
    $same(false, WebDecoy_Llms_Txt::noindex_from_meta(['_seopress_robots_index' => ''], false));
});

$t('the include filter can drop a post', function () use ($true) {
    wd_site_fixture();
    add_filter('webdecoy_llms_txt_include_post', static function ($include, $post) { return $include && $post->post_title !== 'Mug'; });
    $true(strpos(WebDecoy_Llms_Txt::body(), 'Mug') === false);
});

echo "\nllms.txt: caching and invalidation\n";

$t('a second read is served from the cache without querying', function () use ($same) {
    wd_site_fixture();
    $first = WebDecoy_Llms_Txt::body();
    $queries = count($GLOBALS['wd']['queries']);
    $same($first, WebDecoy_Llms_Txt::body());
    $same($queries, count($GLOBALS['wd']['queries']));
});

$t('changing a listed post drops the cache; other types and revisions do not', function () use ($same, $true) {
    wd_site_fixture();
    WebDecoy_Llms_Txt::body();
    WebDecoy_Llms_Txt::post_changed(99, new WP_Post(['ID' => 99, 'post_type' => 'revision']));
    WebDecoy_Llms_Txt::post_changed(98, new WP_Post(['ID' => 98, 'post_type' => 'attachment']));
    $true(isset($GLOBALS['wd']['transients'][WebDecoy_Llms_Txt::CACHE_KEY]), 'unrelated changes keep the cache');
    $GLOBALS['wd']['posts'][4]->post_title = 'Hello again';
    WebDecoy_Llms_Txt::post_changed(5, $GLOBALS['wd']['posts'][4]);
    $true(!isset($GLOBALS['wd']['transients'][WebDecoy_Llms_Txt::CACHE_KEY]));
    $true(strpos(WebDecoy_Llms_Txt::body(), '[Hello again]') !== false);
});

$t('a noindex flag changing drops the cache; other meta does not', function () use ($true) {
    wd_site_fixture();
    WebDecoy_Llms_Txt::body();
    WebDecoy_Llms_Txt::meta_changed(1, 5, '_edit_lock');
    $true(isset($GLOBALS['wd']['transients'][WebDecoy_Llms_Txt::CACHE_KEY]));
    $GLOBALS['wd']['meta'][5]['_yoast_wpseo_meta-robots-noindex'] = '1';
    WebDecoy_Llms_Txt::meta_changed(1, 5, '_yoast_wpseo_meta-robots-noindex');
    $true(strpos(WebDecoy_Llms_Txt::body(), 'Hello') === false);
});

$t('new settings or a renamed site rebuild without any hook', function () use ($true) {
    wd_site_fixture();
    WebDecoy_Llms_Txt::body();
    $GLOBALS['wd']['options']['blogname'] = 'Renamed';
    $true(strpos(WebDecoy_Llms_Txt::body(), "# Renamed\n") === 0);
    $GLOBALS['wd']['options']['webdecoy_options']['llms_txt_summary'] = 'New summary';
    $true(strpos(WebDecoy_Llms_Txt::body(), "> New summary\n") !== false);
});

$t('saving changed llms.txt settings purges VIP once; unrelated saves do not', function () use ($same) {
    wd_reset();
    WebDecoy_Llms_Txt::settings_updated(['llms_txt_enabled' => false], ['llms_txt_enabled' => false, 'monitor_mode' => true]);
    WebDecoy_Llms_Txt::settings_updated([], ['llms_txt_enabled' => true]);
    $same(['https://example.com/llms.txt'], $GLOBALS['wd']['purges']);
});

echo "\nllms.txt: where it is served\n";

$t('the request path matches below the home path, ignoring the query', function () use ($same) {
    $same(true, WebDecoy_Llms_Txt::is_request('/llms.txt', 'https://example.com/'));
    $same(true, WebDecoy_Llms_Txt::is_request('/llms.txt?ver=2', 'https://example.com'));
    $same(true, WebDecoy_Llms_Txt::is_request('/llms%2Etxt', 'https://example.com/'));
    $same(true, WebDecoy_Llms_Txt::is_request('/blog/llms.txt', 'https://example.com/blog/'));
    $same(false, WebDecoy_Llms_Txt::is_request('/llms.txt', 'https://example.com/blog/'));
    $same(false, WebDecoy_Llms_Txt::is_request('/blog/llms.txt', 'https://example.com/'));
    $same(false, WebDecoy_Llms_Txt::is_request('/llms.txt/', 'https://example.com/'));
    $same(false, WebDecoy_Llms_Txt::is_request('/llms-full.txt', 'https://example.com/'));
    $same(false, WebDecoy_Llms_Txt::is_request('/?p=llms.txt', 'https://example.com/'));
    $same(false, WebDecoy_Llms_Txt::is_request('', 'https://example.com/'));
    $same(false, WebDecoy_Llms_Txt::is_request('//llms.txt', 'https://example.com/'));
});

$t('a physical llms.txt is found, and its absence is null', function () use ($same) {
    $dir = sys_get_temp_dir() . '/wd-llms-' . bin2hex(random_bytes(4));
    mkdir($dir);
    file_put_contents($dir . '/robots.txt', "User-agent: *\n");
    $same(null, WebDecoy_Llms_Txt::physical_file([$dir]), 'a robots.txt is not an llms.txt');
    file_put_contents($dir . '/llms.txt', "# Mine\n");
    $same($dir . '/llms.txt', WebDecoy_Llms_Txt::physical_file([$dir . '/']));
    $same($dir . '/robots.txt', WebDecoy_Robots_Txt::physical_file([$dir]), 'robots.txt detection unchanged');
    unlink($dir . '/llms.txt');
    unlink($dir . '/robots.txt');
    rmdir($dir);
});

echo "\nllms.txt: other plugins that provide it\n";

$t('each known provider is named only when its llms.txt is on', function () use ($same) {
    $check = static function (array $constants, array $options) {
        return WebDecoy_Llms_Txt::conflict(
            static function ($name) use ($constants) { return in_array($name, $constants, true); },
            static function ($name) use ($options) { return $options[$name] ?? false; }
        );
    };
    $same(null, $check([], []));
    $same('Website LLMs.txt', $check(['WEBSITE_LLMS_TXT_VERSION'], []));
    $same(null, $check(['WPSEO_VERSION'], ['wpseo' => ['enable_llms_txt' => false]]));
    $same('Yoast SEO', $check(['WPSEO_VERSION'], ['wpseo' => ['enable_llms_txt' => true]]));
    $same(null, $check(['RANK_MATH_VERSION'], ['rank_math_modules' => ['sitemap', 'seo-analysis']]));
    $same('Rank Math', $check(['RANK_MATH_VERSION'], ['rank_math_modules' => ['sitemap', 'llms-txt']]));
    $same(null, $check(['AIOSEO_FILE'], ['aioseo_options' => '{"sitemap":{"llms":{"enable":false}}}']));
    $same('All in One SEO', $check(['AIOSEO_FILE'], ['aioseo_options' => '{"sitemap":{"llms":{"enable":true}}}']));
    $same(null, $check(['AIOSEO_FILE'], ['aioseo_options' => 'not json']));
    $same(null, $check([], ['wpseo' => ['enable_llms_txt' => true]]), 'an option left behind by a removed plugin is not a provider');
});

$t('the conflict filter can name another provider', function () use ($same) {
    wd_reset();
    add_filter('webdecoy_llms_txt_conflict', static function ($found) { return $found ?? 'Custom plugin'; });
    $same('Custom plugin', WebDecoy_Llms_Txt::conflict(static function () { return false; }, static function () { return false; }));
    wd_reset();
});

echo "\nllms.txt: settings input\n";

$t('form input is cleaned: known public types in offered order, cap clamped, text trimmed', function () use ($same) {
    $choices = ['page' => 'Pages', 'post' => 'Posts', 'product' => 'Products'];
    $same([
        'llms_txt_enabled' => true,
        'llms_txt_summary' => 'Hello there',
        'llms_txt_intro' => 'Intro',
        'llms_txt_post_types' => ['page', 'product'],
        'llms_txt_max_items' => 200,
    ], WebDecoy_Llms_Txt::sanitize_settings([
        'llms_txt_enabled' => '1',
        'llms_txt_summary' => "<b>Hello</b>\nthere",
        'llms_txt_intro' => ' Intro ',
        'llms_txt_post_types' => ['product', 'attachment', 'nope', 'PAGE'],
        'llms_txt_max_items' => '999',
    ], $choices));
    $same(false, WebDecoy_Llms_Txt::sanitize_settings([], $choices)['llms_txt_enabled']);
    $same(50, WebDecoy_Llms_Txt::sanitize_settings(['llms_txt_max_items' => 'lots'], $choices)['llms_txt_max_items']);
});

$t('attachments are never offered; pages and posts come first', function () use ($same) {
    $same(['page', 'post', 'product'], array_keys(WebDecoy_Llms_Txt::post_type_choices()));
});

$t('WP-CLI: enable, post types and cap parse; unknown types refuse the value', function () use ($same) {
    $same(['llms_txt_enabled', true], WebDecoy_CLI_Command::parse_config_value('llms_txt_enabled', 'on'));
    $same(['llms_txt_post_types', ['page', 'product']], WebDecoy_CLI_Command::parse_config_value('llms_txt_post_types', 'product, page'));
    $same(['llms_txt_post_types', []], WebDecoy_CLI_Command::parse_config_value('llms_txt_post_types', 'none'));
    $same(null, WebDecoy_CLI_Command::parse_config_value('llms_txt_post_types', 'page,pgae'));
    $same(null, WebDecoy_CLI_Command::parse_config_value('llms_txt_max_items', '201'));
    $same(['llms_txt_summary', 'One line'], WebDecoy_CLI_Command::parse_config_value('llms_txt_summary', "One\nline"));
});

$t('WP-CLI shows the defaults in effect before anything is saved', function () use ($same) {
    $same('false', WebDecoy_CLI_Command::display_value('llms_txt_enabled', []));
    $same('page,post', WebDecoy_CLI_Command::display_value('llms_txt_post_types', []));
    $same('50', WebDecoy_CLI_Command::display_value('llms_txt_max_items', []));
    $same('none', WebDecoy_CLI_Command::display_value('llms_txt_post_types', ['llms_txt_post_types' => []]));
});

exit(TestRunner::summary());
