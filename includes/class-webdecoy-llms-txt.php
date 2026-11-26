<?php

declare(strict_types=1);

if (!defined('ABSPATH')) {
    exit;
}

/**
 * llms.txt generator: a short Markdown map of the site for AI tools.
 *
 * Follows the llms.txt proposal (https://llmstxt.org): an H1 with the site
 * name, a one-line blockquote summary, optional free text, then one H2
 * section per content type holding `- [Title](url): description` links.
 *
 * Served by WordPress at /llms.txt (below the home path) when the owner turns
 * it on. Off by default, so an upgrade never adds a file to a site.
 *
 * Routing: the request path is compared on `parse_request`, so it works with
 * plain and pretty permalinks alike, needs no rewrite rule and so no
 * permalink flush. `parse_request` runs after `init`, where the plugin counts
 * crawler visits and applies blocking, so a crawler fetching llms.txt is
 * counted, and refused when blocked, exactly like any other request.
 *
 * Cost: the body is built from at most a few hundred published posts, cached
 * in one transient keyed by a fingerprint of the settings and site details,
 * and dropped when a post of an included type changes. A request for any
 * other path costs one string comparison.
 *
 * Things it never does: write or delete a physical llms.txt (the web server
 * serves one of those before WordPress runs; the settings page says so and
 * shows the content to copy), or answer when another plugin already provides
 * llms.txt.
 *
 * {@see self::body()} is the only place the served text is produced: the
 * settings preview and the response read it, never a copy.
 */
class WebDecoy_Llms_Txt
{
    public const ENABLED_KEY = 'llms_txt_enabled';
    public const SUMMARY_KEY = 'llms_txt_summary';
    public const INTRO_KEY = 'llms_txt_intro';
    public const POST_TYPES_KEY = 'llms_txt_post_types';
    public const MAX_ITEMS_KEY = 'llms_txt_max_items';

    /** Content types listed when the owner has not chosen any. */
    public const DEFAULT_POST_TYPES = ['page', 'post'];

    public const DEFAULT_MAX_ITEMS = 50;

    /** Highest links-per-section an owner may ask for. */
    public const MAX_ITEMS_CAP = 200;

    /** The served body never grows past this many bytes. */
    public const MAX_BYTES = 262144;

    /** Longest link description, in characters, before it is shortened. */
    public const DESCRIPTION_CHARS = 200;

    public const SUMMARY_CHARS = 300;
    public const INTRO_CHARS = 4000;

    /** Transient holding the built body and the fingerprint it was built for. */
    public const CACHE_KEY = 'webdecoy_llms_txt';

    /** The file name, relative to the site's home path. */
    public const FILE = 'llms.txt';

    /**
     * Post meta that SEO plugins use to mark one post noindex. A change to
     * any of these drops the cached body.
     */
    private const NOINDEX_META = ['_yoast_wpseo_meta-robots-noindex', 'rank_math_robots', '_seopress_robots_index'];

    /**
     * Wire the hooks. Cache invalidation is always registered, so the
     * settings preview stays current while the file is off; the request
     * handler only when the owner turned it on.
     *
     * @param mixed $options The stored webdecoy_options value.
     */
    public static function register($options): void
    {
        add_action('update_option_webdecoy_options', [self::class, 'settings_updated'], 10, 2);
        add_action('clean_post_cache', [self::class, 'post_changed'], 10, 2);
        foreach (['added_post_meta', 'updated_post_meta', 'deleted_post_meta'] as $hook) {
            add_action($hook, [self::class, 'meta_changed'], 10, 3);
        }
        if (defined('WEBDECOY_DISABLE') && WEBDECOY_DISABLE) {
            return;
        }
        if (!self::settings($options)['enabled']) {
            return;
        }
        add_action('parse_request', [self::class, 'maybe_serve'], 0);
    }

    /**
     * Answer a request for llms.txt, or return and let WordPress carry on.
     */
    public static function maybe_serve(): void
    {
        // Compared with one fixed path and never stored or printed, so it is
        // not sanitized: sanitizing would rewrite percent-encoded paths.
        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
        $uri = isset($_SERVER['REQUEST_URI']) ? (string) wp_unslash($_SERVER['REQUEST_URI']) : '';
        if (!self::is_request($uri, home_url('/'))) {
            return;
        }
        if (self::conflict() !== null) {
            return;
        }
        self::send(self::body());
    }

    /**
     * True when a request URI asks for llms.txt below this home address.
     * The query string is ignored. Pure, for tests.
     */
    public static function is_request(string $request_uri, string $home_url): bool
    {
        if ($request_uri === '') {
            return false;
        }
        if ($request_uri[0] === '/') {
            $request_uri = 'http://localhost' . $request_uri;
        }
        $path = rawurldecode((string) wp_parse_url($request_uri, PHP_URL_PATH));
        $home_path = rtrim((string) wp_parse_url($home_url, PHP_URL_PATH), '/');
        return $path === $home_path . '/' . self::FILE;
    }

    /**
     * Send the body as plain text and end the request.
     *
     * text/plain; charset=utf-8 is what llms.txt files are served as across
     * the web and by the other WordPress implementations, displays in every
     * browser instead of downloading, and every consumer reads it.
     */
    private static function send(string $body): void
    {
        // Full-page caches (WP Super Cache, W3TC, WP Rocket, LiteSpeed) honour
        // this: a cached copy would be served as HTML and stop crawler counts.
        if (!defined('DONOTCACHEPAGE')) {
            // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound -- Full-page caches read this shared constant.
            define('DONOTCACHEPAGE', true);
        }
        status_header(200);
        header('Content-Type: text/plain; charset=utf-8');
        header('X-Content-Type-Options: nosniff');
        // Keeps the file itself out of search results, like other llms.txt
        // providers; it does not stop anything from fetching it.
        header('X-Robots-Tag: noindex');
        header('Cache-Control: no-cache, must-revalidate, max-age=0');
        $method = isset($_SERVER['REQUEST_METHOD']) ? strtoupper(sanitize_key(wp_unslash($_SERVER['REQUEST_METHOD']))) : 'GET';
        if ($method !== 'HEAD') {
            // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- text/plain Markdown with nosniff; build() cleans every field (no tags, no line breaks, link syntax escaped).
            echo $body;
        }
        exit;
    }

    /**
     * The llms.txt text for this site. The one source of the served body and
     * the settings preview. Rebuilt only when the cached copy was made for
     * different settings or site details, or was dropped by a content change.
     */
    public static function body(): string
    {
        $settings = self::settings(get_option('webdecoy_options', []));
        $site = [
            'name' => (string) get_bloginfo('name'),
            'description' => (string) get_bloginfo('description'),
            'home' => (string) home_url('/'),
        ];
        $fingerprint = md5((string) wp_json_encode([
            $settings,
            $site,
            defined('WEBDECOY_VERSION') ? WEBDECOY_VERSION : '',
        ]));

        $cached = get_transient(self::CACHE_KEY);
        if (is_array($cached) && ($cached['fingerprint'] ?? '') === $fingerprint && is_string($cached['body'] ?? null)) {
            return $cached['body'];
        }

        $body = self::build($settings, $site, self::collect($settings));
        set_transient(self::CACHE_KEY, ['fingerprint' => $fingerprint, 'body' => $body], DAY_IN_SECONDS);
        return $body;
    }

    /**
     * The settings with defaults applied and every value in range. Accepts
     * the stored options array (or anything else, read as empty). Pure.
     *
     * @param mixed $options
     * @return array{enabled:bool,summary:string,intro:string,post_types:list<string>,max_items:int}
     */
    public static function settings($options): array
    {
        $options = is_array($options) ? $options : [];

        $types = $options[self::POST_TYPES_KEY] ?? self::DEFAULT_POST_TYPES;
        $types = is_array($types) ? array_values(array_unique(array_filter($types, 'is_string'))) : self::DEFAULT_POST_TYPES;

        $max = $options[self::MAX_ITEMS_KEY] ?? self::DEFAULT_MAX_ITEMS;
        $max = is_numeric($max) ? (int) $max : self::DEFAULT_MAX_ITEMS;

        return [
            'enabled' => !empty($options[self::ENABLED_KEY]),
            'summary' => is_string($options[self::SUMMARY_KEY] ?? null) ? $options[self::SUMMARY_KEY] : '',
            'intro' => is_string($options[self::INTRO_KEY] ?? null) ? $options[self::INTRO_KEY] : '',
            'post_types' => $types,
            'max_items' => max(1, min(self::MAX_ITEMS_CAP, $max)),
        ];
    }

    /**
     * The effective settings under their option keys, for display (WP-CLI).
     *
     * @param mixed $options
     * @return array<string,mixed>
     */
    public static function effective_options($options): array
    {
        $settings = self::settings($options);
        return [
            self::ENABLED_KEY => $settings['enabled'],
            self::SUMMARY_KEY => $settings['summary'],
            self::INTRO_KEY => $settings['intro'],
            self::POST_TYPES_KEY => $settings['post_types'],
            self::MAX_ITEMS_KEY => $settings['max_items'],
        ];
    }

    /**
     * Clean submitted settings (the settings form, or a stored array). Post
     * types are reduced to the public ones offered; a comma-separated string
     * is accepted for WP-CLI.
     *
     * @param array<string,mixed>       $input
     * @param array<string,string>|null $choices Post type name => label; null reads WordPress.
     * @return array<string,mixed> Exactly the five llms.txt keys.
     */
    public static function sanitize_settings(array $input, ?array $choices = null): array
    {
        $max = $input[self::MAX_ITEMS_KEY] ?? self::DEFAULT_MAX_ITEMS;
        $max = is_numeric($max) ? (int) $max : self::DEFAULT_MAX_ITEMS;

        $summary = sanitize_text_field((string) ($input[self::SUMMARY_KEY] ?? ''));
        $intro = sanitize_textarea_field((string) ($input[self::INTRO_KEY] ?? ''));

        return [
            self::ENABLED_KEY => !empty($input[self::ENABLED_KEY]),
            self::SUMMARY_KEY => self::truncate($summary, self::SUMMARY_CHARS),
            self::INTRO_KEY => self::truncate($intro, self::INTRO_CHARS),
            self::POST_TYPES_KEY => self::sanitize_post_types($input[self::POST_TYPES_KEY] ?? [], $choices),
            self::MAX_ITEMS_KEY => max(1, min(self::MAX_ITEMS_CAP, $max)),
        ];
    }

    /**
     * Keep only offered post types, in the order they are offered, once each.
     *
     * @param mixed                     $input An array, or a comma-separated string.
     * @param array<string,string>|null $choices
     * @return list<string>
     */
    public static function sanitize_post_types($input, ?array $choices = null): array
    {
        if (is_string($input)) {
            $input = explode(',', $input);
        }
        if (!is_array($input)) {
            return [];
        }
        $wanted = [];
        foreach ($input as $value) {
            if (is_string($value)) {
                $wanted[strtolower(trim($value))] = true;
            }
        }
        $selected = [];
        foreach (array_keys($choices ?? self::post_type_choices()) as $type) {
            if (isset($wanted[$type])) {
                $selected[] = $type;
            }
        }
        return $selected;
    }

    /**
     * Public post types an owner can list, pages and posts first.
     *
     * @return array<string,string> post type name => plural label
     */
    public static function post_type_choices(): array
    {
        $choices = [];
        foreach (get_post_types(['public' => true], 'objects') as $name => $object) {
            if ($name === 'attachment') {
                continue;
            }
            $choices[(string) $name] = (string) ($object->labels->name ?? $name);
        }
        $first = array_intersect_key($choices, array_flip(self::DEFAULT_POST_TYPES));
        uksort($first, static function ($a, $b): int {
            return array_search($a, self::DEFAULT_POST_TYPES, true) <=> array_search($b, self::DEFAULT_POST_TYPES, true);
        });
        return $first + $choices;
    }

    /**
     * Published, public, indexable posts for each chosen type, newest first
     * (pages and other hierarchical types in menu order).
     *
     * @param array{post_types:list<string>,max_items:int} $settings
     * @return list<array{title:string,items:list<array{title:string,url:string,description:string}>}>
     */
    private static function collect(array $settings): array
    {
        $excluded_ids = [];
        if (function_exists('wc_get_page_id')) {
            // WooCommerce's own noindex pages: nothing there for a reader.
            foreach (['cart', 'checkout', 'myaccount'] as $page) {
                $excluded_ids[(int) wc_get_page_id($page)] = true;
            }
        }
        $yoast_titles = defined('WPSEO_VERSION') ? get_option('wpseo_titles', []) : [];

        $sections = [];
        foreach ($settings['post_types'] as $type) {
            $object = get_post_type_object($type);
            if ($object === null || empty($object->public)) {
                continue;
            }
            $max = $settings['max_items'];
            // Fetch a few spare rows so noindex exclusions rarely shorten a section.
            $posts = get_posts([
                'post_type' => $type,
                'post_status' => 'publish',
                'has_password' => false,
                'posts_per_page' => min($max * 2, $max + 50),
                'orderby' => !empty($object->hierarchical) ? ['menu_order' => 'ASC', 'title' => 'ASC'] : ['date' => 'DESC'],
                'no_found_rows' => true,
                'ignore_sticky_posts' => true,
                'suppress_filters' => false,
                'update_post_term_cache' => $type === 'product',
            ]);
            $type_noindex = is_array($yoast_titles) && !empty($yoast_titles['noindex-' . $type]);

            $items = [];
            foreach ($posts as $post) {
                if (count($items) >= $max) {
                    break;
                }
                if (isset($excluded_ids[(int) $post->ID]) || !self::listable($post, $type_noindex)) {
                    continue;
                }
                $items[] = [
                    'title' => (string) $post->post_title,
                    'url' => (string) get_permalink($post),
                    'description' => self::description_source($post),
                ];
            }
            $sections[] = ['title' => (string) ($object->labels->name ?? $type), 'items' => $items];
        }
        return $sections;
    }

    /**
     * Whether a published post belongs in llms.txt: not marked noindex by an
     * SEO plugin, not a hidden WooCommerce product, and not refused by the
     * `webdecoy_llms_txt_include_post` filter.
     */
    private static function listable(WP_Post $post, bool $type_noindex): bool
    {
        $meta = [];
        foreach (self::NOINDEX_META as $key) {
            $meta[$key] = get_post_meta($post->ID, $key, true);
        }
        $include = !self::noindex_from_meta($meta, $type_noindex);
        if ($include && $post->post_type === 'product' && taxonomy_exists('product_visibility')) {
            $include = !has_term('exclude-from-catalog', 'product_visibility', $post);
        }
        /**
         * Filters whether a published post is listed in llms.txt.
         *
         * @param bool    $include Whether to list it.
         * @param WP_Post $post    The post.
         */
        return (bool) apply_filters('webdecoy_llms_txt_include_post', $include, $post);
    }

    /**
     * True when SEO plugin post meta marks a post noindex. Pure, for tests.
     *
     * Yoast SEO: '1' is noindex, '2' forces index, empty follows the post
     * type default ($type_noindex). Rank Math: an array of robots values.
     * SEOPress: 'yes' is noindex.
     *
     * @param array<string,mixed> $meta
     */
    public static function noindex_from_meta(array $meta, bool $type_noindex = false): bool
    {
        $yoast = (string) (is_scalar($meta['_yoast_wpseo_meta-robots-noindex'] ?? '') ? ($meta['_yoast_wpseo_meta-robots-noindex'] ?? '') : '');
        if ($yoast === '1' || ($yoast === '' && $type_noindex)) {
            return true;
        }
        $rank_math = $meta['rank_math_robots'] ?? null;
        if (is_array($rank_math) && in_array('noindex', $rank_math, true)) {
            return true;
        }
        return ($meta['_seopress_robots_index'] ?? '') === 'yes';
    }

    /**
     * Raw text a link description is cut from: the excerpt, or the content
     * with blocks, shortcodes and tags removed. Content filters are not run:
     * they can be slow and have side effects.
     */
    private static function description_source(WP_Post $post): string
    {
        $text = trim((string) $post->post_excerpt);
        if ($text === '') {
            $text = (string) $post->post_content;
            if (function_exists('excerpt_remove_blocks')) {
                $text = excerpt_remove_blocks($text);
            }
            $text = strip_shortcodes($text);
        }
        return $text;
    }

    /**
     * Assemble the llms.txt text. Every value from the site is cleaned here,
     * so nothing a post title, excerpt or setting holds can add a line,
     * heading or link of its own. Stops adding links before MAX_BYTES.
     * Pure, for tests.
     *
     * @param array{summary:string,intro:string} $settings
     * @param array{name:string,description:string,home:string} $site
     * @param list<array{title:string,items:list<array{title:string,url:string,description:string}>}> $sections
     */
    public static function build(array $settings, array $site, array $sections): string
    {
        $name = self::clean_text($site['name']);
        if ($name === '') {
            $name = self::clean_text((string) wp_parse_url($site['home'], PHP_URL_HOST));
        }
        $out = '# ' . self::escape_markdown($name) . "\n";

        $summary = self::clean_text($settings['summary'] !== '' ? $settings['summary'] : $site['description']);
        if ($summary !== '') {
            $out .= "\n> " . self::escape_markdown(self::truncate($summary, self::SUMMARY_CHARS)) . "\n";
        }

        $intro = self::clean_block($settings['intro']);
        if ($intro !== '') {
            $out .= "\n" . $intro . "\n";
        }

        foreach ($sections as $section) {
            $lines = '';
            foreach ($section['items'] as $item) {
                $line = self::link_line($item['title'], $item['url'], $item['description']);
                if ($line === '') {
                    continue;
                }
                if (strlen($out) + strlen($lines) + strlen($line) + 64 > self::MAX_BYTES) {
                    break;
                }
                $lines .= $line . "\n";
            }
            if ($lines === '') {
                continue;
            }
            $out .= "\n## " . self::escape_markdown(self::clean_text($section['title'])) . "\n\n" . $lines;
        }
        return $out;
    }

    /**
     * One `- [Title](url): description` line, or '' when the title or URL
     * is unusable. Pure, for tests.
     */
    public static function link_line(string $title, string $url, string $description): string
    {
        $title = self::clean_text($title);
        $url = self::link_url($url);
        if ($title === '' || $url === '') {
            return '';
        }
        $line = '- [' . self::escape_markdown($title) . '](' . $url . ')';
        $description = self::truncate(self::clean_text($description), self::DESCRIPTION_CHARS);
        if ($description !== '') {
            $line .= ': ' . self::escape_markdown($description);
        }
        return $line;
    }

    /**
     * An http(s) URL safe inside Markdown link parentheses, or ''.
     * Characters that could close the link or start another are encoded.
     */
    public static function link_url(string $url): string
    {
        $url = esc_url_raw(trim($url), ['http', 'https']);
        if ($url === '') {
            return '';
        }
        return strtr($url, [
            '(' => '%28',
            ')' => '%29',
            ' ' => '%20',
            '<' => '%3C',
            '>' => '%3E',
            '[' => '%5B',
            ']' => '%5D',
            '"' => '%22',
            "'" => '%27',
        ]);
    }

    /**
     * Plain, single-line text: tags removed, entities decoded, every run of
     * whitespace or control characters (line breaks included) collapsed to
     * one space. Pure, for tests.
     */
    public static function clean_text(string $text): string
    {
        if (preg_match('//u', $text) !== 1) {
            // Invalid UTF-8 would make every pattern below fail.
            $text = mb_convert_encoding($text, 'UTF-8', 'UTF-8');
        }
        // Tags first: decoding first would turn an escaped "&lt;3" into the
        // start of a tag and lose the rest of the text.
        $text = wp_strip_all_tags($text);
        $text = html_entity_decode($text, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        // Unicode spaces and line or paragraph separators, control characters
        // (carriage return, line feed, tab, next line) and invisible format
        // characters all become one space.
        $text = (string) preg_replace('/[\p{Z}\p{Cc}\p{Cf}\s]+/u', ' ', $text);
        return trim($text);
    }

    /**
     * Backslash-escape the characters that make Markdown links, images and
     * inline HTML, so text reads as text. Pure.
     */
    public static function escape_markdown(string $text): string
    {
        return strtr($text, ['\\' => '\\\\', '[' => '\\[', ']' => '\\]', '<' => '\\<']);
    }

    /**
     * The owner's free-text section: tags removed, line breaks normalised,
     * no more than one blank line in a row, and lines that would start a
     * heading escaped, so it cannot open a section of its own. Pure.
     */
    public static function clean_block(string $text): string
    {
        $text = str_replace(["\r\n", "\r"], "\n", $text);
        $lines = [];
        foreach (explode("\n", $text) as $line) {
            $line = wp_strip_all_tags($line);
            $line = rtrim((string) preg_replace('/[\p{Cc}\p{Cf}]+/u', '', $line));
            if (preg_match('/^\s*#/', $line) === 1) {
                $line = '\\' . ltrim($line);
            }
            $lines[] = $line;
        }
        $text = trim(implode("\n", $lines));
        return (string) preg_replace("/\n{3,}/", "\n\n", $text);
    }

    /**
     * Shorten to at most $chars characters, at a word boundary where one is
     * close, marking the cut with '...'. Pure.
     */
    public static function truncate(string $text, int $chars): string
    {
        if (mb_strlen($text, 'UTF-8') <= $chars) {
            return $text;
        }
        $cut = mb_substr($text, 0, max(1, $chars - 3), 'UTF-8');
        $space = mb_strrpos($cut, ' ', 0, 'UTF-8');
        if ($space !== false && $space > (int) ($chars * 0.6)) {
            $cut = mb_substr($cut, 0, $space, 'UTF-8');
        }
        return rtrim($cut, " \t.,;:") . '...';
    }

    /**
     * The other plugin providing llms.txt on this site, by name, or null.
     * When one is, WebDecoy does not answer /llms.txt at all.
     *
     * Each check reads the plugin's own switch, confirmed from its source:
     * Website LLMs.txt always serves one; Yoast SEO and All in One SEO write
     * a physical file when their option is on; Rank Math serves one from its
     * llms-txt module.
     *
     * @param callable|null $is_defined  defined() stand-in, for tests.
     * @param callable|null $read_option get_option() stand-in, for tests.
     */
    public static function conflict(?callable $is_defined = null, ?callable $read_option = null): ?string
    {
        $is_defined = $is_defined ?? 'defined';
        $read_option = $read_option ?? static function (string $name) {
            return get_option($name);
        };

        $found = null;
        if ($is_defined('WEBSITE_LLMS_TXT_VERSION')) {
            $found = 'Website LLMs.txt';
        } elseif ($is_defined('WPSEO_VERSION') && self::flag($read_option('wpseo'), ['enable_llms_txt'])) {
            $found = 'Yoast SEO';
        } elseif ($is_defined('RANK_MATH_VERSION') && in_array('llms-txt', (array) $read_option('rank_math_modules'), true)) {
            $found = 'Rank Math';
        } elseif ($is_defined('AIOSEO_FILE') && self::flag($read_option('aioseo_options'), ['sitemap', 'llms', 'enable'])) {
            $found = 'All in One SEO';
        }

        if (function_exists('apply_filters')) {
            /**
             * Filters the name of another plugin that provides llms.txt.
             * Return a name to stop WebDecoy serving it, or null.
             *
             * @param string|null $found
             */
            $found = apply_filters('webdecoy_llms_txt_conflict', $found);
        }
        return is_string($found) && $found !== '' ? $found : null;
    }

    /**
     * Read a nested truthy flag from an option that may be an array or a
     * JSON string (All in One SEO stores JSON).
     *
     * @param mixed        $option
     * @param list<string> $path
     */
    private static function flag($option, array $path): bool
    {
        if (is_string($option)) {
            $option = json_decode($option, true);
        }
        foreach ($path as $key) {
            if (!is_array($option) || !array_key_exists($key, $option)) {
                return false;
            }
            $option = $option[$key];
        }
        return !empty($option);
    }

    /**
     * A physical llms.txt the web server sends instead of WordPress, or null.
     * Same check, same directories, as the robots.txt one.
     *
     * @param list<string> $roots Directories to check; defaults to the WordPress ones.
     */
    public static function physical_file(array $roots = []): ?string
    {
        return WebDecoy_Robots_Txt::physical_file($roots, self::FILE);
    }

    /** Drop the cached body when a post of an included type changes. */
    public static function post_changed($post_id, $post = null): void
    {
        if (!$post instanceof WP_Post) {
            $post = get_post((int) $post_id);
        }
        if (!$post instanceof WP_Post || $post->post_type === 'revision') {
            return;
        }
        $settings = self::settings(get_option('webdecoy_options', []));
        if (in_array($post->post_type, $settings['post_types'], true)) {
            delete_transient(self::CACHE_KEY);
        }
    }

    /** Drop the cached body when an SEO plugin's noindex flag changes. */
    public static function meta_changed($meta_id, $object_id, $meta_key): void
    {
        if (in_array($meta_key, self::NOINDEX_META, true)) {
            self::post_changed((int) $object_id);
        }
    }

    /**
     * Settings saved: drop the cache when the llms.txt settings changed, and
     * on WordPress VIP purge the edge copy of /llms.txt.
     */
    public static function settings_updated($old, $new): void
    {
        if (self::settings($old) === self::settings($new)) {
            return;
        }
        delete_transient(self::CACHE_KEY);
        if (function_exists('wpvip_purge_edge_cache_for_url')) {
            wpvip_purge_edge_cache_for_url(home_url('/' . self::FILE));
        } elseif (function_exists('wpcom_vip_purge_edge_cache_for_url')) {
            wpcom_vip_purge_edge_cache_for_url(home_url('/' . self::FILE));
        }
    }
}
