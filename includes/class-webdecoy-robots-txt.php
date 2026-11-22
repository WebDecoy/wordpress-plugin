<?php

declare(strict_types=1);

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Automatic robots.txt: ask whole categories of bots to stay away.
 *
 * The site owner picks categories (AI training crawlers, SEO tools, ...) and
 * this adds one robots.txt group naming every agent in those categories that
 * has a known robots.txt token, ending in `Disallow: /`. The agent list is
 * the bundled shared registry (\WebDecoy\AgentRegistry), so it is kept current
 * with each plugin update and needs no account or network request.
 *
 * robots.txt is a request. Crawlers that honour it stay away; crawlers that
 * ignore it are not stopped by it. Enforcement is the blocking settings' job,
 * and nothing here changes what the plugin blocks.
 *
 * The block is appended to WordPress's virtual robots.txt through the
 * `robots_txt` filter, after whatever WordPress and other plugins produced,
 * which is left untouched. A physical robots.txt file in the web root is
 * served by the web server instead and WordPress never runs, so the block
 * cannot apply there; the settings page says so and shows the block for
 * copying. This class never writes or deletes that file.
 *
 * Off by default: an empty selection adds nothing, so no site's robots.txt
 * changes on upgrade until its owner chooses categories.
 */
class WebDecoy_Robots_Txt
{
    /** The settings key holding the selected category ids. */
    public const OPTION_KEY = 'robots_disallow_categories';

    /** First line of the block. Also how a block already present is recognised. */
    public const BEGIN_MARKER = '# WebDecoy: AI and bot rules';

    /** Last line of the block. */
    public const END_MARKER = '# End of WebDecoy rules';

    /** Registry category for agents with no category; never offered. */
    private const UNCATEGORISED = 'none';

    /**
     * Characters a robots.txt user-agent value may hold here. The registry is
     * trusted, but anything that could break out of the line (a newline, a
     * `#` starting a comment) is refused rather than written into robots.txt.
     */
    private const SAFE_NAME = '/^[A-Za-z0-9][A-Za-z0-9 ._\-]*$/';

    /**
     * Wire the filter for a site. Adds nothing when no category is chosen or
     * the emergency off switch is defined.
     *
     * @param mixed $categories The stored option value.
     */
    public static function register($categories): void
    {
        // Register even for an empty selection so enabling the first category
        // also invalidates VIP's long-lived virtual robots.txt response.
        add_action('update_option_webdecoy_options', [self::class, 'settings_updated'], 10, 2);
        if (defined('WEBDECOY_DISABLE') && WEBDECOY_DISABLE) {
            return;
        }
        $selected = self::sanitize_categories($categories);
        if ($selected === []) {
            return;
        }
        // Late, so sitemap lines and other plugins' rules come first. Takes
        // only the output: the site's "discourage search engines" flag does
        // not decide this, because the owner chose these categories and the
        // noindex tag that setting adds does not keep training crawlers away.
        // phpcs:ignore WordPressVIPMinimum.Hooks.RestrictedHooks.robots_txt -- Category changes queue a targeted VIP robots.txt purge in settings_updated(); deployment changes still require an operator purge.
        add_filter('robots_txt', static function ($output) use ($selected) {
            return self::append(
                (string) $output,
                $selected,
                defined('WEBDECOY_VERSION') ? (string) WEBDECOY_VERSION : ''
            );
        }, 100, 1);
    }

    /** Queue a targeted VIP purge only when the robots policy changes. */
    public static function settings_updated($old, $new): void
    {
        $before = self::sanitize_categories(is_array($old) ? ($old[self::OPTION_KEY] ?? []) : []);
        $after = self::sanitize_categories(is_array($new) ? ($new[self::OPTION_KEY] ?? []) : []);
        sort($before);
        sort($after);
        if ($before === $after) {
            return;
        }
        if (function_exists('wpvip_purge_edge_cache_for_url')) {
            wpvip_purge_edge_cache_for_url(home_url('/robots.txt'));
        } elseif (function_exists('wpcom_vip_purge_edge_cache_for_url')) {
            wpcom_vip_purge_edge_cache_for_url(home_url('/robots.txt'));
        }
    }

    /**
     * The categories an owner can choose, in registry order, each with the
     * number of distinct robots.txt names it covers. Categories with no named
     * agent are left out: robots.txt has nothing to say to them.
     *
     * @param list<array<string,mixed>>|null $agents Registry agents; null reads the bundled registry.
     * @return array<string,int> category id => agent count
     */
    public static function choices(?array $agents = null): array
    {
        if ($agents === null) {
            $agents = \WebDecoy\AgentRegistry::all();
            $order = array_values(array_diff(\WebDecoy\AgentRegistry::categories(), [self::UNCATEGORISED]));
        } else {
            $order = self::category_order($agents);
        }

        $choices = [];
        foreach ($order as $category) {
            $count = count(self::agent_names([$category], $agents));
            if ($count > 0) {
                $choices[$category] = $count;
            }
        }
        return $choices;
    }

    /**
     * Reduce submitted input to known, choosable category ids, in registry
     * order, without duplicates. Accepts an array (the settings form) or a
     * comma-separated string (WP-CLI). Anything else is an empty selection.
     *
     * @param mixed $input
     * @param list<array<string,mixed>>|null $agents
     * @return list<string>
     */
    public static function sanitize_categories($input, ?array $agents = null): array
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
        foreach (array_keys(self::choices($agents)) as $category) {
            if (isset($wanted[$category])) {
                $selected[] = $category;
            }
        }
        return $selected;
    }

    /**
     * Distinct robots.txt names for the agents in these categories, in
     * registry order. Duplicates are dropped case-insensitively (robots.txt
     * matching ignores case), keeping the first spelling. Agents without a
     * known name, unknown categories and unsafe names contribute nothing.
     *
     * @param list<string> $categories
     * @param list<array<string,mixed>>|null $agents
     * @return list<string>
     */
    public static function agent_names(array $categories, ?array $agents = null): array
    {
        $agents = $agents ?? \WebDecoy\AgentRegistry::all();
        $wanted = array_flip(array_diff($categories, [self::UNCATEGORISED]));

        $names = [];
        $seen = [];
        foreach ($agents as $agent) {
            if (!isset($wanted[(string) ($agent['category'] ?? '')])) {
                continue;
            }
            // The pattern also refuses an empty name (no known robots.txt token).
            $name = trim((string) ($agent['robots_name'] ?? ''));
            if (preg_match(self::SAFE_NAME, $name) !== 1) {
                continue;
            }
            $key = strtolower($name);
            if (isset($seen[$key])) {
                continue;
            }
            $seen[$key] = true;
            $names[] = $name;
        }
        return $names;
    }

    /**
     * The robots.txt block for these categories, or '' when it would name no
     * agent. Ends with a newline.
     *
     * @param list<string> $categories
     * @param list<array<string,mixed>>|null $agents
     */
    public static function block(array $categories, string $version, ?array $agents = null): string
    {
        $names = self::agent_names($categories, $agents);
        if ($names === []) {
            return '';
        }
        $count = count($names);
        $header = self::BEGIN_MARKER . ' (' . $count . ($count === 1 ? ' agent' : ' agents');
        if ($version !== '') {
            $header .= ', updated with plugin version ' . $version;
        }
        $header .= ')';

        $lines = [$header];
        foreach ($names as $name) {
            $lines[] = 'User-agent: ' . $name;
        }
        $lines[] = 'Disallow: /';
        $lines[] = self::END_MARKER;
        return implode("\n", $lines) . "\n";
    }

    /**
     * Append the block to robots.txt output from WordPress and other plugins.
     *
     * The existing output is kept as it is. Nothing is added when the block
     * would be empty or is already there.
     *
     * @param list<string> $categories
     * @param list<array<string,mixed>>|null $agents
     */
    public static function append(string $output, array $categories, string $version, ?array $agents = null): string
    {
        if (strpos($output, self::BEGIN_MARKER) !== false) {
            return $output;
        }
        $block = self::block($categories, $version, $agents);
        if ($block === '') {
            return $output;
        }
        if ($output === '') {
            return $block;
        }
        $separator = substr($output, -1) === "\n" ? "\n" : "\n\n";
        return $output . $separator . $block;
    }

    /**
     * A physical robots.txt that the web server serves instead of WordPress's
     * virtual one, or null when there is none. Checks the WordPress directory
     * and, when WordPress lives in a subdirectory of the site, the site root.
     * The llms.txt generator asks the same question through $name.
     *
     * @param list<string> $roots Directories to check; defaults to the WordPress ones.
     * @param string       $name  File name to look for.
     */
    public static function physical_file(array $roots = [], string $name = 'robots.txt'): ?string
    {
        if ($roots === []) {
            $roots[] = ABSPATH;
            if (function_exists('get_home_path')) {
                $roots[] = get_home_path();
            }
        }
        foreach (array_unique($roots) as $root) {
            $path = rtrim($root, '/\\') . '/' . $name;
            if (is_file($path)) {
                return $path;
            }
        }
        return null;
    }

    /**
     * True when the site's home address sits below a path (example.com/blog).
     * robots.txt is only read from the root of a host, and WordPress serves
     * its virtual one only when the site lives at that root.
     */
    public static function home_is_subdirectory(string $home_url): bool
    {
        $path = (string) wp_parse_url($home_url, PHP_URL_PATH);
        return trim($path, '/') !== '';
    }

    /**
     * Categories in the order the given agents first use them, without the
     * uncategorised bucket. For agent lists other than the bundled registry,
     * whose own category list is used otherwise.
     *
     * @param list<array<string,mixed>> $agents
     * @return list<string>
     */
    private static function category_order(array $agents): array
    {
        $order = [];
        foreach ($agents as $agent) {
            $category = (string) ($agent['category'] ?? '');
            if ($category !== '' && $category !== self::UNCATEGORISED && !in_array($category, $order, true)) {
                $order[] = $category;
            }
        }
        return $order;
    }
}
