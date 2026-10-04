<?php

declare(strict_types=1);

namespace WebDecoy;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Recognises a visit an AI product sent: a Referer from an AI chat or search
 * platform, or, with no Referer, a campaign tag naming one.
 *
 * The platform table (registry/llm-platforms.generated.php) is generated from
 * WebDecoy's own classifier, and this is a port of it, pinned case for case by
 * the generated golden vectors (tests/LlmReferralTest.php), so the plugin
 * counts exactly what WebDecoy's other sensors count.
 */
final class LlmReferral
{
    /** Campaign parameters that can name an AI product, in precedence order. */
    private const TAG_KEYS = ['utm_source', 'ref', 'utm_medium'];

    /** @var array<string, string>|null */
    private static $platforms = null;

    /** @return array<string, string> referrer hostname => platform */
    public static function platforms(): array
    {
        if (self::$platforms === null) {
            $loaded = require __DIR__ . '/registry/llm-platforms.generated.php';
            self::$platforms = is_array($loaded) ? $loaded : [];
        }
        return self::$platforms;
    }

    /**
     * The platform a referral came from, or '' when it is not an AI referral.
     * A non-empty Referer decides on its own even when it names no AI
     * product: a campaign tag is easy to forge and must not overrule it.
     */
    public static function classify(string $referer, string $pageUrl): string
    {
        $platforms = self::platforms();
        $referer = trim($referer);
        if ($referer !== '') {
            $host = parse_url($referer, PHP_URL_HOST);
            if (!is_string($host) || $host === '') {
                return '';
            }
            return $platforms[strtolower($host)] ?? '';
        }
        $query = parse_url($pageUrl, PHP_URL_QUERY);
        if (!is_string($query) || $query === '') {
            return '';
        }
        $params = self::queryValues($query);
        foreach (self::TAG_KEYS as $key) {
            foreach ($params[$key] ?? [] as $value) {
                $platform = self::platformForTag($value);
                if ($platform !== '') {
                    return $platform;
                }
            }
        }
        return '';
    }

    /**
     * Every value of every parameter, in order. parse_str() keeps only the
     * last of a repeated key, and a tag must be read the way browsers and the
     * other sensors read it.
     *
     * @return array<string, string[]>
     */
    private static function queryValues(string $query): array
    {
        $out = [];
        foreach (explode('&', $query) as $pair) {
            if ($pair === '') {
                continue;
            }
            $parts = explode('=', $pair, 2);
            $key = urldecode(str_replace('+', ' ', $parts[0]));
            $out[$key][] = urldecode(str_replace('+', ' ', $parts[1] ?? ''));
        }
        return $out;
    }

    private static function squash(string $s): string
    {
        return str_replace([' ', '-', '_', '.'], '', $s);
    }

    private static function platformForTag(string $raw): string
    {
        $platforms = self::platforms();
        $value = strtolower(trim($raw));
        if ($value === '') {
            return '';
        }
        if (strpos($value, '://') !== false) {
            $host = parse_url($value, PHP_URL_HOST);
            if (is_string($host) && $host !== '') {
                $value = strtolower($host);
            }
        }
        $value = rtrim($value, '.');
        if (isset($platforms[$value])) {
            return $platforms[$value];
        }
        $normalized = self::squash($value);
        foreach ($platforms as $domain => $name) {
            $bare = str_replace('.', '', preg_replace('/^www\./', '', $domain) ?? $domain);
            if ($normalized === self::squash(strtolower($name)) || $normalized === $bare) {
                return $name;
            }
        }
        return '';
    }
}
