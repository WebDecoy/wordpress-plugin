<?php

declare(strict_types=1);

namespace WebDecoy;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * The plain-language sentence for a decoy hit (WebDecoy/app#443).
 *
 * The Detections list shows it, and the WordPress digest email shows the same
 * sentence for the same hit. The sentences are not written here: they are
 * generated from pkg/hitexplain in WebDecoy/app into
 * registry/hit-explanations.generated.php, and this port of Explain is pinned
 * case for case by the generated golden vectors (tests/HitExplanationTest.php).
 *
 * A sentence says only what the stored hit records: the path and which trap
 * it was. It never says how the visitor found the path, why it asked, or that
 * anything was blocked. The result is plain text; escape it on output.
 */
final class HitExplanation
{
    /** The detection source a local tripwire row becomes when reported. */
    public const SOURCE_TRIPWIRE = 'sdk_tripwire';

    /** @var array<string, mixed>|null */
    private static $table = null;

    /** @return array<string, mixed> */
    public static function table(): array
    {
        if (self::$table === null) {
            $loaded = require __DIR__ . '/registry/hit-explanations.generated.php';
            self::$table = is_array($loaded) ? $loaded : [];
        }
        return self::$table;
    }

    /**
     * Which trap a hit touched, or '' when it is not a decoy hit.
     */
    public static function classify(string $source, string $trapKind, string $path): string
    {
        $t = self::table();
        if ($source === $t['source_decoy_link']) {
            return 'decoy_url';
        }
        if ($source === $t['source_decoy_endpoint']) {
            return 'decoy_endpoint';
        }
        if ($source !== $t['source_tripwire']) {
            return '';
        }
        if (in_array($trapKind, $t['trap_kinds'], true)) {
            return $trapKind;
        }
        if (strpos(self::safePath($path), (string) $t['hidden_link_prefix']) === 0) {
            return 'hidden_link';
        }
        return 'trap_path';
    }

    /**
     * The sentence for a hit, or '' when it is not a decoy hit.
     */
    public static function explain(string $source, string $trapKind, string $path): string
    {
        $kind = self::classify($source, $trapKind, $path);
        if ($kind === '') {
            return '';
        }
        $template = self::table()['templates'][$kind];
        $safe = self::safePath($path);
        if ($safe === '') {
            return (string) $template['without_path'];
        }
        return str_replace('{path}', $safe, (string) $template['with_path']);
    }

    /**
     * The sentence for a row of the local detections table, from its flags
     * JSON. Only rule-engine tripwire rows (flag "tripwire_rule") are decoy
     * hits; every other row, including the "decoy_served" follow-up row and
     * test triggers, gets ''.
     */
    public static function forLocalFlags(?string $flagsJson): string
    {
        $data = json_decode((string) $flagsJson, true);
        if (!is_array($data) || !isset($data['flags']) || !is_array($data['flags'])) {
            return '';
        }
        if (!in_array('tripwire_rule', $data['flags'], true)) {
            return '';
        }
        $meta = isset($data['metadata']) && is_array($data['metadata']) ? $data['metadata'] : [];
        $key = (string) self::table()['metadata_key'];
        $kind = isset($meta[$key]) && is_string($meta[$key]) ? $meta[$key] : '';
        $path = isset($meta['path']) && is_string($meta['path']) ? $meta['path'] : '';
        return self::explain(self::SOURCE_TRIPWIRE, $kind, $path);
    }

    /**
     * The part of a stored path a sentence may show: no query string or
     * fragment, no control or text-direction characters, at most
     * max_path_runes characters. Invalid UTF-8 counts as not recorded.
     */
    public static function safePath(string $path): string
    {
        if (preg_match('//u', $path) !== 1) {
            return '';
        }
        $path = substr($path, 0, strcspn($path, '?#'));
        $path = (string) preg_replace(
            '/[\x{0}-\x{1F}\x{7F}-\x{9F}\x{200E}\x{200F}\x{202A}-\x{202E}\x{2066}-\x{2069}]/u',
            '',
            $path
        );
        $path = trim($path, ' ');
        $max = (int) self::table()['max_path_runes'];
        $chars = preg_split('//u', $path, -1, PREG_SPLIT_NO_EMPTY);
        if (is_array($chars) && count($chars) > $max) {
            $path = implode('', array_slice($chars, 0, $max)) . '...';
        }
        return $path;
    }
}
