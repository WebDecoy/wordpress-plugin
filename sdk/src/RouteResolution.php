<?php

declare(strict_types=1);

namespace WebDecoy;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * What protected paths say about one request path.
 *
 * The rule is written on ResolveRoute in WebDecoy/app pkg/models, and this is
 * its PHP implementation. Go, the Cloudflare Worker, the Lambda and this file
 * replay the same route_resolution_vectors.json, so none of them can change
 * the rule alone. Ported statement for statement from the Worker's
 * route-resolution.ts; where this reads oddly, that is why.
 *
 * A rule is an array with `pattern`, and optionally `min_trust`, `mode`
 * ('monitor' for a watched path), `exceptions` (patterns beneath it that it
 * does not cover) and `refuse_behaviors` (crawler behaviors it refuses).
 */
final class RouteResolution
{
    private const TRUST_RANK = [
        'attested-human' => 2,
        'human-likely' => 1,
        'clean' => 0,
    ];

    private static function rank(?string $grade): int
    {
        return self::TRUST_RANK[$grade ?? ''] ?? 0;
    }

    private static function grade(int $rank): string
    {
        if ($rank <= 0) {
            return '';
        }
        foreach (self::TRUST_RANK as $g => $r) {
            if ($r === $rank) {
                return $g;
            }
        }
        return '';
    }

    /**
     * The pattern grammar, once: a trailing "/*" covers the base and everything
     * beneath it, anything else is an exact path.
     */
    public static function patternMatches(string $path, string $pattern): bool
    {
        if (substr($pattern, -2) === '/*') {
            $base = substr($pattern, 0, -2);
            // "/*" is the whole site: an empty base covers every path.
            if ($base === '') {
                return true;
            }
            return $path === $base || strpos($path, $base . '/') === 0;
        }
        return $path === $pattern;
    }

    /** Exact patterns outrank every prefix; a longer prefix outranks a shorter one. */
    private static function specificity(string $pattern): int
    {
        return substr($pattern, -2) === '/*' ? strlen($pattern) - 2 : 1 << 20;
    }

    /**
     * @param list<array<string,mixed>> $rules
     * @param string $siteMode The site's enforcement mode; anything but 'monitor' is enforcing.
     * @return array{covering:list<string>,deciding_mode:string,attributed:string,required_trust:string,requirement_source:string,previews:list<array<string,mixed>>,excepted_by:string,refused_behaviors:list<string>}
     */
    public static function resolve(string $path, array $rules, string $siteMode): array
    {
        /** @var array<string,int> $strictest */
        $strictest = [];
        /** @var array<string,true> $enforcing */
        $enforcing = [];
        /** @var list<string> $covering */
        $covering = [];
        /** @var list<string> $excepting */
        $excepting = [];
        /** @var array<string,array<string,true>> $refuses */
        $refuses = [];

        // The sorted union of $already and what each pattern refuses; null when empty.
        $refusedUnion = static function (array $already, array $patterns) use (&$refuses): ?array {
            $set = [];
            foreach ($already as $b) {
                $set[$b] = true;
            }
            foreach ($patterns as $p) {
                foreach ($refuses[$p] ?? [] as $b => $_) {
                    $set[$b] = true;
                }
            }
            if ($set === []) {
                return null;
            }
            $out = array_keys($set);
            sort($out, SORT_STRING);
            return $out;
        };
        $preview = static function (string $pattern, string $requiredTrust, ?array $refused): array {
            $out = ['pattern' => $pattern, 'required_trust' => $requiredTrust];
            if ($refused !== null) {
                $out['refused_behaviors'] = $refused;
            }
            return $out;
        };

        foreach ($rules as $r) {
            $pattern = (string) ($r['pattern'] ?? '');
            if (!self::patternMatches($path, $pattern)) {
                continue;
            }
            // An exception removes this path's coverage only.
            $excepted = false;
            foreach ((array) ($r['exceptions'] ?? []) as $e) {
                if (self::patternMatches($path, (string) $e)) {
                    $excepted = true;
                    break;
                }
            }
            if ($excepted) {
                $excepting[] = $pattern;
                continue;
            }
            $seen = array_key_exists($pattern, $strictest);
            if (!$seen) {
                $covering[] = $pattern;
            }
            $tr = self::rank(isset($r['min_trust']) ? (string) $r['min_trust'] : null);
            if (!$seen || $tr > $strictest[$pattern]) {
                $strictest[$pattern] = $tr;
            }
            // Existing enforcing coverage wins: one refusing definition makes the path refuse.
            if (($r['mode'] ?? '') !== 'monitor') {
                $enforcing[$pattern] = true;
            }
            foreach ((array) ($r['refuse_behaviors'] ?? []) as $b) {
                $refuses[$pattern][(string) $b] = true;
            }
        }

        $previews = [];
        if ($covering === []) {
            $exceptedBy = '';
            foreach ($excepting as $p) {
                if ($exceptedBy === '' || self::specificity($p) > self::specificity($exceptedBy)) {
                    $exceptedBy = $p;
                }
            }
            return [
                'covering' => [],
                'deciding_mode' => '',
                'attributed' => '',
                'required_trust' => '',
                'requirement_source' => '',
                'previews' => [],
                'excepted_by' => $exceptedBy,
                'refused_behaviors' => [],
            ];
        }

        // usort is stable since PHP 8.0; on 7.4 the index tiebreak keeps it so,
        // matching Go's sort.SliceStable.
        $indexed = [];
        foreach ($covering as $i => $p) {
            $indexed[] = [$p, $i];
        }
        usort($indexed, static function (array $a, array $b): int {
            $d = self::specificity($b[0]) - self::specificity($a[0]);
            return $d !== 0 ? $d : $a[1] - $b[1];
        });
        $covering = array_map(static function (array $x): string {
            return $x[0];
        }, $indexed);

        $siteMonitors = $siteMode === 'monitor';
        $deciding = array_values(array_filter($covering, static function (string $p) use ($enforcing): bool {
            return isset($enforcing[$p]);
        }));
        $decidingMode = $siteMonitors ? 'monitor' : 'enforce';
        if ($deciding === []) {
            if (!$siteMonitors) {
                // Only Monitor paths cover this request on an enforcing site, so
                // nothing enforces it and each preview starts from no requirement.
                foreach ($covering as $p) {
                    $previews[] = $preview($p, self::grade($strictest[$p] ?? 0), $refusedUnion([], [$p]));
                }
            }
            $deciding = $covering;
            $decidingMode = 'monitor';
        }
        // A monitoring site keeps the same deciding paths, so its would-have-refused
        // counts are what enforcing would refuse.

        $best = 0;
        $source = '';
        foreach ($deciding as $p) {
            $r = $strictest[$p] ?? 0;
            if ($r > $best) {
                $best = $r;
                $source = $p;
            }
        }

        // Overlapping rules add up, over the same paths that set the requirement.
        $refused = $refusedUnion([], $deciding) ?? [];

        if ($decidingMode === 'enforce') {
            foreach ($covering as $p) {
                if (isset($enforcing[$p])) {
                    continue;
                }
                $previews[] = $preview($p, self::grade(max($best, $strictest[$p] ?? 0)), $refusedUnion($refused, [$p]));
            }
        }

        return [
            'covering' => $covering,
            'deciding_mode' => $decidingMode,
            'attributed' => $deciding[0],
            'required_trust' => self::grade($best),
            'requirement_source' => $source,
            'previews' => $previews,
            'excepted_by' => '',
            'refused_behaviors' => $refused,
        ];
    }

    /**
     * The rules a validator config carries, in the shape resolve() reads.
     *
     * Mirrors routeRules() in the Worker: a refusing pattern's exceptions
     * belong to every definition of it; a watched path carries its own mode;
     * a refusal entry is one more definition of its pattern and the resolver
     * unions them.
     *
     * @param array<string,mixed> $config The clearance config body
     * @return list<array<string,mixed>>
     */
    public static function rulesFromConfig(array $config): array
    {
        $routes = array_values(array_filter((array) ($config['routes'] ?? []), 'is_string'));
        $refusing = array_fill_keys($routes, true);
        $except = [];
        foreach ((array) ($config['route_exceptions'] ?? []) as $e) {
            if (is_array($e) && isset($refusing[$e['pattern'] ?? '']) && is_array($e['except'] ?? null)) {
                $except[(string) $e['pattern']] = array_values(array_filter($e['except'], 'is_string'));
            }
        }
        $rules = [];
        foreach ($routes as $p) {
            $rules[] = ['pattern' => $p, 'exceptions' => $except[$p] ?? []];
        }
        foreach ((array) ($config['route_min_trust'] ?? []) as $e) {
            if (is_array($e) && isset($refusing[$e['pattern'] ?? ''])) {
                $rules[] = ['pattern' => (string) $e['pattern'], 'min_trust' => (string) ($e['min_trust'] ?? ''), 'exceptions' => $except[(string) $e['pattern']] ?? []];
            }
        }
        foreach ((array) ($config['monitor_routes'] ?? []) as $e) {
            if (is_array($e) && is_string($e['pattern'] ?? null)) {
                $rules[] = ['pattern' => $e['pattern'], 'min_trust' => (string) ($e['min_trust'] ?? ''), 'mode' => 'monitor', 'exceptions' => array_values(array_filter((array) ($e['except'] ?? []), 'is_string'))];
            }
        }
        foreach ((array) ($config['route_refusals'] ?? []) as $e) {
            if (!is_array($e) || !is_string($e['pattern'] ?? null)) {
                continue;
            }
            $behaviors = array_values(array_filter((array) ($e['refuse_behaviors'] ?? []), 'is_string'));
            if ($behaviors === []) {
                continue;
            }
            if (($e['mode'] ?? '') === 'monitor') {
                $rules[] = ['pattern' => $e['pattern'], 'mode' => 'monitor', 'refuse_behaviors' => $behaviors];
            } elseif (isset($refusing[$e['pattern']])) {
                $rules[] = ['pattern' => $e['pattern'], 'exceptions' => $except[$e['pattern']] ?? [], 'refuse_behaviors' => $behaviors];
            }
        }
        return $rules;
    }
}
