<?php

declare(strict_types=1);

namespace WebDecoy\Rules;

/**
 * Tripwire Rule (F4 — deception layer).
 *
 * Deterministic, zero-false-positive bot detection: a request for a hidden
 * honeypot path (a "tripwire") that a real user can never reach — because it is
 * only exposed as an invisible link or is scanner-bait no human ever types — is,
 * by construction, automated.
 *
 * Unlike fingerprinting (which stealth tooling is purpose-built to defeat), a
 * tripwire detects *intent* — going where a human cannot — which cannot be
 * spoofed away by a better browser fingerprint.
 *
 * Faithful PHP port of @webdecoy/node's tripwire-rule.ts. The default path list
 * MUST stay in lockstep with node's DEFAULT_TRIPWIRE_PATHS.
 */
class TripwireRule implements RuleInterface
{
    /**
     * Common scanner/scraper bait paths that no legitimate user ever requests.
     * Kept byte-identical to @webdecoy/node's DEFAULT_TRIPWIRE_PATHS.
     *
     * @var string[]
     */
    public const DEFAULT_TRIPWIRE_PATHS = [
        '/.git/config',
        '/.git/HEAD',
        '/.env',
        '/.env.local',
        '/.env.production',
        '/wp-config.php',
        '/config.php',
        '/.aws/credentials',
        '/.ssh/id_rsa',
        '/backup.zip',
        '/backup.sql',
        '/database.sql',
        '/dump.sql',
        '/.DS_Store',
        '/phpinfo.php',
        '/server-status',
        '/actuator/env',
        '/.vscode/sftp.json',
    ];

    /** @var array<string,bool> Exact paths as a lookup set. */
    private $exact;

    /** @var string[] */
    private $prefixes;

    /** @var string[] Regex patterns (PCRE, without delimiters). */
    private $patterns;

    /** @var string DENY or THROTTLE. */
    private $action;

    /** @var bool */
    private $dryRun;

    /**
     * @param array<string,mixed> $config {
     *     @type string[] $paths            Extra exact paths.
     *     @type string[] $prefixes         Match paths that start with any of these.
     *     @type string[] $patterns         Regex patterns (PCRE bodies, no delimiters).
     *     @type bool     $includeDefaults  Merge DEFAULT_TRIPWIRE_PATHS (default true).
     *     @type string   $action           DENY (default) or THROTTLE.
     *     @type bool     $dryRun           Record but don't block (default false).
     * }
     */
    public function __construct(array $config = [])
    {
        $paths = $config['paths'] ?? [];
        if ($config['includeDefaults'] ?? true) {
            $paths = array_merge($paths, self::DEFAULT_TRIPWIRE_PATHS);
        }

        $this->exact = [];
        foreach ($paths as $path) {
            $this->exact[$path] = true;
        }

        $this->prefixes = $config['prefixes'] ?? [];
        $this->patterns = $config['patterns'] ?? [];
        $this->action = $config['action'] ?? RuleResult::DENY;
        $this->dryRun = $config['dryRun'] ?? false;
    }

    public function getName(): string
    {
        return 'tripwire';
    }

    /**
     * Strip query string and fragment for path matching (mirrors node's
     * normalizePath).
     */
    private static function normalizePath(string $path): string
    {
        $path = explode('#', $path, 2)[0];
        $path = explode('?', $path, 2)[0];
        return $path;
    }

    public function evaluate(RuleContext $context): RuleResult
    {
        $path = self::normalizePath($context->path);

        $hit = isset($this->exact[$path]);

        if (!$hit) {
            foreach ($this->prefixes as $prefix) {
                if ($prefix !== '' && strpos($path, $prefix) === 0) {
                    $hit = true;
                    break;
                }
            }
        }

        if (!$hit) {
            foreach ($this->patterns as $pattern) {
                // Invalid regex must not throw; treat as non-match (fail-open).
                $delimited = '#' . str_replace('#', '\\#', $pattern) . '#';
                // phpcs:ignore
                if (@preg_match($delimited, $path) === 1) {
                    $hit = true;
                    break;
                }
            }
        }

        if ($hit) {
            return new RuleResult(
                $this->dryRun ? RuleResult::ALLOW : $this->action,
                'tripwire',
                'Tripwire hit: ' . $path . ' — hidden honeypot path, deterministic automated-intent signal',
                ['path' => $path, 'dryRun' => $this->dryRun, 'confidence' => 100]
            );
        }

        return RuleResult::allow('tripwire');
    }
}
