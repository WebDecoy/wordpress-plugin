<?php

declare(strict_types=1);

namespace WebDecoy\Rules;

/**
 * Request context evaluated by the rule engine.
 *
 * Mirrors the `RuleContext` shape in @webdecoy/node
 * (packages/webdecoy/src/rules/types.ts) so rule semantics stay identical
 * across the two SDKs.
 */
class RuleContext
{
    /** @var string Trusted-proxy-resolved client IP. */
    public $ip;

    /** @var string Request path (may include query/fragment; rules normalize). */
    public $path;

    /** @var string HTTP method. */
    public $method;

    /** @var string User agent, or empty string. */
    public $userAgent;

    /**
     * Request headers, keyed by lowercased header name.
     *
     * @var array<string,string>
     */
    public $headers;

    /** @var int Unix timestamp in milliseconds. */
    public $timestamp;

    /**
     * Optional IP enrichment data (security/location/network/reputation), used
     * by filter rules referencing `ip.*` fields. Null when unavailable.
     *
     * @var array<string,mixed>|null
     */
    public $enrichment;

    /**
     * @param array<string,string>      $headers
     * @param array<string,mixed>|null  $enrichment
     */
    public function __construct(
        string $ip,
        string $path,
        string $method = 'GET',
        string $userAgent = '',
        array $headers = [],
        ?int $timestamp = null,
        ?array $enrichment = null
    ) {
        $this->ip = $ip;
        $this->path = $path;
        $this->method = $method;
        $this->userAgent = $userAgent;
        // Normalize header keys to lowercase for case-insensitive lookups.
        $normalized = [];
        foreach ($headers as $name => $value) {
            $normalized[strtolower((string) $name)] = (string) $value;
        }
        $this->headers = $normalized;
        $this->timestamp = $timestamp ?? (int) round(microtime(true) * 1000);
        $this->enrichment = $enrichment;
    }

    /**
     * Case-insensitive header lookup.
     */
    public function header(string $name): ?string
    {
        return $this->headers[strtolower($name)] ?? null;
    }
}
