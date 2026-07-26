<?php

declare(strict_types=1);

namespace WebDecoy;

/**
 * Signal Collector
 *
 * Collects various signals from the current HTTP request
 * for bot detection analysis.
 */
class SignalCollector
{
    // Headers that should be present in legitimate browser requests
    private const EXPECTED_HEADERS = [
        'HTTP_ACCEPT',
        'HTTP_ACCEPT_LANGUAGE',
        'HTTP_ACCEPT_ENCODING',
    ];

    // Priority order for extracting client IP via proxy headers. These are ONLY
    // consulted when the direct peer (REMOTE_ADDR) is a configured trusted proxy.
    private const IP_HEADERS = [
        'HTTP_CF_CONNECTING_IP',      // Cloudflare
        'HTTP_X_REAL_IP',             // Nginx proxy
        'HTTP_X_FORWARDED_FOR',       // Standard proxy
        'REMOTE_ADDR',                // Direct connection
    ];

    /**
     * Trusted proxy IPs/CIDRs. Forwarding headers (X-Forwarded-For,
     * CF-Connecting-IP, X-Real-IP) are only honored when the request's direct
     * peer (REMOTE_ADDR) matches one of these. Empty = direct mode (secure
     * default): forwarding headers are ignored entirely so a client cannot
     * spoof its IP by sending an X-Forwarded-For / CF-Connecting-IP header.
     *
     * @var string[]
     */
    private array $trustedProxies;

    /**
     * @param string[] $trustedProxies List of trusted proxy IPs or CIDR ranges
     */
    public function __construct(array $trustedProxies = [])
    {
        $this->trustedProxies = array_values(array_filter(array_map('trim', $trustedProxies)));
    }

    /**
     * Sanitize a string value (uses WordPress functions if available)
     *
     * @param string|null $value Value to sanitize
     * @return string Sanitized value
     */
    private function sanitizeString(?string $value): string
    {
        if ($value === null) {
            return '';
        }

        // Use WordPress sanitization if available
        if (function_exists('sanitize_text_field')) {
            return sanitize_text_field(wp_unslash($value));
        }

        // Fallback sanitization for non-WordPress environments
        $stripped = function_exists('wp_strip_all_tags') ? wp_strip_all_tags(trim($value)) : strip_tags(trim($value)); // phpcs:ignore WordPress.WP.AlternativeFunctions.strip_tags_strip_tags -- guarded fallback for non-WordPress (standalone SDK) use
        return htmlspecialchars($stripped, ENT_QUOTES, 'UTF-8');
    }

    /**
     * Get a server variable safely
     *
     * @param string $key Server variable key
     * @param string|null $default Default value
     * @return string|null
     */
    private function getServerVar(string $key, ?string $default = null): ?string
    {
        if (!isset($_SERVER[$key])) {
            return $default;
        }

        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- WP path unslashes + sanitizes below; the standalone fallback trims the raw value because wp_unslash() is unavailable outside WordPress
        $value = $_SERVER[$key];

        // Use WordPress sanitization if available
        if (function_exists('sanitize_text_field')) {
            return sanitize_text_field(wp_unslash($value));
        }

        // Basic sanitization for non-WordPress environments
        return is_string($value) ? trim($value) : $default;
    }

    /**
     * Collect all signals from the current request
     *
     * @return array Collected signals
     */
    public function collect(): array
    {
        return [
            'ip_address' => $this->getIP(),
            'user_agent' => $this->getUserAgent(),
            'referer' => $this->getReferer(),
            'headers' => $this->getHeaders(),
            'missing_headers' => $this->detectMissingHeaders(),
            'request_method' => $this->getRequestMethod(),
            'request_uri' => $this->getRequestUri(),
            'is_ajax' => $this->isAjaxRequest(),
            'is_ssl' => $this->isSSL(),
            'has_cookies' => $this->hasCookies(),
            'accept_language' => $this->getAcceptLanguage(),
            'accept_encoding' => $this->getAcceptEncoding(),
            'accept' => $this->getAccept(),
            'timestamp' => time(),
        ];
    }

    /**
     * Get client IP address
     *
     * @return string IP address
     */
    public function getIP(): string
    {
        $remoteAddr = trim((string) $this->getServerVar('REMOTE_ADDR', ''));
        $remoteValid = filter_var($remoteAddr, FILTER_VALIDATE_IP) ? $remoteAddr : '0.0.0.0';

        // Secure default: if no trusted proxies are configured, or the request did
        // not arrive via one of them, never trust client-supplied forwarding
        // headers — they are trivially spoofable (an attacker can send any
        // X-Forwarded-For / CF-Connecting-IP). Use the real connecting address.
        if (empty($this->trustedProxies) || !$this->ipInRanges($remoteAddr, $this->trustedProxies)) {
            return $remoteValid;
        }

        // Request arrived via a trusted proxy. Single-value headers are written by
        // the proxy itself and can be trusted.
        $cfIp = $this->getServerVar('HTTP_CF_CONNECTING_IP');
        if (!empty($cfIp) && filter_var($cfIp, FILTER_VALIDATE_IP)) {
            return $cfIp;
        }
        $realIp = $this->getServerVar('HTTP_X_REAL_IP');
        if (!empty($realIp) && filter_var($realIp, FILTER_VALIDATE_IP)) {
            return $realIp;
        }

        // For X-Forwarded-For, the left-most entries are attacker-controlled. Walk
        // right-to-left and return the first address that is NOT itself a trusted
        // proxy (i.e. the real client as seen by our outermost trusted proxy).
        $xff = $this->getServerVar('HTTP_X_FORWARDED_FOR');
        if (!empty($xff)) {
            $parts = array_map('trim', explode(',', $xff));
            for ($i = count($parts) - 1; $i >= 0; $i--) {
                $candidate = $parts[$i];
                if (!filter_var($candidate, FILTER_VALIDATE_IP)) {
                    continue;
                }
                if ($this->ipInRanges($candidate, $this->trustedProxies)) {
                    continue; // another trusted hop, keep walking left
                }
                return $candidate;
            }
        }

        return $remoteValid;
    }

    /**
     * Check whether an IP falls within any of the given IPs/CIDR ranges.
     *
     * @param string   $ip     IP address to test
     * @param string[] $ranges List of plain IPs or CIDR ranges (v4 or v6)
     */
    private function ipInRanges(string $ip, array $ranges): bool
    {
        if ($ip === '' || !filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }
        foreach ($ranges as $range) {
            $range = trim($range);
            if ($range === '') {
                continue;
            }
            if (strpos($range, '/') === false) {
                if ($ip === $range) {
                    return true;
                }
                continue;
            }
            if ($this->cidrMatch($ip, $range)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Match an IP against a CIDR range. Handles both IPv4 and IPv6.
     */
    private function cidrMatch(string $ip, string $cidr): bool
    {
        $parts = explode('/', $cidr, 2);
        if (count($parts) !== 2) {
            return false;
        }
        [$subnet, $bitsRaw] = $parts;
        $bits = (int) $bitsRaw;

        $ipBin = @inet_pton($ip);
        $subnetBin = @inet_pton(trim($subnet));
        if ($ipBin === false || $subnetBin === false || strlen($ipBin) !== strlen($subnetBin)) {
            return false; // invalid, or IPv4/IPv6 family mismatch
        }

        $maxBits = strlen($ipBin) * 8;
        if ($bits < 0 || $bits > $maxBits) {
            return false;
        }

        $fullBytes = intdiv($bits, 8);
        $remainder = $bits % 8;
        if ($fullBytes > 0 && strncmp($ipBin, $subnetBin, $fullBytes) !== 0) {
            return false;
        }
        if ($remainder === 0) {
            return true;
        }
        $mask = chr((0xff << (8 - $remainder)) & 0xff);
        return ($ipBin[$fullBytes] & $mask) === ($subnetBin[$fullBytes] & $mask);
    }

    /**
     * Get User-Agent string
     *
     * @return string User-Agent
     */
    public function getUserAgent(): string
    {
        return $this->getServerVar('HTTP_USER_AGENT', '') ?? '';
    }

    /**
     * Get HTTP Referer
     *
     * @return string|null Referer URL
     */
    public function getReferer(): ?string
    {
        return $this->getServerVar('HTTP_REFERER');
    }

    /**
     * Get all HTTP headers
     *
     * @return array Headers
     */
    public function getHeaders(): array
    {
        $headers = [];

        foreach ($_SERVER as $key => $value) {
            if (strpos($key, 'HTTP_') === 0) {
                // Convert HTTP_ACCEPT_LANGUAGE to Accept-Language
                $header = str_replace('_', '-', substr($key, 5));
                $header = ucwords(strtolower($header), '-');
                $headers[$header] = $value;
            }
        }

        return $headers;
    }

    /**
     * Detect missing headers that should be present in browser requests
     *
     * @return array List of missing header names
     */
    public function detectMissingHeaders(): array
    {
        $missing = [];

        foreach (self::EXPECTED_HEADERS as $header) {
            if (empty($_SERVER[$header])) {
                $missing[] = $header;
            }
        }

        return $missing;
    }

    /**
     * Get HTTP request method
     *
     * @return string Request method
     */
    public function getRequestMethod(): string
    {
        return $this->getServerVar('REQUEST_METHOD', 'GET') ?? 'GET';
    }

    /**
     * Get request URI
     *
     * @return string Request URI
     */
    public function getRequestUri(): string
    {
        return $this->getServerVar('REQUEST_URI', '/') ?? '/';
    }

    /**
     * Check if request is AJAX
     *
     * @return bool
     */
    public function isAjaxRequest(): bool
    {
        // Check standard header
        $requestedWith = $this->getServerVar('HTTP_X_REQUESTED_WITH');
        if ($requestedWith !== null && strtolower($requestedWith) === 'xmlhttprequest') {
            return true;
        }

        // Check Accept header for JSON
        $accept = $this->getServerVar('HTTP_ACCEPT', '');
        if ($accept !== null && strpos($accept, 'application/json') !== false) {
            return true;
        }

        return false;
    }

    /**
     * Check if request is over SSL/TLS
     *
     * @return bool
     */
    public function isSSL(): bool
    {
        // Check HTTPS server variable
        $https = $this->getServerVar('HTTPS');
        if ($https !== null && $https !== 'off') {
            return true;
        }

        // Check for load balancer/proxy headers
        $forwardedProto = $this->getServerVar('HTTP_X_FORWARDED_PROTO');
        if ($forwardedProto === 'https') {
            return true;
        }

        // Check Cloudflare header
        $cfVisitor = $this->getServerVar('HTTP_CF_VISITOR');
        if ($cfVisitor !== null) {
            $visitor = json_decode($cfVisitor, true);
            if (isset($visitor['scheme']) && $visitor['scheme'] === 'https') {
                return true;
            }
        }

        // Check port
        $port = $this->getServerVar('SERVER_PORT');
        if ($port !== null && (int) $port === 443) {
            return true;
        }

        return false;
    }

    /**
     * Check if request has cookies
     *
     * @return bool
     */
    public function hasCookies(): bool
    {
        return !empty($_COOKIE);
    }

    /**
     * Get Accept-Language header
     *
     * @return string|null
     */
    public function getAcceptLanguage(): ?string
    {
        return $this->getServerVar('HTTP_ACCEPT_LANGUAGE');
    }

    /**
     * Get Accept-Encoding header
     *
     * @return string|null
     */
    public function getAcceptEncoding(): ?string
    {
        return $this->getServerVar('HTTP_ACCEPT_ENCODING');
    }

    /**
     * Get Accept header
     *
     * @return string|null
     */
    public function getAccept(): ?string
    {
        return $this->getServerVar('HTTP_ACCEPT');
    }

    /**
     * Header-name prefixes added by a proxy or CDN rather than by the client.
     *
     * Excluded for the same reason the edge sensor excludes them: they are
     * constant for every request through that infrastructure, so they carry no
     * information, but including them would make the same visitor fingerprint
     * differently here than anywhere else they are seen.
     *
     * @var string[]
     */
    private const PROXY_HEADER_PREFIXES = [
        'cf-',
        'x-forwarded-',
        'x-real-ip',
        'true-client-ip',
        'cdn-loop',
        'x-vercel-',
        'fastly-',
        'x-amz-cf-',
    ];

    /**
     * Client fingerprint material for a detection forwarded to the ingest
     * service (the `cs` payload field).
     *
     * This site's server is reporting somebody else's request, and it beacons
     * over its own HTTP connection — so without this the ingest service has
     * nothing but the beacon's own headers to identify the visitor with, and
     * those are identical for every visitor this site ever reports. It grouped
     * them all into one "actor" as a result.
     *
     * Header VALUES are not forwarded. The identity is composed from the SET of
     * header names plus Accept-Language and Accept-Encoding, so those two are
     * sent and every other header contributes its name alone — nothing here can
     * carry a cookie or an Authorization header off this server.
     *
     * There is no TLS material: PHP is handed a decrypted request and never
     * sees the ClientHello, so no JA3/JA4 is derivable. The header-name set
     * carries the identity on its own, which is weaker but honest.
     *
     * @return array{hn: string[], al: string, ae: string}
     */
    public function getClientSignals(): array
    {
        $names = [];
        foreach (array_keys($this->getHeaders()) as $header) {
            $name = strtolower((string) $header);
            foreach (self::PROXY_HEADER_PREFIXES as $prefix) {
                if (strpos($name, $prefix) === 0) {
                    continue 2;
                }
            }
            $names[] = $name;
        }
        sort($names);

        return [
            'hn' => array_values(array_unique($names)),
            'al' => $this->sanitizeString($this->getAcceptLanguage()),
            'ae' => $this->sanitizeString($this->getAcceptEncoding()),
        ];
    }

    /**
     * Get current page URL
     *
     * @return string Full URL
     */
    public function getCurrentUrl(): string
    {
        $protocol = $this->isSSL() ? 'https' : 'http';
        $host = $this->getServerVar('HTTP_HOST') ?? $this->getServerVar('SERVER_NAME', 'localhost') ?? 'localhost';
        $uri = $this->getServerVar('REQUEST_URI', '/') ?? '/';

        return $protocol . '://' . $host . $uri;
    }

    /**
     * Build fingerprint data from available signals
     *
     * @return array Fingerprint data
     */
    public function buildFingerprint(): array
    {
        $fingerprint = [
            'userAgent' => $this->getUserAgent(),
            'language' => $this->getAcceptLanguage(),
            'languages' => $this->parseAcceptLanguage(),
            'encoding' => $this->getAcceptEncoding(),
            'accept' => $this->getAccept(),
            'timezone' => $this->guessTimezone(),
        ];

        // Add connection info if available
        $connection = $this->getServerVar('HTTP_CONNECTION');
        if ($connection !== null) {
            $fingerprint['connection'] = $connection;
        }

        // Add DNT if present
        $dnt = $this->getServerVar('HTTP_DNT');
        if ($dnt !== null) {
            $fingerprint['doNotTrack'] = $dnt;
        }

        return $fingerprint;
    }

    /**
     * Parse Accept-Language into array
     *
     * @return array Languages with quality values
     */
    private function parseAcceptLanguage(): array
    {
        $acceptLanguage = $this->getAcceptLanguage();
        if (empty($acceptLanguage)) {
            return [];
        }

        $languages = [];
        $parts = explode(',', $acceptLanguage);

        foreach ($parts as $part) {
            $part = trim($part);
            if (strpos($part, ';') !== false) {
                list($lang, $q) = explode(';', $part, 2);
                $lang = trim($lang);
            } else {
                $lang = $part;
            }
            if (!empty($lang)) {
                $languages[] = $lang;
            }
        }

        return $languages;
    }

    /**
     * Attempt to guess timezone from Accept-Language
     *
     * @return string|null Guessed timezone
     */
    private function guessTimezone(): ?string
    {
        // This is a rough guess based on language
        $langTimezones = [
            'en-US' => 'America/New_York',
            'en-GB' => 'Europe/London',
            'de' => 'Europe/Berlin',
            'fr' => 'Europe/Paris',
            'ja' => 'Asia/Tokyo',
            'zh' => 'Asia/Shanghai',
        ];

        $languages = $this->parseAcceptLanguage();
        foreach ($languages as $lang) {
            if (isset($langTimezones[$lang])) {
                return $langTimezones[$lang];
            }
            // Try base language
            $baseLang = explode('-', $lang)[0];
            if (isset($langTimezones[$baseLang])) {
                return $langTimezones[$baseLang];
            }
        }

        return null;
    }

    /**
     * Check if a specific header exists
     *
     * @param string $header Header name (e.g., 'Accept-Language')
     * @return bool
     */
    public function hasHeader(string $header): bool
    {
        $serverKey = 'HTTP_' . strtoupper(str_replace('-', '_', $header));
        return isset($_SERVER[$serverKey]);
    }

    /**
     * Get a specific header value
     *
     * @param string $header Header name
     * @param string|null $default Default value if not present
     * @return string|null
     */
    public function getHeader(string $header, ?string $default = null): ?string
    {
        $serverKey = 'HTTP_' . strtoupper(str_replace('-', '_', $header));
        return $this->getServerVar($serverKey, $default);
    }
}
