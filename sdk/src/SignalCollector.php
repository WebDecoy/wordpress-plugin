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

    // Priority order for extracting client IP
    private const IP_HEADERS = [
        'HTTP_CF_CONNECTING_IP',      // Cloudflare
        'HTTP_X_REAL_IP',             // Nginx proxy
        'HTTP_X_FORWARDED_FOR',       // Standard proxy
        'REMOTE_ADDR',                // Direct connection
    ];

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
        return htmlspecialchars(strip_tags(trim($value)), ENT_QUOTES, 'UTF-8');
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

        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Sanitized below
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
        foreach (self::IP_HEADERS as $header) {
            $rawIp = $this->getServerVar($header);
            if (!empty($rawIp)) {
                $ip = $rawIp;

                // Handle comma-separated IPs (X-Forwarded-For)
                if (strpos($ip, ',') !== false) {
                    $ips = explode(',', $ip);
                    $ip = trim($ips[0]);
                }

                // Validate IP
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }

        return $this->getServerVar('REMOTE_ADDR', '0.0.0.0') ?? '0.0.0.0';
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
