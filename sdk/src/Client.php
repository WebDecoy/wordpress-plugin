<?php

declare(strict_types=1);

namespace WebDecoy;

use WebDecoy\Exception\WebDecoyException;

/**
 * WebDecoy API Client
 *
 * Handles all communication with the WebDecoy API for bot detection,
 * threat intelligence, and detection management.
 */
class Client
{
    private const DEFAULT_BASE_URL = 'https://api.webdecoy.com';
    private const DEFAULT_INGEST_URL = 'https://ingest.webdecoy.com';
    private const DEFAULT_TIMEOUT = 10;
    private const USER_AGENT = 'WebDecoy-PHP-SDK/1.0';

    private string $apiKey;
    private string $baseUrl;
    private string $ingestUrl;
    private ?string $organizationId = null;
    private int $timeout;
    private bool $verifySsl;

    /**
     * Create a new WebDecoy API client
     *
     * @param array $config Configuration options:
     *   - api_key: (required) Your WebDecoy API key
     *   - organization_id: (optional) Your organization UUID - will be auto-fetched if not provided
     *   - base_url: (optional) API base URL, defaults to https://api.webdecoy.com
     *   - ingest_url: (optional) Ingest service URL, defaults to https://ingest.webdecoy.com
     *   - timeout: (optional) Request timeout in seconds, defaults to 10
     *   - verify_ssl: (optional) Verify SSL certificates, defaults to true
     * @throws WebDecoyException If required configuration is missing
     */
    public function __construct(array $config)
    {
        if (empty($config['api_key'])) {
            throw new WebDecoyException('API key is required');
        }

        $this->apiKey = $config['api_key'];
        $this->organizationId = $config['organization_id'] ?? null;
        $this->baseUrl = rtrim($config['base_url'] ?? self::DEFAULT_BASE_URL, '/');
        $this->ingestUrl = rtrim($config['ingest_url'] ?? self::DEFAULT_INGEST_URL, '/');
        $this->timeout = $config['timeout'] ?? self::DEFAULT_TIMEOUT;
        $this->verifySsl = $config['verify_ssl'] ?? true;
    }

    /**
     * Validate the API key and fetch organization info
     *
     * @return array Validation response with organization_id, key_name, scopes
     * @throws WebDecoyException On validation error
     */
    public function validateKey(): array
    {
        // Use ingest service for API key validation (CORS-accessible from any domain)
        $response = $this->request('GET', '/api/v1/auth/validate-key', [], true, $this->ingestUrl);

        // Cache the organization ID for future requests
        if (!empty($response['organization_id'])) {
            $this->organizationId = $response['organization_id'];
        }

        return $response;
    }

    /**
     * Ensure organization ID is available, fetching it if necessary
     *
     * @return string The organization ID
     * @throws WebDecoyException If organization ID cannot be determined
     */
    private function ensureOrganizationId(): string
    {
        if ($this->organizationId === null) {
            $this->validateKey();
        }

        if ($this->organizationId === null) {
            throw new WebDecoyException('Could not determine organization ID from API key');
        }

        return $this->organizationId;
    }

    /**
     * Submit a bot detection to the WebDecoy API
     *
     * @param Detection $detection The detection to submit
     * @return array The API response
     * @throws WebDecoyException On API error
     */
    public function submitDetection(Detection $detection): array
    {
        $payload = $detection->toApiPayload($this->ensureOrganizationId());

        // Submit to ingest service (with API key authentication)
        return $this->request('POST', '/api/v1/detect', $payload, true, $this->ingestUrl);
    }

    /**
     * Get detections for the organization
     *
     * @param array $filters Optional filters:
     *   - page: Page number (default 1)
     *   - page_size: Results per page (default 50)
     *   - source: Filter by source (bot_scanner, decoy_link, etc)
     *   - min_bot_score: Minimum threat score
     *   - max_bot_score: Maximum threat score
     *   - threat_level: MINIMAL, LOW, MEDIUM, HIGH, CRITICAL
     *   - start_date: ISO 8601 date string
     *   - end_date: ISO 8601 date string
     *   - ip_address: Filter by IP
     * @return array List of detections with pagination info
     * @throws WebDecoyException On API error
     */
    public function getDetections(array $filters = []): array
    {
        $orgId = $this->ensureOrganizationId();
        $endpoint = "/api/organizations/{$orgId}/detections";

        return $this->request('GET', $endpoint, $filters);
    }

    /**
     * Get a single detection by ID
     *
     * @param string $detectionId The detection UUID
     * @return array The detection details
     * @throws WebDecoyException On API error
     */
    public function getDetection(string $detectionId): array
    {
        $orgId = $this->ensureOrganizationId();
        $endpoint = "/api/organizations/{$orgId}/detections/{$detectionId}";

        return $this->request('GET', $endpoint);
    }

    /**
     * Get detection statistics
     *
     * @param string $startDate Start date (Y-m-d format)
     * @param string $endDate End date (Y-m-d format)
     * @return array Statistics including counts, trends, and breakdowns
     * @throws WebDecoyException On API error
     */
    public function getStats(string $startDate, string $endDate): array
    {
        $orgId = $this->ensureOrganizationId();
        $endpoint = "/api/organizations/{$orgId}/detections/stats";

        return $this->request('GET', $endpoint, [
            'start_date' => $startDate,
            'end_date' => $endDate,
        ]);
    }

    /**
     * Get hourly detection statistics
     *
     * @param string $startDate Start date (Y-m-d format)
     * @param string $endDate End date (Y-m-d format)
     * @return array Hourly statistics
     * @throws WebDecoyException On API error
     */
    public function getHourlyStats(string $startDate, string $endDate): array
    {
        $orgId = $this->ensureOrganizationId();
        $endpoint = "/api/organizations/{$orgId}/detections/stats/hourly";

        return $this->request('GET', $endpoint, [
            'start_date' => $startDate,
            'end_date' => $endDate,
        ]);
    }

    /**
     * Get bot policies for the organization
     *
     * @return array List of bot policies
     * @throws WebDecoyException On API error
     */
    public function getBotPolicies(): array
    {
        $orgId = $this->ensureOrganizationId();
        $endpoint = "/api/organizations/{$orgId}/bot-policies";

        return $this->request('GET', $endpoint);
    }

    /**
     * Get bot scanner configuration
     *
     * @param string $scannerId The scanner UUID
     * @return array Scanner configuration
     * @throws WebDecoyException On API error
     */
    public function getBotScanner(string $scannerId): array
    {
        $orgId = $this->ensureOrganizationId();
        $endpoint = "/api/organizations/{$orgId}/bot-scanners/{$scannerId}";

        return $this->request('GET', $endpoint);
    }

    /**
     * Get the JavaScript snippet for a bot scanner
     *
     * @param string $scannerId The scanner UUID
     * @return array Snippet details including the script tag
     * @throws WebDecoyException On API error
     */
    public function getBotScannerSnippet(string $scannerId): array
    {
        $orgId = $this->ensureOrganizationId();
        $endpoint = "/api/organizations/{$orgId}/bot-scanners/{$scannerId}/snippet";

        return $this->request('GET', $endpoint);
    }

    /**
     * Block an IP address
     *
     * @param string $ip The IP address to block
     * @param int|null $durationHours Duration in hours, null for permanent
     * @param string $reason Reason for blocking
     * @return bool True on success
     * @throws WebDecoyException On API error
     */
    public function blockIP(string $ip, ?int $durationHours = null, string $reason = ''): bool
    {
        $orgId = $this->ensureOrganizationId();
        $endpoint = "/api/organizations/{$orgId}/blocked-ips";

        $payload = [
            'ip_address' => $ip,
            'reason' => $reason,
        ];

        if ($durationHours !== null) {
            $payload['duration_hours'] = $durationHours;
        }

        $this->request('POST', $endpoint, $payload);

        return true;
    }

    /**
     * Unblock an IP address
     *
     * @param string $ip The IP address to unblock
     * @return bool True on success
     * @throws WebDecoyException On API error
     */
    public function unblockIP(string $ip): bool
    {
        $orgId = $this->ensureOrganizationId();
        $endpoint = "/api/organizations/{$orgId}/blocked-ips/{$ip}";

        $this->request('DELETE', $endpoint);

        return true;
    }

    /**
     * Get list of blocked IPs
     *
     * @return array List of blocked IPs
     * @throws WebDecoyException On API error
     */
    public function getBlockedIPs(): array
    {
        $orgId = $this->ensureOrganizationId();
        $endpoint = "/api/organizations/{$orgId}/blocked-ips";

        return $this->request('GET', $endpoint);
    }

    /**
     * Test the API connection and validate the API key
     *
     * @return bool True if connection is successful
     * @throws WebDecoyException On connection error
     */
    public function testConnection(): bool
    {
        try {
            $this->validateKey();
            return true;
        } catch (WebDecoyException $e) {
            if ($e->getCode() === 401 || $e->getCode() === 403) {
                throw new WebDecoyException('Invalid API key or insufficient permissions', $e->getCode());
            }
            throw $e;
        }
    }

    /**
     * Get the organization ID
     *
     * @return string The organization UUID
     * @throws WebDecoyException If organization ID cannot be determined
     */
    public function getOrganizationId(): string
    {
        return $this->ensureOrganizationId();
    }

    /**
     * Make an HTTP request to the API
     *
     * Uses WordPress HTTP API when available, falls back to cURL otherwise.
     *
     * @param string $method HTTP method
     * @param string $endpoint API endpoint
     * @param array $data Request data
     * @param bool $authenticated Whether to include API key auth
     * @param string|null $baseUrlOverride Optional base URL override (for ingest service calls)
     * @return array Decoded response
     * @throws WebDecoyException On error
     */
    private function request(string $method, string $endpoint, array $data = [], bool $authenticated = true, ?string $baseUrlOverride = null): array
    {
        $baseUrl = $baseUrlOverride ?? $this->baseUrl;
        $url = $baseUrl . $endpoint;

        // Add query params for GET requests
        if ($method === 'GET' && !empty($data)) {
            $url .= '?' . http_build_query($data);
            $data = [];
        }

        // Use WordPress HTTP API if available (preferred for WP plugins)
        if (function_exists('wp_remote_request')) {
            return $this->requestWithWordPress($method, $url, $data, $authenticated);
        }

        // Fall back to cURL for non-WordPress environments
        return $this->requestWithCurl($method, $url, $data, $authenticated);
    }

    /**
     * Make HTTP request using WordPress HTTP API
     *
     * @param string $method HTTP method
     * @param string $url Full URL
     * @param array $data Request data
     * @param bool $authenticated Whether to include API key auth
     * @return array Decoded response
     * @throws WebDecoyException On error
     */
    private function requestWithWordPress(string $method, string $url, array $data, bool $authenticated): array
    {
        $headers = [
            'Content-Type' => 'application/json',
            'Accept' => 'application/json',
            'User-Agent' => self::USER_AGENT,
        ];

        if ($authenticated) {
            $headers['Authorization'] = 'Bearer ' . $this->apiKey;
        }

        $args = [
            'method' => $method,
            'timeout' => $this->timeout,
            'headers' => $headers,
            'sslverify' => $this->verifySsl,
        ];

        if (in_array($method, ['POST', 'PUT'], true) && !empty($data)) {
            $args['body'] = wp_json_encode($data);
        }

        $response = wp_remote_request($url, $args);

        if (is_wp_error($response)) {
            throw new WebDecoyException('API request failed: ' . $response->get_error_message(), 0);
        }

        $httpCode = wp_remote_retrieve_response_code($response);
        $body = wp_remote_retrieve_body($response);
        $decoded = json_decode($body, true);

        if ($httpCode >= 400) {
            $message = $decoded['error']['message'] ?? $decoded['message'] ?? 'Unknown error';
            throw new WebDecoyException("API error: {$message}", $httpCode);
        }

        return $decoded ?? [];
    }

    /**
     * Make HTTP request using cURL (fallback for non-WordPress environments)
     *
     * @param string $method HTTP method
     * @param string $url Full URL
     * @param array $data Request data
     * @param bool $authenticated Whether to include API key auth
     * @return array Decoded response
     * @throws WebDecoyException On error
     */
    private function requestWithCurl(string $method, string $url, array $data, bool $authenticated): array
    {
        $headers = [
            'Content-Type: application/json',
            'Accept: application/json',
            'User-Agent: ' . self::USER_AGENT,
        ];

        if ($authenticated) {
            $headers[] = 'Authorization: Bearer ' . $this->apiKey;
        }

        $ch = curl_init();

        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => $this->timeout,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_SSL_VERIFYPEER => $this->verifySsl,
            CURLOPT_SSL_VERIFYHOST => $this->verifySsl ? 2 : 0,
        ]);

        switch ($method) {
            case 'POST':
                curl_setopt($ch, CURLOPT_POST, true);
                curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
                break;
            case 'PUT':
                curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'PUT');
                curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
                break;
            case 'DELETE':
                curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'DELETE');
                break;
        }

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);

        curl_close($ch);

        if ($error) {
            throw new WebDecoyException("API request failed: {$error}", 0);
        }

        $decoded = json_decode($response, true);

        if ($httpCode >= 400) {
            $message = $decoded['error']['message'] ?? $decoded['message'] ?? 'Unknown error';
            throw new WebDecoyException("API error: {$message}", $httpCode);
        }

        return $decoded ?? [];
    }
}
