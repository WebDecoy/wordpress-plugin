<?php

declare(strict_types=1);

namespace WebDecoy;

if (!defined('ABSPATH')) {
    exit;
}

// PHP 7.4 polyfill for str_ends_with (available in PHP 8.0+)
// Kept here for non-WordPress contexts where webdecoy.php is not loaded
if (!function_exists('str_ends_with')) {
    function str_ends_with(string $haystack, string $needle): bool
    {
        if ($needle === '') {
            return true;
        }
        return substr($haystack, -strlen($needle)) === $needle;
    }
}

/**
 * Good Bot List
 *
 * Comprehensive list of known legitimate bots including search engines,
 * social media crawlers, AI bots, monitoring services, and more.
 */
class GoodBotList
{
    // Bot categories
    public const CATEGORY_SEARCH_ENGINE = 'search_engine';
    public const CATEGORY_AI_CRAWLER = 'ai_crawler';
    public const CATEGORY_SOCIAL = 'social';
    public const CATEGORY_MONITORING = 'monitoring';
    public const CATEGORY_SEO = 'seo';
    public const CATEGORY_FEED = 'feed';
    public const CATEGORY_ARCHIVE = 'archive';
    public const CATEGORY_DEVELOPER = 'developer';

    /**
     * Bots that require IP verification via reverse DNS, keyed by registry
     * agent id, mapped to the hostname suffixes their operators publish.
     */
    private const VERIFIABLE_BOTS = [
        'googlebot' => ['.googlebot.com', '.google.com'],
        'google-inspectiontool' => ['.googlebot.com', '.google.com'],
        'google-extended' => ['.googlebot.com', '.google.com'],
        'feedfetcher-google' => ['.google.com'],
        'bingbot' => ['.search.msn.com'],
        'msnbot' => ['.search.msn.com'],
        'yandexbot' => ['.yandex.ru', '.yandex.net', '.yandex.com'],
        'baiduspider' => ['.baidu.com', '.baidu.jp'],
        'duckduckbot' => ['.duckduckgo.com'],
        'applebot' => ['.applebot.apple.com'],
        'facebookexternalhit' => ['.facebook.com', '.fbsv.net'],
        'facebot' => ['.facebook.com', '.fbsv.net'],
        'linkedinbot' => ['.linkedin.com'],
        'twitterbot' => ['.twitter.com', '.twttr.com'],
        'pinterestbot' => ['.pinterest.com'],
    ];

    /**
     * Registry categories that are good bots here, and which plugin category
     * each one lands in. A registry category absent from this map (security
     * scanners, scraping frameworks, headless browsers, HTTP clients) is not a
     * good bot: identify() returns null for it and the request is scored as
     * it always was.
     *
     * AI agents and assistants join AI crawlers deliberately: the "Block AI
     * crawlers" switch is the owner's one instruction about AI traffic, and an
     * agent browsing on a person's behalf is still AI traffic.
     */
    private const PLUGIN_CATEGORY = [
        'search_crawler' => self::CATEGORY_SEARCH_ENGINE,
        'ai_search_crawler' => self::CATEGORY_SEARCH_ENGINE,
        'training_crawler' => self::CATEGORY_AI_CRAWLER,
        'ai_agent' => self::CATEGORY_AI_CRAWLER,
        'ai_assistant' => self::CATEGORY_AI_CRAWLER,
        'fetcher' => self::CATEGORY_SOCIAL,
        'monitoring' => self::CATEGORY_MONITORING,
        'seo_crawler' => self::CATEGORY_SEO,
        'feed_reader' => self::CATEGORY_FEED,
        'archiver' => self::CATEGORY_ARCHIVE,
    ];

    /**
     * In-memory cache for verified bot IPs (pattern => [ip => bool])
     * Used as fallback when WordPress transients are not available
     * @var array
     */
    private array $verificationCache = [];

    /**
     * Cache TTL in seconds (1 hour)
     */
    private const CACHE_TTL = 3600;

    /**
     * Get cached verification result (uses WordPress transients if available)
     *
     * @param string $cacheKey
     * @return array|null Cached result or null if not found/expired
     */
    private function getCachedVerification(string $cacheKey): ?array
    {
        // Use WordPress transients if available (persistent across requests)
        if (function_exists('get_transient')) {
            $cached = get_transient('webdecoy_bot_verify_' . md5($cacheKey));
            if ($cached !== false) {
                return $cached;
            }
            return null;
        }

        // Fall back to in-memory cache
        if (isset($this->verificationCache[$cacheKey])) {
            $cached = $this->verificationCache[$cacheKey];
            if (time() - $cached['time'] < self::CACHE_TTL) {
                return $cached['result'];
            }
        }

        return null;
    }

    /**
     * Set cached verification result (uses WordPress transients if available)
     *
     * @param string $cacheKey
     * @param array $result
     */
    private function setCachedVerification(string $cacheKey, array $result): void
    {
        // Use WordPress transients if available (persistent across requests)
        if (function_exists('set_transient')) {
            set_transient('webdecoy_bot_verify_' . md5($cacheKey), $result, self::CACHE_TTL);
            return;
        }

        // Fall back to in-memory cache
        $this->verificationCache[$cacheKey] = [
            'time' => time(),
            'result' => $result,
        ];
    }

    /**
     * Identify a bot from User-Agent string
     *
     * @param string $userAgent
     * @return array|null Bot info ['name', 'category', 'url'] or null
     */
    public function identify(string $userAgent): ?array
    {
        $agent = AgentRegistry::match($userAgent);
        if ($agent === null) {
            return null;
        }
        return self::fromAgent($agent);
    }

    /**
     * The plugin's view of a registry agent, or null when the agent is not a
     * good bot here.
     *
     * @param array<string,mixed> $agent
     * @return array{name:string,category:string,url:string,pattern:string,id:string,behavior:string,registry_category:string}|null
     */
    private static function fromAgent(array $agent): ?array
    {
        $category = self::PLUGIN_CATEGORY[$agent['category']] ?? null;
        if ($category === null) {
            return null;
        }
        return [
            'name' => (string) $agent['name'],
            'category' => $category,
            'url' => (string) $agent['website'],
            'pattern' => (string) $agent['pattern'],
            'id' => (string) $agent['id'],
            // The policy vocabulary (#995): what kind of crawler this is, in
            // the words the dashboard's per-path refusals use.
            'behavior' => (string) ($agent['behavior'] ?? ''),
            'registry_category' => (string) $agent['category'],
        ];
    }

    /**
     * Check if User-Agent belongs to a known good bot
     *
     * @param string $userAgent
     * @return bool
     */
    public function isKnownBot(string $userAgent): bool
    {
        return $this->identify($userAgent) !== null;
    }

    /**
     * Check if a bot is allowed based on policies
     *
     * @param string $botName Bot name (as returned by identify())
     * @param array $policies Array of policies ['allow' => [], 'block' => []]
     * @return bool
     */
    public function isAllowed(string $botName, array $policies = []): bool
    {
        // Check explicit block list
        if (!empty($policies['block']) && in_array($botName, $policies['block'], true)) {
            return false;
        }

        // Check explicit allow list
        if (!empty($policies['allow']) && in_array($botName, $policies['allow'], true)) {
            return true;
        }

        // Default: allow known good bots
        return true;
    }

    /**
     * Get all bots in a specific category
     *
     * @param string $category One of the CATEGORY_* constants
     * @return array List of bot info
     */
    public function getByCategory(string $category): array
    {
        $bots = [];
        foreach ($this->getAllBots() as $bot) {
            if ($bot['category'] === $category) {
                $bots[] = $bot;
            }
        }
        return $bots;
    }

    /**
     * Get all search engine bots
     *
     * @return array
     */
    public function getSearchEngineBots(): array
    {
        return $this->getByCategory(self::CATEGORY_SEARCH_ENGINE);
    }

    /**
     * Get all AI crawler bots
     *
     * @return array
     */
    public function getAICrawlers(): array
    {
        return $this->getByCategory(self::CATEGORY_AI_CRAWLER);
    }

    /**
     * Get all social media bots
     *
     * @return array
     */
    public function getSocialBots(): array
    {
        return $this->getByCategory(self::CATEGORY_SOCIAL);
    }

    /**
     * Get all monitoring bots
     *
     * @return array
     */
    public function getMonitoringBots(): array
    {
        return $this->getByCategory(self::CATEGORY_MONITORING);
    }

    /**
     * Get all SEO tool bots
     *
     * @return array
     */
    public function getSEOBots(): array
    {
        return $this->getByCategory(self::CATEGORY_SEO);
    }

    /**
     * Get all known bots
     *
     * @return array
     */
    public function getAllBots(): array
    {
        $bots = [];
        foreach (AgentRegistry::all() as $agent) {
            $agent['pattern'] = (string) ($agent['patterns'][0] ?? '');
            $bot = self::fromAgent($agent);
            if ($bot !== null) {
                $bots[] = $bot;
            }
        }
        return $bots;
    }

    /**
     * Get all available categories
     *
     * @return array
     */
    public function getCategories(): array
    {
        return [
            self::CATEGORY_SEARCH_ENGINE,
            self::CATEGORY_AI_CRAWLER,
            self::CATEGORY_SOCIAL,
            self::CATEGORY_MONITORING,
            self::CATEGORY_SEO,
            self::CATEGORY_FEED,
            self::CATEGORY_ARCHIVE,
            self::CATEGORY_DEVELOPER,
        ];
    }

    /**
     * Get bot count by category
     *
     * @return array ['category' => count]
     */
    public function getCategoryCounts(): array
    {
        $counts = [];
        foreach ($this->getCategories() as $category) {
            $counts[$category] = 0;
        }
        foreach ($this->getAllBots() as $bot) {
            $counts[$bot['category']]++;
        }
        return $counts;
    }

    /**
     * Verify a bot claim by checking if the IP matches expected hostname patterns
     * Uses reverse DNS lookup followed by forward DNS verification
     *
     * @param string $userAgent The User-Agent string
     * @param string $ip The client IP address
     * @return array ['verified' => bool, 'hostname' => string|null, 'reason' => string]
     */
    public function verifyBotIP(string $userAgent, string $ip): array
    {
        // Identify the bot from User-Agent
        $bot = $this->identify($userAgent);

        if ($bot === null) {
            return [
                'verified' => false,
                'hostname' => null,
                'reason' => 'not_a_known_bot',
            ];
        }

        $pattern = $bot['id'];

        // Check if this bot requires IP verification
        if (!isset(self::VERIFIABLE_BOTS[$pattern])) {
            // Bot doesn't require verification (monitoring tools, etc.)
            return [
                'verified' => true,
                'hostname' => null,
                'reason' => 'verification_not_required',
            ];
        }

        // Check cache first (uses WordPress transients if available for persistence)
        $cacheKey = $pattern . ':' . $ip;
        $cached = $this->getCachedVerification($cacheKey);
        if ($cached !== null) {
            return $cached;
        }

        // Perform reverse DNS lookup
        $result = $this->performReverseDNSVerification($ip, self::VERIFIABLE_BOTS[$pattern]);

        // Cache the result (uses WordPress transients if available)
        $this->setCachedVerification($cacheKey, $result);

        return $result;
    }

    /**
     * Perform reverse DNS verification
     * 1. Get hostname from IP (reverse DNS)
     * 2. Verify hostname ends with expected suffix
     * 3. Forward resolve hostname to verify it resolves back to original IP
     *
     * @param string $ip The IP address to verify
     * @param array $expectedSuffixes List of valid hostname suffixes
     * @return array ['verified' => bool, 'hostname' => string|null, 'reason' => string]
     */
    private function performReverseDNSVerification(string $ip, array $expectedSuffixes): array
    {
        // Validate IP format
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return [
                'verified' => false,
                'hostname' => null,
                'reason' => 'invalid_ip',
            ];
        }

        // Step 1: Reverse DNS lookup
        $hostname = @gethostbyaddr($ip);

        if ($hostname === false || $hostname === $ip) {
            return [
                'verified' => false,
                'hostname' => null,
                'reason' => 'no_reverse_dns',
            ];
        }

        $hostname = strtolower($hostname);

        // Step 2: Check if hostname ends with expected suffix
        $matchesSuffix = false;
        foreach ($expectedSuffixes as $suffix) {
            $suffixLower = strtolower($suffix);
            $suffixLen = strlen($suffixLower);
            if ($suffixLen === 0 || substr($hostname, -$suffixLen) === $suffixLower) {
                $matchesSuffix = true;
                break;
            }
        }

        if (!$matchesSuffix) {
            return [
                'verified' => false,
                'hostname' => $hostname,
                'reason' => 'hostname_mismatch',
            ];
        }

        // Step 3: Forward DNS verification - ensure hostname resolves back to original IP
        $resolvedIPs = @gethostbynamel($hostname);

        if ($resolvedIPs === false || !is_array($resolvedIPs)) {
            // Try IPv6 resolution if IPv4 fails
            $dns = @dns_get_record($hostname, DNS_AAAA);
            if ($dns !== false && is_array($dns)) {
                $resolvedIPs = array_column($dns, 'ipv6');
            }
        }

        if (empty($resolvedIPs)) {
            return [
                'verified' => false,
                'hostname' => $hostname,
                'reason' => 'forward_dns_failed',
            ];
        }

        // Check if original IP is in resolved IPs
        if (!in_array($ip, $resolvedIPs, true)) {
            return [
                'verified' => false,
                'hostname' => $hostname,
                'reason' => 'ip_mismatch',
            ];
        }

        // All checks passed!
        return [
            'verified' => true,
            'hostname' => $hostname,
            'reason' => 'verified',
        ];
    }

    /**
     * Check if a bot claim is legitimate (User-Agent + IP verification)
     *
     * @param string $userAgent The User-Agent string
     * @param string $ip The client IP address
     * @return bool True if the bot is verified or doesn't require verification
     */
    public function isVerifiedBot(string $userAgent, string $ip): bool
    {
        $result = $this->verifyBotIP($userAgent, $ip);
        return $result['verified'];
    }

    /**
     * Identify and verify a bot in one call
     *
     * @param string $userAgent The User-Agent string
     * @param string $ip The client IP address
     * @return array|null Bot info with verification status, or null if not a bot
     */
    public function identifyAndVerify(string $userAgent, string $ip): ?array
    {
        $bot = $this->identify($userAgent);

        if ($bot === null) {
            return null;
        }

        $verification = $this->verifyBotIP($userAgent, $ip);

        return array_merge($bot, [
            'verified' => $verification['verified'],
            'verified_hostname' => $verification['hostname'],
            'verification_reason' => $verification['reason'],
            'requires_verification' => isset(self::VERIFIABLE_BOTS[$bot['id']]),
        ]);
    }

    /**
     * Check if a bot requires IP verification.
     *
     * Takes the registry agent id, or a User-Agent pattern for callers that
     * still hold the matched pattern from identify().
     *
     * @param string $key The registry id or the matched pattern
     * @return bool
     */
    public function requiresVerification(string $key): bool
    {
        return $this->getExpectedHostnames($key) !== null;
    }

    /**
     * Get the expected hostname suffixes for a bot.
     *
     * @param string $key The registry id or the matched pattern
     * @return array|null List of expected suffixes, or null if verification not required
     */
    public function getExpectedHostnames(string $key): ?array
    {
        if (isset(self::VERIFIABLE_BOTS[$key])) {
            return self::VERIFIABLE_BOTS[$key];
        }
        $agent = AgentRegistry::match($key);
        if ($agent !== null && isset(self::VERIFIABLE_BOTS[$agent['id']])) {
            return self::VERIFIABLE_BOTS[$agent['id']];
        }
        return null;
    }

    /**
     * Clear the verification cache
     */
    public function clearCache(): void
    {
        $this->verificationCache = [];
    }
}
