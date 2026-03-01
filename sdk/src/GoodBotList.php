<?php

declare(strict_types=1);

namespace WebDecoy;

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
     * Bots that require IP verification via reverse DNS
     * Maps bot pattern to expected hostname suffix(es)
     */
    private const VERIFIABLE_BOTS = [
        'googlebot' => ['.googlebot.com', '.google.com'],
        'google-inspectiontool' => ['.googlebot.com', '.google.com'],
        'google-extended' => ['.googlebot.com', '.google.com'],
        'feedfetcher' => ['.google.com'],
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
     * Known good bots with their patterns and categories
     *
     * Format: 'pattern' => ['name' => '...', 'category' => '...', 'url' => '...']
     */
    private const BOTS = [
        // Search Engines
        'googlebot' => [
            'name' => 'Googlebot',
            'category' => self::CATEGORY_SEARCH_ENGINE,
            'url' => 'https://developers.google.com/search/docs/crawling-indexing/googlebot',
        ],
        'google-inspectiontool' => [
            'name' => 'Google Inspection Tool',
            'category' => self::CATEGORY_SEARCH_ENGINE,
            'url' => 'https://support.google.com/webmasters/answer/9012289',
        ],
        'bingbot' => [
            'name' => 'Bingbot',
            'category' => self::CATEGORY_SEARCH_ENGINE,
            'url' => 'https://www.bing.com/webmasters/help/which-crawlers-does-bing-use-8c184ec0',
        ],
        'msnbot' => [
            'name' => 'MSNBot',
            'category' => self::CATEGORY_SEARCH_ENGINE,
            'url' => 'https://www.bing.com/webmasters',
        ],
        'yandexbot' => [
            'name' => 'YandexBot',
            'category' => self::CATEGORY_SEARCH_ENGINE,
            'url' => 'https://yandex.com/support/webmaster/robot-workings/check-yandex-robots.html',
        ],
        'baiduspider' => [
            'name' => 'Baiduspider',
            'category' => self::CATEGORY_SEARCH_ENGINE,
            'url' => 'http://www.baidu.com/search/spider.html',
        ],
        'duckduckbot' => [
            'name' => 'DuckDuckBot',
            'category' => self::CATEGORY_SEARCH_ENGINE,
            'url' => 'https://duckduckgo.com/duckduckbot',
        ],
        'slurp' => [
            'name' => 'Yahoo Slurp',
            'category' => self::CATEGORY_SEARCH_ENGINE,
            'url' => 'https://help.yahoo.com/kb/slurp-crawling-page-sln22600.html',
        ],
        'sogou' => [
            'name' => 'Sogou Spider',
            'category' => self::CATEGORY_SEARCH_ENGINE,
            'url' => 'https://www.sogou.com/docs/help/webmasters.htm',
        ],
        'exabot' => [
            'name' => 'Exabot',
            'category' => self::CATEGORY_SEARCH_ENGINE,
            'url' => 'https://www.exalead.com/search/webmasterguide',
        ],
        'qwantify' => [
            'name' => 'Qwantify',
            'category' => self::CATEGORY_SEARCH_ENGINE,
            'url' => 'https://www.qwant.com/',
        ],
        'applebot' => [
            'name' => 'Applebot',
            'category' => self::CATEGORY_SEARCH_ENGINE,
            'url' => 'https://support.apple.com/en-us/HT204683',
        ],

        // AI Crawlers
        'gptbot' => [
            'name' => 'GPTBot',
            'category' => self::CATEGORY_AI_CRAWLER,
            'url' => 'https://platform.openai.com/docs/gptbot',
        ],
        'chatgpt-user' => [
            'name' => 'ChatGPT User',
            'category' => self::CATEGORY_AI_CRAWLER,
            'url' => 'https://platform.openai.com/docs/plugins/bot',
        ],
        'oai-searchbot' => [
            'name' => 'OAI-SearchBot',
            'category' => self::CATEGORY_AI_CRAWLER,
            'url' => 'https://platform.openai.com/',
        ],
        'claudebot' => [
            'name' => 'ClaudeBot',
            'category' => self::CATEGORY_AI_CRAWLER,
            'url' => 'https://www.anthropic.com/',
        ],
        'claude-web' => [
            'name' => 'Claude-Web',
            'category' => self::CATEGORY_AI_CRAWLER,
            'url' => 'https://www.anthropic.com/',
        ],
        'anthropic-ai' => [
            'name' => 'Anthropic-AI',
            'category' => self::CATEGORY_AI_CRAWLER,
            'url' => 'https://www.anthropic.com/',
        ],
        'perplexitybot' => [
            'name' => 'PerplexityBot',
            'category' => self::CATEGORY_AI_CRAWLER,
            'url' => 'https://www.perplexity.ai/',
        ],
        'ccbot' => [
            'name' => 'CCBot',
            'category' => self::CATEGORY_AI_CRAWLER,
            'url' => 'https://commoncrawl.org/ccbot',
        ],
        'cohere-ai' => [
            'name' => 'Cohere-AI',
            'category' => self::CATEGORY_AI_CRAWLER,
            'url' => 'https://cohere.ai/',
        ],
        'google-extended' => [
            'name' => 'Google-Extended',
            'category' => self::CATEGORY_AI_CRAWLER,
            'url' => 'https://developers.google.com/search/docs/crawling-indexing/overview-google-crawlers',
        ],
        'meta-externalagent' => [
            'name' => 'Meta-ExternalAgent',
            'category' => self::CATEGORY_AI_CRAWLER,
            'url' => 'https://developers.facebook.com/',
        ],
        'amazonbot' => [
            'name' => 'Amazonbot',
            'category' => self::CATEGORY_AI_CRAWLER,
            'url' => 'https://developer.amazon.com/amazonbot',
        ],

        // Social Media
        'twitterbot' => [
            'name' => 'Twitterbot',
            'category' => self::CATEGORY_SOCIAL,
            'url' => 'https://developer.twitter.com/en/docs/twitter-for-websites/cards/guides/getting-started',
        ],
        'facebookexternalhit' => [
            'name' => 'Facebook External Hit',
            'category' => self::CATEGORY_SOCIAL,
            'url' => 'https://developers.facebook.com/docs/sharing/webmasters/crawler',
        ],
        'facebot' => [
            'name' => 'Facebot',
            'category' => self::CATEGORY_SOCIAL,
            'url' => 'https://developers.facebook.com/',
        ],
        'linkedinbot' => [
            'name' => 'LinkedInBot',
            'category' => self::CATEGORY_SOCIAL,
            'url' => 'https://www.linkedin.com/',
        ],
        'pinterestbot' => [
            'name' => 'Pinterestbot',
            'category' => self::CATEGORY_SOCIAL,
            'url' => 'https://www.pinterest.com/',
        ],
        'slackbot' => [
            'name' => 'Slackbot',
            'category' => self::CATEGORY_SOCIAL,
            'url' => 'https://api.slack.com/robots',
        ],
        'telegrambot' => [
            'name' => 'TelegramBot',
            'category' => self::CATEGORY_SOCIAL,
            'url' => 'https://telegram.org/',
        ],
        'whatsapp' => [
            'name' => 'WhatsApp',
            'category' => self::CATEGORY_SOCIAL,
            'url' => 'https://www.whatsapp.com/',
        ],
        'discordbot' => [
            'name' => 'Discordbot',
            'category' => self::CATEGORY_SOCIAL,
            'url' => 'https://discord.com/',
        ],
        'redditbot' => [
            'name' => 'Redditbot',
            'category' => self::CATEGORY_SOCIAL,
            'url' => 'https://www.reddit.com/',
        ],

        // Monitoring & Uptime
        'pingdom' => [
            'name' => 'Pingdom',
            'category' => self::CATEGORY_MONITORING,
            'url' => 'https://www.pingdom.com/',
        ],
        'uptimerobot' => [
            'name' => 'UptimeRobot',
            'category' => self::CATEGORY_MONITORING,
            'url' => 'https://uptimerobot.com/',
        ],
        'newrelicpinger' => [
            'name' => 'NewRelicPinger',
            'category' => self::CATEGORY_MONITORING,
            'url' => 'https://newrelic.com/',
        ],
        'datadogsynthetics' => [
            'name' => 'DatadogSynthetics',
            'category' => self::CATEGORY_MONITORING,
            'url' => 'https://www.datadoghq.com/',
        ],
        'statuscake' => [
            'name' => 'StatusCake',
            'category' => self::CATEGORY_MONITORING,
            'url' => 'https://www.statuscake.com/',
        ],
        'site24x7' => [
            'name' => 'Site24x7',
            'category' => self::CATEGORY_MONITORING,
            'url' => 'https://www.site24x7.com/',
        ],
        'gtmetrix' => [
            'name' => 'GTmetrix',
            'category' => self::CATEGORY_MONITORING,
            'url' => 'https://gtmetrix.com/',
        ],
        'pagespeed' => [
            'name' => 'PageSpeed',
            'category' => self::CATEGORY_MONITORING,
            'url' => 'https://pagespeed.web.dev/',
        ],

        // SEO Tools
        'semrushbot' => [
            'name' => 'SemrushBot',
            'category' => self::CATEGORY_SEO,
            'url' => 'https://www.semrush.com/bot/',
        ],
        'ahrefsbot' => [
            'name' => 'AhrefsBot',
            'category' => self::CATEGORY_SEO,
            'url' => 'https://ahrefs.com/robot',
        ],
        'mj12bot' => [
            'name' => 'MJ12bot (Majestic)',
            'category' => self::CATEGORY_SEO,
            'url' => 'https://majestic.com/reports/majestic-bot',
        ],
        'dotbot' => [
            'name' => 'DotBot (Moz)',
            'category' => self::CATEGORY_SEO,
            'url' => 'https://moz.com/help/moz-procedures/crawlers/dotbot',
        ],
        'screaming frog' => [
            'name' => 'Screaming Frog',
            'category' => self::CATEGORY_SEO,
            'url' => 'https://www.screamingfrog.co.uk/',
        ],

        // Feed Readers
        'feedfetcher' => [
            'name' => 'Feedfetcher-Google',
            'category' => self::CATEGORY_FEED,
            'url' => 'https://www.google.com/',
        ],
        'feedly' => [
            'name' => 'Feedly',
            'category' => self::CATEGORY_FEED,
            'url' => 'https://feedly.com/',
        ],
        'newsblur' => [
            'name' => 'NewsBlur',
            'category' => self::CATEGORY_FEED,
            'url' => 'https://newsblur.com/',
        ],

        // Archive/Research
        'archive.org_bot' => [
            'name' => 'Archive.org Bot',
            'category' => self::CATEGORY_ARCHIVE,
            'url' => 'https://archive.org/details/archive.org_bot',
        ],
        'ia_archiver' => [
            'name' => 'Internet Archive',
            'category' => self::CATEGORY_ARCHIVE,
            'url' => 'https://archive.org/',
        ],

        // Developer Tools
        'w3c_validator' => [
            'name' => 'W3C Validator',
            'category' => self::CATEGORY_DEVELOPER,
            'url' => 'https://validator.w3.org/',
        ],
        'validator.nu' => [
            'name' => 'Validator.nu',
            'category' => self::CATEGORY_DEVELOPER,
            'url' => 'https://validator.nu/',
        ],
    ];

    /**
     * Identify a bot from User-Agent string
     *
     * @param string $userAgent
     * @return array|null Bot info ['name', 'category', 'url'] or null
     */
    public function identify(string $userAgent): ?array
    {
        if (empty($userAgent)) {
            return null;
        }

        $uaLower = strtolower($userAgent);

        foreach (self::BOTS as $pattern => $info) {
            if (strpos($uaLower, $pattern) !== false) {
                return [
                    'name' => $info['name'],
                    'category' => $info['category'],
                    'url' => $info['url'],
                    'pattern' => $pattern,
                ];
            }
        }

        return null;
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

        foreach (self::BOTS as $pattern => $info) {
            if ($info['category'] === $category) {
                $bots[] = [
                    'name' => $info['name'],
                    'category' => $info['category'],
                    'url' => $info['url'],
                    'pattern' => $pattern,
                ];
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

        foreach (self::BOTS as $pattern => $info) {
            $bots[] = [
                'name' => $info['name'],
                'category' => $info['category'],
                'url' => $info['url'],
                'pattern' => $pattern,
            ];
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

        foreach (self::BOTS as $info) {
            $counts[$info['category']]++;
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

        $pattern = $bot['pattern'];

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
            if (str_ends_with($hostname, strtolower($suffix))) {
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
            'requires_verification' => isset(self::VERIFIABLE_BOTS[$bot['pattern']]),
        ]);
    }

    /**
     * Check if a specific bot pattern requires IP verification
     *
     * @param string $pattern The bot pattern
     * @return bool
     */
    public function requiresVerification(string $pattern): bool
    {
        return isset(self::VERIFIABLE_BOTS[$pattern]);
    }

    /**
     * Get the expected hostname suffixes for a bot pattern
     *
     * @param string $pattern The bot pattern
     * @return array|null List of expected suffixes, or null if verification not required
     */
    public function getExpectedHostnames(string $pattern): ?array
    {
        return self::VERIFIABLE_BOTS[$pattern] ?? null;
    }

    /**
     * Clear the verification cache
     */
    public function clearCache(): void
    {
        $this->verificationCache = [];
    }
}
