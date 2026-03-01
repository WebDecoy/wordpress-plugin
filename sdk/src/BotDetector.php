<?php

declare(strict_types=1);

namespace WebDecoy;

/**
 * Bot Detector
 *
 * Server-side bot detection using various signals including
 * User-Agent analysis, header inspection, and behavioral patterns.
 */
class BotDetector
{
    private GoodBotList $goodBotList;
    private SignalCollector $signalCollector;
    private array $options;

    // Score weights for different signals
    private const SCORE_MISSING_HEADERS = 10;
    private const SCORE_MISSING_HEADERS_MAX = 30;
    private const SCORE_NO_COOKIES = 15;
    private const SCORE_SUSPICIOUS_UA = 25;
    private const SCORE_BOT_UA = 50;
    private const SCORE_CURL_WGET = 35;
    private const SCORE_AUTOMATION_TOOL = 40;
    private const SCORE_HEADLESS = 25;
    private const SCORE_RATE_EXCEEDED = 25;
    private const SCORE_HONEYPOT = 60;
    private const SCORE_FAKE_BOT = 80; // Claiming to be a bot but IP doesn't verify

    // Path-based scoring (MITRE ATT&CK aligned)
    private const SCORE_PATH_CONFIG_FILE = 30;      // TA0006 Credential Access - config files
    private const SCORE_PATH_BACKUP_FILE = 25;      // TA0009 Collection - backup/export files
    private const SCORE_PATH_ADMIN_PROBE = 20;      // TA0043 Reconnaissance - admin panels
    private const SCORE_PATH_DEBUG_ENDPOINT = 20;   // TA0007 Discovery - debug/info endpoints
    private const SCORE_PATH_VERSION_CONTROL = 30;  // TA0006 Credential Access - git/svn exposure

    // Suspicious path patterns mapped to MITRE tactics
    private const SUSPICIOUS_PATHS = [
        // TA0006 - Credential Access: config files that may contain secrets
        'config_files' => [
            'score' => self::SCORE_PATH_CONFIG_FILE,
            'tactic' => 'TA0006',
            'tactic_name' => 'Credential Access',
            'patterns' => [
                '/\.env$/',
                '/\.env\.[a-z]+$/',           // .env.local, .env.production, etc.
                '/wp-config\.php/',
                '/config\.json$/',
                '/config\.ya?ml$/',
                '/settings\.py$/',
                '/database\.yml$/',
                '/credentials/',
                '/secrets/',
                '/\.aws\//',
                '/\.ssh\//',
            ],
        ],
        // TA0006 - Credential Access: version control exposure
        'version_control' => [
            'score' => self::SCORE_PATH_VERSION_CONTROL,
            'tactic' => 'TA0006',
            'tactic_name' => 'Credential Access',
            'patterns' => [
                '/\.git\//',
                '/\.svn\//',
                '/\.hg\//',
                '/\.bzr\//',
            ],
        ],
        // TA0007 - Discovery: endpoints that reveal system information
        'debug_endpoints' => [
            'score' => self::SCORE_PATH_DEBUG_ENDPOINT,
            'tactic' => 'TA0007',
            'tactic_name' => 'Discovery',
            'patterns' => [
                '/\/debug/',
                '/phpinfo/',
                '/server-status/',
                '/server-info/',
                '/actuator\//',
                '/swagger/',
                '/api-docs/',
                '/graphql/',              // GraphQL introspection
                '/\.well-known\//',
                '/trace/',
                '/metrics/',
                '/health/',
            ],
        ],
        // TA0009 - Collection: backup and export files
        'backup_files' => [
            'score' => self::SCORE_PATH_BACKUP_FILE,
            'tactic' => 'TA0009',
            'tactic_name' => 'Collection',
            'patterns' => [
                '/\.sql$/',
                '/\.sql\.gz$/',
                '/\.bak$/',
                '/\.backup$/',
                '/\.old$/',
                '/\.orig$/',
                '/\.tar\.gz$/',
                '/\.tgz$/',
                '/\.zip$/',
                '/dump/',
                '/backup/',
                '/export/',
                '/database\.[a-z]+$/',
            ],
        ],
        // TA0043 - Reconnaissance: admin panel discovery
        'admin_probing' => [
            'score' => self::SCORE_PATH_ADMIN_PROBE,
            'tactic' => 'TA0043',
            'tactic_name' => 'Reconnaissance',
            'patterns' => [
                '/\/wp-admin/',
                '/\/administrator/',
                '/\/admin\//',
                '/\/phpmyadmin/',
                '/\/pma\//',
                '/\/mysql/',
                '/\/adminer/',
                '/\/cpanel/',
                '/\/webmail/',
                '/\/cgi-bin\//',
                '/\/manager\//',           // Tomcat manager
            ],
        ],
    ];

    // MITRE ATT&CK tactic IDs for reference
    public const MITRE_TACTIC_RECONNAISSANCE = 'TA0043';
    public const MITRE_TACTIC_CREDENTIAL_ACCESS = 'TA0006';
    public const MITRE_TACTIC_DISCOVERY = 'TA0007';
    public const MITRE_TACTIC_COLLECTION = 'TA0009';

    /**
     * Create a new Bot Detector
     *
     * @param array $options Detection options:
     *   - sensitivity: 'low', 'medium', 'high' (default: 'medium')
     *   - allow_search_engines: bool (default: true)
     *   - allow_social_bots: bool (default: true)
     *   - block_ai_crawlers: bool (default: false)
     *   - custom_allowlist: array of bot names (default: [])
     *   - verify_bot_ips: bool (default: true) - Verify good bots via reverse DNS
     */
    public function __construct(array $options = [])
    {
        $this->options = array_merge([
            'sensitivity' => 'medium',
            'allow_search_engines' => true,
            'allow_social_bots' => true,
            'block_ai_crawlers' => false,
            'custom_allowlist' => [],
            'verify_bot_ips' => true,
        ], $options);

        $this->goodBotList = new GoodBotList();
        $this->signalCollector = new SignalCollector();
    }

    /**
     * Analyze the current request for bot signals
     *
     * @param array|null $signals Optional pre-collected signals
     * @param string|null $clientIP Optional client IP for bot verification
     * @return DetectionResult
     */
    public function analyze(?array $signals = null, ?string $clientIP = null): DetectionResult
    {
        if ($signals === null) {
            $signals = $this->signalCollector->collect();
        }

        // Get client IP if not provided
        if ($clientIP === null) {
            $clientIP = $signals['ip_address'] ?? $this->getClientIP();
        }

        $result = new DetectionResult(0, []);

        // Check for good bots first
        $userAgent = $signals['user_agent'] ?? '';
        $botInfo = $this->identifyBot($userAgent);

        if ($botInfo !== null) {
            $result->setBotName($botInfo['name']);
            $result->setBotCategory($botInfo['category']);

            // Check if this bot should be allowed
            if ($this->shouldAllowBot($botInfo)) {
                // Verify the bot's IP if verification is enabled
                if ($this->options['verify_bot_ips'] && $this->goodBotList->requiresVerification($botInfo['pattern'])) {
                    $verification = $this->goodBotList->verifyBotIP($userAgent, $clientIP);

                    $result->addMetadata('bot_verification', $verification);

                    if ($verification['verified']) {
                        // Legitimate bot - allow with zero score
                        $result->setIsGoodBot(true);
                        $result->setScore(0);
                        $result->addFlag('verified_good_bot');
                        $result->addMetadata('bot_info', $botInfo);
                        $result->addMetadata('verified_hostname', $verification['hostname']);
                        return $result;
                    } else {
                        // Bot UA but IP doesn't verify - likely spoofed
                        $result->setIsGoodBot(false);
                        $result->addFlag('fake_bot');
                        $result->addFlag('bot_verification_failed');
                        $result->addMetadata('verification_reason', $verification['reason']);
                        $result->addMetadata('claimed_bot', $botInfo['name']);

                        // Add high score for fake bot
                        $score = self::SCORE_FAKE_BOT;
                        $result->setScore($score);
                        $result->setScoreBreakdown(['fake_bot' => self::SCORE_FAKE_BOT]);
                        $result->setConfidence(0.95); // High confidence this is malicious
                        return $result;
                    }
                } else {
                    // Bot doesn't require verification or verification is disabled
                    $result->setIsGoodBot(true);
                    $result->setScore(0);
                    $result->addFlag('good_bot');
                    $result->addMetadata('bot_info', $botInfo);
                    return $result;
                }
            }
        }

        // Calculate threat score
        $score = $this->calculateScore($signals, $result);
        $result->setScore($score);

        // Set confidence based on number of signals
        $signalCount = count(array_filter($signals));
        $result->setConfidence(min(1.0, $signalCount / 10));

        return $result;
    }

    /**
     * Get client IP address
     *
     * @return string
     */
    private function getClientIP(): string
    {
        // Priority: CF-Connecting-IP > X-Forwarded-For > X-Real-IP > REMOTE_ADDR
        $headers = [
            'HTTP_CF_CONNECTING_IP',
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_REAL_IP',
            'REMOTE_ADDR',
        ];

        foreach ($headers as $header) {
            // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- IP validated with FILTER_VALIDATE_IP below
            if (!empty($_SERVER[$header])) {
                // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
                $ip = function_exists('sanitize_text_field') ? sanitize_text_field(wp_unslash($_SERVER[$header])) : trim($_SERVER[$header]);
                // X-Forwarded-For can contain multiple IPs
                if (strpos($ip, ',') !== false) {
                    $ip = trim(explode(',', $ip)[0]);
                }
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }

        return '0.0.0.0';
    }

    /**
     * Calculate threat score from signals
     *
     * @param array $signals Collected signals
     * @param DetectionResult $result Result to populate with flags
     * @return int Score 0-100
     */
    public function calculateScore(array $signals, DetectionResult $result): int
    {
        $score = 0;
        $breakdown = [];

        // Apply sensitivity multiplier
        $multiplier = $this->getSensitivityMultiplier();

        // Missing headers
        $missingHeaders = $signals['missing_headers'] ?? [];
        if (!empty($missingHeaders)) {
            $headerScore = min(
                count($missingHeaders) * self::SCORE_MISSING_HEADERS,
                self::SCORE_MISSING_HEADERS_MAX
            );
            $score += (int) ($headerScore * $multiplier);
            $breakdown['missing_headers'] = $headerScore;
            foreach ($missingHeaders as $header) {
                $result->addFlag('missing_' . strtolower($header));
            }
        }

        // No cookies on returning visitor
        if (isset($signals['has_cookies']) && !$signals['has_cookies']) {
            if (isset($signals['is_returning']) && $signals['is_returning']) {
                $score += (int) (self::SCORE_NO_COOKIES * $multiplier);
                $breakdown['no_cookies'] = self::SCORE_NO_COOKIES;
                $result->addFlag('no_cookies');
            }
        }

        // User-Agent analysis
        $uaScore = $this->analyzeUserAgent($signals['user_agent'] ?? '', $result);
        $score += (int) ($uaScore * $multiplier);
        $breakdown['user_agent'] = $uaScore;

        // Rate limit exceeded
        if (isset($signals['rate_exceeded']) && $signals['rate_exceeded']) {
            $score += (int) (self::SCORE_RATE_EXCEEDED * $multiplier);
            $breakdown['rate_exceeded'] = self::SCORE_RATE_EXCEEDED;
            $result->addFlag('rate_exceeded');
        }

        // Honeypot triggered
        if (isset($signals['honeypot_triggered']) && $signals['honeypot_triggered']) {
            $score += self::SCORE_HONEYPOT; // No multiplier for honeypot
            $breakdown['honeypot'] = self::SCORE_HONEYPOT;
            $result->addFlag('honeypot_triggered');
        }

        // Path-based analysis (MITRE ATT&CK aligned)
        $requestPath = $signals['request_path'] ?? $signals['url'] ?? '';
        if (!empty($requestPath)) {
            $pathAnalysis = $this->analyzePath($requestPath);
            if ($pathAnalysis['score'] > 0) {
                $score += (int) ($pathAnalysis['score'] * $multiplier);
                $breakdown['suspicious_path'] = $pathAnalysis['score'];
                $result->addFlag('suspicious_path');
                $result->addFlag($pathAnalysis['category']);

                // Add MITRE ATT&CK metadata
                $result->addMetadata('mitre_tactic', $pathAnalysis['tactic']);
                $result->addMetadata('mitre_tactic_name', $pathAnalysis['tactic_name']);
                $result->addMetadata('path_category', $pathAnalysis['category']);
                $result->addMetadata('matched_pattern', $pathAnalysis['matched_pattern']);
            }
        }

        // Store breakdown
        $result->setScoreBreakdown($breakdown);

        return min(100, $score);
    }

    /**
     * Analyze User-Agent string for bot signals
     *
     * @param string $userAgent
     * @param DetectionResult $result
     * @return int Score contribution
     */
    private function analyzeUserAgent(string $userAgent, DetectionResult $result): int
    {
        if (empty($userAgent)) {
            $result->addFlag('empty_user_agent');
            return self::SCORE_SUSPICIOUS_UA;
        }

        $score = 0;
        $uaLower = strtolower($userAgent);

        // Check for curl, wget, etc.
        $cliTools = ['curl/', 'wget/', 'python-requests/', 'python-urllib/', 'libwww-perl', 'java/', 'apache-httpclient'];
        foreach ($cliTools as $tool) {
            if (strpos($uaLower, $tool) !== false) {
                $score += self::SCORE_CURL_WGET;
                $result->addFlag('cli_tool');
                break;
            }
        }

        // Check for automation tools
        $automationTools = ['selenium', 'puppeteer', 'playwright', 'phantomjs', 'headlesschrome'];
        foreach ($automationTools as $tool) {
            if (strpos($uaLower, $tool) !== false) {
                $score += self::SCORE_AUTOMATION_TOOL;
                $result->addFlag('automation_tool');
                break;
            }
        }

        // Check for headless indicators
        if (strpos($uaLower, 'headless') !== false) {
            $score += self::SCORE_HEADLESS;
            $result->addFlag('headless');
        }

        // Check for suspicious patterns
        $suspiciousPatterns = [
            '/^mozilla\/[0-9.]+$/', // Bare Mozilla
            '/^$/', // Empty
        ];
        foreach ($suspiciousPatterns as $pattern) {
            if (preg_match($pattern, $uaLower)) {
                $score += self::SCORE_SUSPICIOUS_UA;
                $result->addFlag('suspicious_user_agent');
                break;
            }
        }

        // Check for known bot patterns (not in good bot list)
        $genericBotPatterns = ['bot', 'crawler', 'spider', 'scraper'];
        $isGenericBot = false;
        foreach ($genericBotPatterns as $pattern) {
            if (strpos($uaLower, $pattern) !== false) {
                $isGenericBot = true;
                break;
            }
        }

        if ($isGenericBot) {
            $botInfo = $this->goodBotList->identify($userAgent);
            if ($botInfo === null) {
                // Unknown bot
                $score += self::SCORE_BOT_UA;
                $result->addFlag('unknown_bot');
            }
        }

        return $score;
    }

    /**
     * Analyze request path for suspicious patterns (MITRE ATT&CK aligned)
     *
     * @param string $path Request path or full URL
     * @return array Analysis result with score, tactic, category, etc.
     */
    public function analyzePath(string $path): array
    {
        $result = [
            'score' => 0,
            'tactic' => null,
            'tactic_name' => null,
            'category' => null,
            'matched_pattern' => null,
        ];

        // Extract path from URL if full URL provided
        if (strpos($path, '://') !== false) {
            $parsed = parse_url($path);
            $path = ($parsed['path'] ?? '/') . (isset($parsed['query']) ? '?' . $parsed['query'] : '');
        }

        // Normalize path for matching
        $pathLower = strtolower($path);

        // Check each category of suspicious paths
        foreach (self::SUSPICIOUS_PATHS as $category => $config) {
            foreach ($config['patterns'] as $pattern) {
                if (preg_match($pattern . 'i', $pathLower)) {
                    // Return the highest-scoring match
                    if ($config['score'] > $result['score']) {
                        $result = [
                            'score' => $config['score'],
                            'tactic' => $config['tactic'],
                            'tactic_name' => $config['tactic_name'],
                            'category' => $category,
                            'matched_pattern' => $pattern,
                        ];
                    }
                    break; // Found match in this category, move to next
                }
            }
        }

        return $result;
    }

    /**
     * Get MITRE ATT&CK tactic info for a given path
     *
     * @param string $path Request path
     * @return array|null Tactic info or null if path is not suspicious
     */
    public function getMitreTacticForPath(string $path): ?array
    {
        $analysis = $this->analyzePath($path);
        if ($analysis['score'] > 0) {
            return [
                'id' => $analysis['tactic'],
                'name' => $analysis['tactic_name'],
                'category' => $analysis['category'],
            ];
        }
        return null;
    }

    /**
     * Identify a bot from User-Agent
     *
     * @param string $userAgent
     * @return array|null Bot info or null if not a known bot
     */
    public function identifyBot(string $userAgent): ?array
    {
        return $this->goodBotList->identify($userAgent);
    }

    /**
     * Check if a bot should be allowed based on policies
     *
     * @param array $botInfo Bot information
     * @return bool
     */
    public function shouldAllowBot(array $botInfo): bool
    {
        $category = $botInfo['category'] ?? 'unknown';
        $name = $botInfo['name'] ?? '';

        // Check custom allowlist
        if (in_array($name, $this->options['custom_allowlist'], true)) {
            return true;
        }

        // Check category settings
        switch ($category) {
            case GoodBotList::CATEGORY_SEARCH_ENGINE:
                return $this->options['allow_search_engines'];

            case GoodBotList::CATEGORY_SOCIAL:
                return $this->options['allow_social_bots'];

            case GoodBotList::CATEGORY_AI_CRAWLER:
                return !$this->options['block_ai_crawlers'];

            case GoodBotList::CATEGORY_MONITORING:
            case GoodBotList::CATEGORY_SEO:
                return true; // Usually allowed

            default:
                return false;
        }
    }

    /**
     * Get sensitivity multiplier
     *
     * @return float
     */
    private function getSensitivityMultiplier(): float
    {
        switch ($this->options['sensitivity']) {
            case 'low':
                return 0.7;
            case 'high':
                return 1.3;
            case 'medium':
            default:
                return 1.0;
        }
    }

    /**
     * Quick check if request is likely a bot
     *
     * @param string|null $userAgent
     * @return bool
     */
    public function isLikelyBot(?string $userAgent = null): bool
    {
        if ($userAgent === null) {
            $userAgent = $this->signalCollector->getUserAgent();
        }

        // Check for known bots
        if ($this->goodBotList->identify($userAgent) !== null) {
            return true;
        }

        // Check for bot patterns
        $uaLower = strtolower($userAgent);
        $botIndicators = ['bot', 'crawler', 'spider', 'scraper', 'curl/', 'wget/', 'python', 'java/'];

        foreach ($botIndicators as $indicator) {
            if (strpos($uaLower, $indicator) !== false) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get the GoodBotList instance
     *
     * @return GoodBotList
     */
    public function getGoodBotList(): GoodBotList
    {
        return $this->goodBotList;
    }

    /**
     * Get the SignalCollector instance
     *
     * @return SignalCollector
     */
    public function getSignalCollector(): SignalCollector
    {
        return $this->signalCollector;
    }

    /**
     * Set detection options
     *
     * @param array $options
     * @return self
     */
    public function setOptions(array $options): self
    {
        $this->options = array_merge($this->options, $options);
        return $this;
    }

    /**
     * Get detection options
     *
     * @return array
     */
    public function getOptions(): array
    {
        return $this->options;
    }
}
