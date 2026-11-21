<?php
/**
 * Allowlisted browser observations sent by the AJAX relay.
 *
 * @package WebDecoy
 */

if (!defined('ABSPATH')) {
    exit;
}

final class WebDecoy_Browser_Report
{
    private const FLAGS = [
        'webdriver', 'headless', 'honeypot', 'no_language', 'no_user_agent',
        'puppeteer', 'playwright', 'selenium', 'nightmare', 'phantom', 'watir',
        'chromedp', 'cypress', 'protractor', 'jsdom', 'testcafe', 'casperjs', 'zombie',
        'no_chrome_object', 'invalid_chrome_app', 'non_chrome_stack_trace',
        'invalid_performance_memory', 'missing_performance_memory', 'modified_permissions_api',
        'chrome_devtools_protocol', 'empty_languages_array', 'modified_plugins_array',
        'permission_notification_mismatch', 'notification_permission_inconsistent', 'permissions_api_failed',
        'iframe_no_chrome', 'iframe_empty_chrome', 'iframe_webdriver_mismatch', 'iframe_plugins_mismatch',
        'dom_timing_too_fast', 'canvas_timing_too_fast', 'timing_precision_suspicious',
        'lie:Function.prototype.toString', 'lie:navigator.webdriver getter',
        'lie:navigator.permissions.query', 'lie:Notification.requestPermission',
        'lie:HTMLCanvasElement.toDataURL', 'lie:WebGLRenderingContext.getParameter',
        'lie:mediaDevices.enumerateDevices',
        'behavior_no_interaction_5s', 'behavior_instant_interaction',
        'behavior_clicks_without_mouse_movement', 'behavior_robotic_mouse_movement', 'behavior_rapid_clicking',
        'behavior_robotic_scrolling', 'behavior_instant_page_load', 'behavior_suspicious_direct_navigation',
    ];

    private const AI_BOTS = [
        'GPTBot', 'ClaudeBot', 'PerplexityBot', 'CCBot', 'OAI-SearchBot', 'anthropic-ai',
        'Googlebot', 'Bingbot', 'Slurp', 'DuckDuckBot', 'Baiduspider', 'YandexBot',
        'AppleBot', 'Facebookexternalhit', 'Twitterbot', 'LinkedInBot', 'WhatsApp',
        'Slack', 'Telegram', 'Semrush', 'Ahrefs', 'MJ12bot', 'Scrapy', 'Curl', 'Wget', 'Python-Requests',
    ];

    /** Normalize the cloud report after the plugin has made its local decision. */
    public static function build(array $detection, string $user_agent): array
    {
        $flags = is_array($detection['f'] ?? null) ? array_slice($detection['f'], 0, 64) : [];
        $fingerprint = is_array($detection['fp'] ?? null) ? $detection['fp'] : [];
        $behavior = is_array($detection['behavior'] ?? null) ? $detection['behavior'] : [];
        $behavior['maxTouchPoints'] = $fingerprint['maxTouchPoints'] ?? null;
        $report = [
            'source' => 'wordpress_browser',
            'v' => 1,
            's' => max(0, min(100, is_numeric($detection['s'] ?? null) ? (int) $detection['s'] : 0)),
            'f' => array_values(array_filter(self::FLAGS, static function (string $flag) use ($flags): bool {
                return in_array($flag, $flags, true);
            })),
            'url' => self::page_url($detection['url'] ?? null),
            'ref' => self::page_url($detection['ref'] ?? null),
            'ts' => time() * 1000,
        ];
        if (in_array($detection['ai'] ?? null, self::AI_BOTS, true)) {
            $report['ai'] = $detection['ai'];
        }
        // Convert cached scanners' field value and current scanners' marker
        // to the same fixed marker without forwarding what was entered.
        if (is_string($detection['hp'] ?? null) && $detection['hp'] !== '') {
            $report['hp'] = 'filled';
        }
        $metrics = self::bounded_numbers($behavior, [
            'timeOnPage' => 86400000, 'timeToFirstInteraction' => 86400000,
            'mouseMovements' => 100000, 'straightLineRatio' => 1,
            'clicks' => 100000, 'scrollEvents' => 50, 'keyPresses' => 100000, 'maxTouchPoints' => 32,
        ]);
        if ($metrics) {
            $report['behavior'] = $metrics;
        }
        $fp = self::bounded_numbers($fingerprint, [
            'hardwareConcurrency' => 1024, 'deviceMemory' => 1024, 'maxTouchPoints' => 32,
        ]);
        foreach (['language', 'timezone', 'platform', 'vendor', 'webGL'] as $key) {
            $value = $fingerprint[$key] ?? null;
            if (is_string($value) && preg_match('~^[a-zA-Z0-9_./+() -]{0,96}$~D', $value)) {
                $fp[$key] = $value;
            }
        }
        foreach (['canvas', 'cookieEnabled', 'localStorage', 'sessionStorage', 'indexedDB', 'openDatabase'] as $key) {
            if (is_bool($fingerprint[$key] ?? null)) {
                $fp[$key] = $fingerprint[$key];
            }
        }
        $screen = $fingerprint['screenResolution'] ?? null;
        foreach (['width', 'height', 'colorDepth', 'pixelDepth'] as $key) {
            if (is_array($screen) && is_int($screen[$key] ?? null) && $screen[$key] >= 0 && $screen[$key] <= 32768) {
                $fp['screenResolution'][$key] = $screen[$key];
            }
        }
        foreach (['languages' => '~^[A-Za-z0-9-]{1,35}$~D', 'plugins' => '~^[a-zA-Z0-9_.() -]{1,64}$~D'] as $key => $pattern) {
            if (!is_array($fingerprint[$key] ?? null)) {
                continue;
            }
            $fp[$key] = array_values(array_filter(array_slice($fingerprint[$key], 0, 16), static function ($value) use ($pattern): bool {
                return is_string($value) && preg_match($pattern, $value);
            }));
        }
        if (in_array($fingerprint['doNotTrack'] ?? null, ['0', '1', 'unspecified'], true)) {
            $fp['doNotTrack'] = $fingerprint['doNotTrack'];
        }
        $webrtc_ip = $fingerprint['webrtcIP'] ?? null;
        if (is_string($webrtc_ip) && filter_var($webrtc_ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            $fp['webrtcIP'] = $webrtc_ip;
        }
        if ($user_agent !== '') {
            $fp['userAgent'] = $user_agent;
            $report['ua'] = $user_agent;
        }
        if ($fp) {
            $report['fp'] = $fp;
        }
        return $report;
    }

    /** @return array<string,int|float> */
    private static function bounded_numbers(array $data, array $limits): array
    {
        $bounded = [];
        foreach ($limits as $key => $maximum) {
            $value = $data[$key] ?? null;
            if ((is_int($value) || is_float($value)) && $value >= 0 && $value <= $maximum) {
                $bounded[$key] = $value;
            }
        }
        return $bounded;
    }

    private static function page_url($value): string
    {
        if (!is_string($value) || strlen($value) > 4096) {
            return '';
        }
        $parts = wp_parse_url($value);
        if (!is_array($parts) || !in_array(strtolower($parts['scheme'] ?? ''), ['http', 'https'], true) || empty($parts['host'])) {
            return '';
        }
        return strtolower($parts['scheme']) . '://' . $parts['host']
            . (isset($parts['port']) ? ':' . $parts['port'] : '')
            . ($parts['path'] ?? '/');
    }
}
