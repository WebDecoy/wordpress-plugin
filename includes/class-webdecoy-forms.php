<?php
/**
 * WebDecoy Forms Protection
 *
 * Provides protection for WordPress forms including comments,
 * login, registration, and contact forms.
 *
 * @package WebDecoy
 */

// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared
// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared
// phpcs:disable WordPress.DB.PreparedSQLPlaceholders.LikeWildcardsInQuery

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * WebDecoy Forms Class
 */
class WebDecoy_Forms
{
    /**
     * Plugin options
     *
     * @var array
     */
    private array $options;

    /**
     * Honeypot field names
     *
     * @var array
     */
    private array $honeypot_names = [];

    /**
     * Honeypot CSS class names
     *
     * @var array
     */
    private array $honeypot_classes = [];

    /**
     * Seed for daily rotation
     *
     * @var string
     */
    private string $daily_seed;

    /**
     * Legitimate-looking field name prefixes for obfuscation
     *
     * @var array
     */
    private const FIELD_PREFIXES = [
        'contact', 'user', 'form', 'field', 'input', 'data',
        'info', 'msg', 'txt', 'val', 'ref', 'src'
    ];

    /**
     * Legitimate-looking field name suffixes for obfuscation
     *
     * @var array
     */
    private const FIELD_SUFFIXES = [
        'name', 'email', 'phone', 'website', 'url', 'address',
        'city', 'zip', 'company', 'title', 'note', 'details'
    ];

    /**
     * CSS class prefixes that look like common frameworks
     *
     * @var array
     */
    private const CLASS_PREFIXES = [
        'form', 'input', 'field', 'control', 'widget', 'el',
        'ui', 'wp', 'cf', 'wpcf', 'gform', 'ninja'
    ];

    /**
     * Fake label texts for honeypot fields
     *
     * @var array
     */
    private const LABEL_TEXTS = [
        'Website URL', 'Your Website', 'Homepage', 'Company URL',
        'Fax Number', 'Secondary Email', 'Middle Name', 'Nickname',
        'How did you hear about us?', 'Referral Code', 'Alternative Phone'
    ];

    /**
     * Constructor
     *
     * @param array|null $options Plugin options
     */
    public function __construct(?array $options = null)
    {
        $this->options = $options ?? get_option('webdecoy_options', []);
        $this->daily_seed = date('Ymd') . wp_salt('auth');
        $this->generate_honeypot_names();
        $this->generate_honeypot_classes();
    }

    /**
     * Generate random honeypot field names that look legitimate
     */
    private function generate_honeypot_names(): void
    {
        $contexts = ['comment', 'login', 'register', 'contact'];

        foreach ($contexts as $context) {
            // Generate a deterministic but random-looking field name
            $hash = md5($this->daily_seed . $context);

            // Select prefix and suffix based on hash
            $prefixIndex = hexdec(substr($hash, 0, 2)) % count(self::FIELD_PREFIXES);
            $suffixIndex = hexdec(substr($hash, 2, 2)) % count(self::FIELD_SUFFIXES);

            $prefix = self::FIELD_PREFIXES[$prefixIndex];
            $suffix = self::FIELD_SUFFIXES[$suffixIndex];

            // Add a short random segment to ensure uniqueness
            $randomSegment = substr($hash, 4, 4);

            // Create names that look like legitimate form fields
            $this->honeypot_names[$context] = $prefix . '_' . $suffix . '_' . $randomSegment;
        }
    }

    /**
     * Generate random CSS class names
     */
    private function generate_honeypot_classes(): void
    {
        $contexts = ['comment', 'login', 'register', 'contact'];

        foreach ($contexts as $context) {
            $hash = md5($this->daily_seed . 'class_' . $context);

            // Generate wrapper class
            $wrapperPrefixIndex = hexdec(substr($hash, 0, 2)) % count(self::CLASS_PREFIXES);
            $wrapperPrefix = self::CLASS_PREFIXES[$wrapperPrefixIndex];
            $wrapperSuffix = substr($hash, 2, 6);

            // Generate field class
            $fieldPrefixIndex = hexdec(substr($hash, 8, 2)) % count(self::CLASS_PREFIXES);
            $fieldPrefix = self::CLASS_PREFIXES[$fieldPrefixIndex];
            $fieldSuffix = substr($hash, 10, 6);

            $this->honeypot_classes[$context] = [
                'wrapper' => $wrapperPrefix . '-group-' . $wrapperSuffix,
                'field' => $fieldPrefix . '-input-' . $fieldSuffix,
            ];
        }
    }

    /**
     * Get a random label text for honeypot
     *
     * @param string $context Form context
     * @return string
     */
    private function get_honeypot_label(string $context): string
    {
        $hash = md5($this->daily_seed . 'label_' . $context);
        $index = hexdec(substr($hash, 0, 2)) % count(self::LABEL_TEXTS);
        return self::LABEL_TEXTS[$index];
    }

    /**
     * Get randomized hiding CSS styles
     *
     * @param string $context Form context
     * @return string
     */
    private function get_hiding_styles(string $context): string
    {
        $hash = md5($this->daily_seed . 'style_' . $context);
        $variant = hexdec(substr($hash, 0, 2)) % 5;

        // Different hiding techniques that are harder to detect
        $styles = [
            // Off-screen positioning with random values
            'position:absolute;left:-' . (9000 + (hexdec(substr($hash, 2, 3)) % 1000)) . 'px;top:-' . (9000 + (hexdec(substr($hash, 5, 3)) % 1000)) . 'px;',
            // Zero dimensions with clip
            'position:absolute;width:0;height:0;padding:0;margin:0;overflow:hidden;clip:rect(0,0,0,0);border:0;',
            // Opacity and pointer-events (modern)
            'opacity:0;position:absolute;top:0;left:0;height:0;width:0;z-index:-1;pointer-events:none;',
            // Transform off-screen
            'position:absolute;transform:translateX(-' . (10000 + (hexdec(substr($hash, 8, 3)) % 500)) . 'px);',
            // Visibility hidden with off-screen
            'visibility:hidden;position:absolute;left:-100vw;top:-100vh;',
        ];

        return $styles[$variant];
    }

    /**
     * Get honeypot field name for a context
     *
     * @param string $context Form context
     * @return string Field name
     */
    public function get_honeypot_name(string $context): string
    {
        return $this->honeypot_names[$context] ?? 'webdecoy_hp_' . $context;
    }

    /**
     * Render honeypot field HTML
     *
     * @param string $context Form context
     * @return string HTML
     */
    public function render_honeypot(string $context): string
    {
        $name = $this->get_honeypot_name($context);
        $classes = $this->honeypot_classes[$context] ?? [
            'wrapper' => 'form-group-' . substr(md5($context), 0, 6),
            'field' => 'input-field-' . substr(md5($context), 6, 6),
        ];
        $label = $this->get_honeypot_label($context);
        $styles = $this->get_hiding_styles($context);

        // Generate a unique ID that looks legitimate
        $fieldId = $classes['field'] . '-' . substr(md5($this->daily_seed . $name), 0, 4);

        // Build HTML that looks like a normal form field
        $html = '<div class="' . esc_attr($classes['wrapper']) . '" style="' . esc_attr($styles) . '" aria-hidden="true">';
        $html .= '<label for="' . esc_attr($fieldId) . '">' . esc_html($label) . '</label>';
        $html .= '<input type="text" name="' . esc_attr($name) . '" id="' . esc_attr($fieldId) . '" ';
        $html .= 'class="' . esc_attr($classes['field']) . '" value="" tabindex="-1" autocomplete="off" />';
        $html .= '</div>';

        return $html;
    }

    /**
     * Output honeypot field
     *
     * @param string $context Form context
     */
    public function output_honeypot(string $context): void
    {
        // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- render_honeypot returns safe HTML
        echo $this->render_honeypot($context);
    }

    /**
     * Check if honeypot was triggered
     *
     * @param string $context Form context
     * @return bool True if honeypot triggered (bot detected)
     */
    public function check_honeypot(string $context): bool
    {
        $name = $this->get_honeypot_name($context);

        // Check POST data for current day's honeypot name
        if (isset($_POST[$name]) && !empty($_POST[$name])) {
            return true;
        }

        // Check previous day's name (in case form was loaded before midnight)
        $previousDaySeed = date('Ymd', strtotime('-1 day')) . wp_salt('auth');
        $previousName = $this->generate_name_for_seed($previousDaySeed, $context);
        if (isset($_POST[$previousName]) && !empty($_POST[$previousName])) {
            return true;
        }

        return false;
    }

    /**
     * Generate honeypot name for a specific seed
     *
     * @param string $seed Daily seed
     * @param string $context Form context
     * @return string Field name
     */
    private function generate_name_for_seed(string $seed, string $context): string
    {
        $hash = md5($seed . $context);
        $prefixIndex = hexdec(substr($hash, 0, 2)) % count(self::FIELD_PREFIXES);
        $suffixIndex = hexdec(substr($hash, 2, 2)) % count(self::FIELD_SUFFIXES);
        $prefix = self::FIELD_PREFIXES[$prefixIndex];
        $suffix = self::FIELD_SUFFIXES[$suffixIndex];
        $randomSegment = substr($hash, 4, 4);
        return $prefix . '_' . $suffix . '_' . $randomSegment;
    }

    /**
     * Validate form submission
     *
     * @param string $context Form context
     * @return array ['valid' => bool, 'reason' => string|null]
     */
    public function validate_submission(string $context): array
    {
        // Check honeypot if enabled
        if ($this->options['inject_honeypot'] && $this->check_honeypot($context)) {
            return [
                'valid' => false,
                'reason' => 'honeypot_triggered',
            ];
        }

        // Run bot detection
        $detector = new WebDecoy_Detector($this->options);
        $result = $detector->analyze();

        if ($result->shouldBlock($this->options['min_score_to_block'])) {
            return [
                'valid' => false,
                'reason' => 'bot_detected',
                'score' => $result->getScore(),
                'flags' => $result->getFlags(),
            ];
        }

        return ['valid' => true, 'reason' => null];
    }

    /**
     * Handle invalid form submission
     *
     * @param string $context Form context
     * @param array $validation Validation result
     */
    public function handle_invalid(string $context, array $validation): void
    {
        $ip = (new \WebDecoy\SignalCollector())->getIP();

        // Block the IP
        $blocker = new WebDecoy_Blocker();
        $duration = $this->options['block_duration'] > 0 ? $this->options['block_duration'] : null;
        $reason = sprintf('%s form: %s', $context, $validation['reason']);

        if ($validation['reason'] === 'honeypot_triggered') {
            // Honeypot = definite bot, longer block
            $blocker->block($ip, $reason, $duration ? $duration * 2 : $duration);
        } else {
            $blocker->block($ip, $reason, $duration);
        }

        // Log detection
        $this->log_detection($ip, $context, $validation);
    }

    /**
     * Log detection to database and forward to WebDecoy
     *
     * @param string $ip
     * @param string $context
     * @param array $validation
     */
    private function log_detection(string $ip, string $context, array $validation): void
    {
        global $wpdb;

        $table = $wpdb->prefix . 'webdecoy_detections';
        $score = $validation['score'] ?? ($validation['reason'] === 'honeypot_triggered' ? 100 : 75);
        $source = 'form_' . $context;
        $flags = $validation['flags'] ?? [$validation['reason']];

        // Log locally
        $wpdb->insert($table, [
            'ip_address' => $ip,
            'user_agent' => isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field($_SERVER['HTTP_USER_AGENT']) : '',
            'score' => $score,
            'threat_level' => 'HIGH',
            'source' => $source,
            'flags' => json_encode($flags),
            'created_at' => current_time('mysql'),
        ]);

        // Forward to WebDecoy ingest service
        $this->forward_to_webdecoy($ip, $source, $score, $flags);
    }

    /**
     * Forward detection to WebDecoy ingest service
     *
     * @param string $ip
     * @param string $source
     * @param int $score
     * @param array $flags
     */
    private function forward_to_webdecoy(string $ip, string $source, int $score, array $flags): void
    {
        // Check if API is configured
        if (empty($this->options['api_key']) || empty($this->options['organization_id'])) {
            return;
        }

        $ingest_url = rtrim($this->options['api_url'] ?? 'https://api.webdecoy.com', '/');
        $ingest_url = str_replace('api.webdecoy.com', 'ingest.webdecoy.com', $ingest_url);
        $ingest_url .= '/api/v1/detect';

        $collector = new \WebDecoy\SignalCollector();

        $payload = [
            'aid' => $this->options['organization_id'],
            'sid' => $this->options['scanner_id'] ?? ('wordpress-forms-' . get_site_url()),
            'v' => 1,
            's' => $score,
            'f' => $flags,
            'fp' => [
                'userAgent' => $collector->getUserAgent(),
                'ip' => $ip,
            ],
            'url' => $collector->getCurrentUrl(),
            'ref' => isset($_SERVER['HTTP_REFERER']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_REFERER'])) : '', // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
            'ts' => time() * 1000,
            'source' => $source,
            'blocked' => true,
        ];

        // Send to ingest (fire-and-forget)
        wp_remote_post($ingest_url, [
            'timeout' => 1,
            'blocking' => false,
            'headers' => [
                'Content-Type' => 'application/json',
                'Authorization' => 'Bearer ' . $this->options['api_key'],
            ],
            'body' => json_encode($payload),
        ]);
    }

    /**
     * Add honeypot to comment form
     */
    public function add_comment_honeypot(): void
    {
        $this->output_honeypot('comment');
    }

    /**
     * Add honeypot to login form
     */
    public function add_login_honeypot(): void
    {
        $this->output_honeypot('login');
    }

    /**
     * Add honeypot to registration form
     */
    public function add_register_honeypot(): void
    {
        $this->output_honeypot('register');
    }

    /**
     * Validate comment
     *
     * @param array $commentdata
     * @return array
     */
    public function validate_comment(array $commentdata): array
    {
        if (!$this->options['protect_comments']) {
            return $commentdata;
        }

        $validation = $this->validate_submission('comment');

        if (!$validation['valid']) {
            $this->handle_invalid('comment', $validation);

            wp_die(
                esc_html__('Your comment was blocked due to suspicious activity.', 'webdecoy'),
                esc_html__('Comment Blocked', 'webdecoy'),
                ['response' => 403, 'back_link' => true]
            );
        }

        return $commentdata;
    }

    /**
     * Validate login
     *
     * @param \WP_User|\WP_Error|null $user
     * @param string $username
     * @param string $password
     * @return \WP_User|\WP_Error|null
     */
    public function validate_login($user, string $username, string $password)
    {
        if (!$this->options['protect_login']) {
            return $user;
        }

        // Skip if already an error or empty credentials
        if (is_wp_error($user) || empty($username)) {
            return $user;
        }

        $validation = $this->validate_submission('login');

        if (!$validation['valid']) {
            $this->handle_invalid('login', $validation);

            return new \WP_Error(
                'webdecoy_blocked',
                __('Login blocked due to suspicious activity.', 'webdecoy')
            );
        }

        return $user;
    }

    /**
     * Validate registration
     *
     * @param string $sanitized_user_login
     * @param string $user_email
     * @param \WP_Error $errors
     */
    public function validate_registration(string $sanitized_user_login, string $user_email, \WP_Error $errors): void
    {
        if (!$this->options['protect_registration']) {
            return;
        }

        $validation = $this->validate_submission('register');

        if (!$validation['valid']) {
            $this->handle_invalid('register', $validation);

            $errors->add(
                'webdecoy_blocked',
                __('Registration blocked due to suspicious activity.', 'webdecoy')
            );
        }
    }

    /**
     * Get form protection stats
     *
     * @param int $days Number of days
     * @return array
     */
    public function get_stats(int $days = 7): array
    {
        global $wpdb;

        $table = $wpdb->prefix . 'webdecoy_detections';
        $since = date('Y-m-d H:i:s', strtotime("-{$days} days"));

        // phpcs:ignore WordPress.DB.PreparedSQLPlaceholders.LikeWildcardsInQuery -- Static pattern for form sources
        $by_form = $wpdb->get_results($wpdb->prepare(
            "SELECT source, COUNT(*) as count FROM {$table}
             WHERE created_at > %s AND source LIKE 'form_%'
             GROUP BY source",
            $since
        ), OBJECT_K);

        // phpcs:ignore WordPress.DB.PreparedSQLPlaceholders.LikeWildcardsInQuery -- Static pattern for form sources
        $honeypot_triggers = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$table}
             WHERE created_at > %s AND score = 100 AND source LIKE 'form_%'",
            $since
        ));

        return [
            'by_form' => $by_form,
            'honeypot_triggers' => (int) $honeypot_triggers,
            'period_days' => $days,
        ];
    }
}
