<?php
/**
 * WebDecoy Blocker
 *
 * Handles IP blocking functionality including adding, removing,
 * and checking blocked IPs.
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
 * WebDecoy Blocker Class
 */
class WebDecoy_Blocker
{
    /**
     * Block an IP address or CIDR range
     *
     * @param string $ip IP address or CIDR range to block (supports IPv4 and IPv6)
     * @param string $reason Reason for blocking
     * @param int|null $duration_hours Duration in hours, null for permanent
     * @return bool Success
     */
    public function block(string $ip, string $reason = '', ?int $duration_hours = null): bool
    {
        global $wpdb;

        // Support both single IPs and CIDR ranges
        if (strpos($ip, '/') !== false) {
            // Validate CIDR
            list($subnet, $bits) = explode('/', $ip);
            if (!filter_var($subnet, FILTER_VALIDATE_IP)) {
                return false;
            }
            $bits = (int) $bits;
            $version = filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ? 4 : 6;
            $maxBits = $version === 4 ? 32 : 128;
            if ($bits < 0 || $bits > $maxBits) {
                return false;
            }
        } else {
            // Validate single IP (IPv4 or IPv6)
            if (!filter_var($ip, FILTER_VALIDATE_IP)) {
                return false;
            }
        }

        $table = $wpdb->prefix . 'webdecoy_blocked_ips';

        $expires_at = null;
        if ($duration_hours !== null && $duration_hours > 0) {
            $expires_at = date('Y-m-d H:i:s', strtotime("+{$duration_hours} hours"));
        }

        // Check if already blocked
        $existing = $wpdb->get_var($wpdb->prepare(
            "SELECT id FROM {$table} WHERE ip_address = %s",
            $ip
        ));

        if ($existing) {
            // Update existing block
            $result = $wpdb->update(
                $table,
                [
                    'reason' => $reason,
                    'blocked_at' => current_time('mysql'),
                    'expires_at' => $expires_at,
                ],
                ['ip_address' => $ip]
            );
        } else {
            // Insert new block
            $result = $wpdb->insert(
                $table,
                [
                    'ip_address' => $ip,
                    'reason' => $reason,
                    'blocked_at' => current_time('mysql'),
                    'expires_at' => $expires_at,
                    'created_by' => is_user_logged_in() ? wp_get_current_user()->user_login : 'system',
                ]
            );
        }

        // Clear cache
        wp_cache_delete('webdecoy_blocked_' . $ip, 'webdecoy');

        return $result !== false;
    }

    /**
     * Unblock an IP address
     *
     * @param string $ip IP address to unblock
     * @return bool Success
     */
    public function unblock(string $ip): bool
    {
        global $wpdb;

        $table = $wpdb->prefix . 'webdecoy_blocked_ips';

        $result = $wpdb->delete($table, ['ip_address' => $ip]);

        // Clear cache
        wp_cache_delete('webdecoy_blocked_' . $ip, 'webdecoy');

        return $result !== false;
    }

    /**
     * Check if an IP is blocked (checks exact match and CIDR ranges)
     *
     * @param string $ip IP address to check (IPv4 or IPv6)
     * @return bool True if blocked
     */
    public function is_blocked(string $ip): bool
    {
        // Validate IP first
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }

        // Check cache first
        $cached = wp_cache_get('webdecoy_blocked_' . $ip, 'webdecoy');
        if ($cached !== false) {
            return $cached === 'blocked';
        }

        global $wpdb;

        $table = $wpdb->prefix . 'webdecoy_blocked_ips';

        // First check for exact IP match (fastest)
        $exact_blocked = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$table} WHERE ip_address = %s AND (expires_at IS NULL OR expires_at > %s)",
            $ip,
            current_time('mysql')
        ));

        if ((int) $exact_blocked > 0) {
            wp_cache_set('webdecoy_blocked_' . $ip, 'blocked', 'webdecoy', 60);
            return true;
        }

        // Check CIDR ranges
        // phpcs:ignore WordPress.DB.PreparedSQLPlaceholders.LikeWildcardsInQuery -- Searching for CIDR notation IPs containing /
        $cidr_blocks = $wpdb->get_col($wpdb->prepare(
            "SELECT ip_address FROM {$table} WHERE ip_address LIKE '%%/%%' AND (expires_at IS NULL OR expires_at > %s)",
            current_time('mysql')
        ));

        foreach ($cidr_blocks as $cidr) {
            if ($this->ip_in_range($ip, $cidr)) {
                wp_cache_set('webdecoy_blocked_' . $ip, 'blocked', 'webdecoy', 60);
                return true;
            }
        }

        // Not blocked
        wp_cache_set('webdecoy_blocked_' . $ip, 'allowed', 'webdecoy', 60);
        return false;
    }

    /**
     * Get all blocked IPs
     *
     * @param array $args Query arguments
     * @return array List of blocked IPs
     */
    public function get_blocked_ips(array $args = []): array
    {
        global $wpdb;

        $defaults = [
            'page' => 1,
            'per_page' => 50,
            'include_expired' => false,
            'orderby' => 'blocked_at',
            'order' => 'DESC',
        ];

        $args = wp_parse_args($args, $defaults);
        $table = $wpdb->prefix . 'webdecoy_blocked_ips';

        $where = '1=1';
        if (!$args['include_expired']) {
            $where .= $wpdb->prepare(" AND (expires_at IS NULL OR expires_at > %s)", current_time('mysql'));
        }

        $orderby = in_array($args['orderby'], ['ip_address', 'blocked_at', 'expires_at']) ? $args['orderby'] : 'blocked_at';
        $order = strtoupper($args['order']) === 'ASC' ? 'ASC' : 'DESC';

        $offset = ($args['page'] - 1) * $args['per_page'];

        $results = $wpdb->get_results($wpdb->prepare(
            "SELECT * FROM {$table} WHERE {$where} ORDER BY {$orderby} {$order} LIMIT %d OFFSET %d",
            $args['per_page'],
            $offset
        ), ARRAY_A);

        return $results ?: [];
    }

    /**
     * Get total count of blocked IPs
     *
     * @param bool $include_expired Include expired blocks
     * @return int Count
     */
    public function get_blocked_count(bool $include_expired = false): int
    {
        global $wpdb;

        $table = $wpdb->prefix . 'webdecoy_blocked_ips';

        $where = '1=1';
        if (!$include_expired) {
            $where .= $wpdb->prepare(" AND (expires_at IS NULL OR expires_at > %s)", current_time('mysql'));
        }

        return (int) $wpdb->get_var("SELECT COUNT(*) FROM {$table} WHERE {$where}");
    }

    /**
     * Get block info for an IP
     *
     * @param string $ip IP address
     * @return array|null Block info or null if not blocked
     */
    public function get_block_info(string $ip): ?array
    {
        global $wpdb;

        $table = $wpdb->prefix . 'webdecoy_blocked_ips';

        $result = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM {$table} WHERE ip_address = %s AND (expires_at IS NULL OR expires_at > %s)",
            $ip,
            current_time('mysql')
        ), ARRAY_A);

        return $result ?: null;
    }

    /**
     * Extend block duration
     *
     * @param string $ip IP address
     * @param int $hours Additional hours
     * @return bool Success
     */
    public function extend_block(string $ip, int $hours): bool
    {
        global $wpdb;

        $table = $wpdb->prefix . 'webdecoy_blocked_ips';

        $info = $this->get_block_info($ip);
        if (!$info) {
            return false;
        }

        $new_expires = null;
        if ($info['expires_at']) {
            $new_expires = date('Y-m-d H:i:s', strtotime($info['expires_at'] . " +{$hours} hours"));
        }

        $result = $wpdb->update(
            $table,
            ['expires_at' => $new_expires],
            ['ip_address' => $ip]
        );

        wp_cache_delete('webdecoy_blocked_' . $ip, 'webdecoy');

        return $result !== false;
    }

    /**
     * Clear all blocks
     *
     * @return int Number of rows deleted
     */
    public function clear_all(): int
    {
        global $wpdb;

        $table = $wpdb->prefix . 'webdecoy_blocked_ips';

        $count = $wpdb->query("DELETE FROM {$table}");

        // Clear all cache
        wp_cache_flush_group('webdecoy');

        return $count;
    }

    /**
     * Clean up expired blocks
     *
     * @return int Number of rows deleted
     */
    public function cleanup_expired(): int
    {
        global $wpdb;

        $table = $wpdb->prefix . 'webdecoy_blocked_ips';

        return $wpdb->query($wpdb->prepare(
            "DELETE FROM {$table} WHERE expires_at IS NOT NULL AND expires_at < %s",
            current_time('mysql')
        ));
    }

    /**
     * Check if IP is in allowlist
     *
     * @param string $ip IP address
     * @return bool True if allowed
     */
    public function is_allowlisted(string $ip): bool
    {
        $options = get_option('webdecoy_options', []);
        $allowlist = $options['ip_allowlist'] ?? [];

        if (in_array($ip, $allowlist, true)) {
            return true;
        }

        // Check CIDR ranges
        foreach ($allowlist as $allowed) {
            if (strpos($allowed, '/') !== false && $this->ip_in_range($ip, $allowed)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if IP is in CIDR range (supports both IPv4 and IPv6)
     *
     * @param string $ip IP address
     * @param string $range CIDR range
     * @return bool True if in range
     */
    private function ip_in_range(string $ip, string $range): bool
    {
        if (strpos($range, '/') === false) {
            return $ip === $range;
        }

        list($subnet, $bits) = explode('/', $range);
        $bits = (int) $bits;

        // Determine IP version
        $ipVersion = $this->get_ip_version($ip);
        $subnetVersion = $this->get_ip_version($subnet);

        // IP versions must match
        if ($ipVersion !== $subnetVersion) {
            return false;
        }

        if ($ipVersion === 4) {
            return $this->ipv4_in_range($ip, $subnet, $bits);
        } elseif ($ipVersion === 6) {
            return $this->ipv6_in_range($ip, $subnet, $bits);
        }

        return false;
    }

    /**
     * Check if IPv4 is in CIDR range
     *
     * @param string $ip IPv4 address
     * @param string $subnet Subnet address
     * @param int $bits CIDR bits
     * @return bool True if in range
     */
    private function ipv4_in_range(string $ip, string $subnet, int $bits): bool
    {
        if ($bits < 0 || $bits > 32) {
            return false;
        }

        $ip_long = ip2long($ip);
        $subnet_long = ip2long($subnet);

        if ($ip_long === false || $subnet_long === false) {
            return false;
        }

        if ($bits === 0) {
            return true; // 0.0.0.0/0 matches everything
        }

        $mask = -1 << (32 - $bits);
        $subnet_long &= $mask;

        return ($ip_long & $mask) === $subnet_long;
    }

    /**
     * Check if IPv6 is in CIDR range
     *
     * @param string $ip IPv6 address
     * @param string $subnet Subnet address
     * @param int $bits CIDR bits
     * @return bool True if in range
     */
    private function ipv6_in_range(string $ip, string $subnet, int $bits): bool
    {
        if ($bits < 0 || $bits > 128) {
            return false;
        }

        // Convert to binary representations
        $ip_bin = $this->ipv6_to_binary($ip);
        $subnet_bin = $this->ipv6_to_binary($subnet);

        if ($ip_bin === null || $subnet_bin === null) {
            return false;
        }

        if ($bits === 0) {
            return true; // ::/0 matches everything
        }

        // Compare the first $bits bits
        $ip_prefix = substr($ip_bin, 0, $bits);
        $subnet_prefix = substr($subnet_bin, 0, $bits);

        return $ip_prefix === $subnet_prefix;
    }

    /**
     * Convert IPv6 address to binary string representation
     *
     * @param string $ip IPv6 address
     * @return string|null Binary string (128 chars of 0s and 1s) or null on error
     */
    private function ipv6_to_binary(string $ip): ?string
    {
        // Use inet_pton for reliable parsing
        $packed = @inet_pton($ip);
        if ($packed === false) {
            return null;
        }

        // Convert to binary string
        $binary = '';
        for ($i = 0; $i < strlen($packed); $i++) {
            $binary .= str_pad(decbin(ord($packed[$i])), 8, '0', STR_PAD_LEFT);
        }

        return $binary;
    }

    /**
     * Get IP version (4 or 6)
     *
     * @param string $ip IP address
     * @return int|null 4 for IPv4, 6 for IPv6, null for invalid
     */
    private function get_ip_version(string $ip): ?int
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return 4;
        }
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return 6;
        }
        return null;
    }

    /**
     * Validate CIDR notation
     *
     * @param string $cidr CIDR string (e.g., "192.168.1.0/24" or "2001:db8::/32")
     * @return bool True if valid
     */
    public function is_valid_cidr(string $cidr): bool
    {
        if (strpos($cidr, '/') === false) {
            // Plain IP without CIDR
            return filter_var($cidr, FILTER_VALIDATE_IP) !== false;
        }

        list($ip, $bits) = explode('/', $cidr);
        $bits = (int) $bits;

        $version = $this->get_ip_version($ip);

        if ($version === 4) {
            return $bits >= 0 && $bits <= 32;
        } elseif ($version === 6) {
            return $bits >= 0 && $bits <= 128;
        }

        return false;
    }

    /**
     * Expand IPv6 address to full notation
     *
     * @param string $ip IPv6 address (may be compressed)
     * @return string|null Full IPv6 address or null on error
     */
    public function expand_ipv6(string $ip): ?string
    {
        $packed = @inet_pton($ip);
        if ($packed === false) {
            return null;
        }

        // Convert back to full notation
        $hex = unpack('H*', $packed);
        if ($hex === false) {
            return null;
        }

        $expanded = substr(preg_replace('/([a-f0-9]{4})/i', '$1:', $hex[1]), 0, -1);
        return $expanded;
    }

    /**
     * Bulk block IPs
     *
     * @param array $ips Array of IPs to block
     * @param string $reason Reason for blocking
     * @param int|null $duration_hours Duration in hours
     * @return int Number of IPs blocked
     */
    public function bulk_block(array $ips, string $reason = '', ?int $duration_hours = null): int
    {
        $blocked = 0;

        foreach ($ips as $ip) {
            if ($this->block($ip, $reason, $duration_hours)) {
                $blocked++;
            }
        }

        return $blocked;
    }

    /**
     * Bulk unblock IPs
     *
     * @param array $ips Array of IPs to unblock
     * @return int Number of IPs unblocked
     */
    public function bulk_unblock(array $ips): int
    {
        $unblocked = 0;

        foreach ($ips as $ip) {
            if ($this->unblock($ip)) {
                $unblocked++;
            }
        }

        return $unblocked;
    }

    /**
     * Get statistics
     *
     * @return array Statistics
     */
    public function get_stats(): array
    {
        global $wpdb;

        $table = $wpdb->prefix . 'webdecoy_blocked_ips';

        $total = $wpdb->get_var("SELECT COUNT(*) FROM {$table}");
        $active = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$table} WHERE expires_at IS NULL OR expires_at > %s",
            current_time('mysql')
        ));
        $expired = $total - $active;
        $permanent = $wpdb->get_var("SELECT COUNT(*) FROM {$table} WHERE expires_at IS NULL");

        // Blocks in last 24 hours
        $recent = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$table} WHERE blocked_at > %s",
            date('Y-m-d H:i:s', strtotime('-24 hours'))
        ));

        return [
            'total' => (int) $total,
            'active' => (int) $active,
            'expired' => (int) $expired,
            'permanent' => (int) $permanent,
            'last_24h' => (int) $recent,
        ];
    }
}
