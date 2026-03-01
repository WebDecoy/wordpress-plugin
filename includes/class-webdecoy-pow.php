<?php
/**
 * WebDecoy Proof-of-Work Challenge System
 *
 * Generates and verifies SHA-256 proof-of-work challenges.
 * Used for invisible bot verification and challenge mode.
 *
 * @package WebDecoy
 */

// Prevent direct access
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class WebDecoy_PoW {

    /**
     * Default challenge expiry in seconds
     *
     * @var int
     */
    private $challenge_expiry = 300; // 5 minutes

    /**
     * Generate a PoW challenge
     *
     * Creates a signed challenge containing a random prefix and difficulty level.
     * The client must find a nonce such that SHA-256(prefix + nonce) starts with
     * the required number of leading zero hex characters.
     *
     * @param string $ip              Client IP address.
     * @param int    $base_difficulty Base difficulty (default 4, meaning 4 leading hex zeros).
     * @return array {
     *     Challenge data to send to the client.
     *
     *     @type string $challengeId Unique challenge identifier.
     *     @type string $prefix      Random hex prefix the client must hash with a nonce.
     *     @type int    $difficulty   Number of leading hex zeros required.
     *     @type int    $expiresAt   Unix timestamp when the challenge expires.
     *     @type string $sig         HMAC signature to prevent tampering.
     * }
     */
    public function generate_challenge( $ip, $base_difficulty = 4 ) {
        $difficulty   = $this->get_difficulty_for_ip( $ip, $base_difficulty );
        $challenge_id = $this->generate_id();
        $prefix       = bin2hex( random_bytes( 8 ) ); // 16 hex chars
        $expires_at   = time() + $this->challenge_expiry;

        // Sign the challenge to prevent tampering
        $sig_data = $challenge_id . '|' . $prefix . '|' . $difficulty . '|' . $expires_at;
        $sig      = $this->sign( $sig_data );

        return array(
            'challengeId' => $challenge_id,
            'prefix'      => $prefix,
            'difficulty'   => $difficulty,
            'expiresAt'   => $expires_at,
            'sig'         => $sig,
        );
    }

    /**
     * Verify a PoW solution
     *
     * Checks that:
     * 1. The challenge has not expired.
     * 2. The challenge signature is valid (not tampered with).
     * 3. The challenge has not already been solved (replay protection).
     * 4. SHA-256(prefix + nonce) matches the provided hash.
     * 5. The hash has the required number of leading zero hex characters.
     *
     * @param array  $challenge Original challenge data from generate_challenge().
     * @param int    $nonce     The nonce found by the client.
     * @param string $hash      The SHA-256 hash computed by the client.
     * @return array {
     *     Verification result.
     *
     *     @type bool   $valid  Whether the solution is valid.
     *     @type string $reason Human-readable reason.
     * }
     */
    public function verify_solution( $challenge, $nonce, $hash ) {
        // Check expiry
        $expires_at = isset( $challenge['expiresAt'] ) ? (int) $challenge['expiresAt'] : 0;
        if ( time() > $expires_at ) {
            return array( 'valid' => false, 'reason' => 'Challenge expired' );
        }

        // Verify signature (prevents forged challenges)
        $challenge_id = isset( $challenge['challengeId'] ) ? $challenge['challengeId'] : '';
        $prefix       = isset( $challenge['prefix'] ) ? $challenge['prefix'] : '';
        $difficulty    = isset( $challenge['difficulty'] ) ? (int) $challenge['difficulty'] : 0;
        $sig          = isset( $challenge['sig'] ) ? $challenge['sig'] : '';

        $sig_data = $challenge_id . '|' . $prefix . '|' . $difficulty . '|' . $expires_at;
        if ( ! $this->verify_sig( $sig_data, $sig ) ) {
            return array( 'valid' => false, 'reason' => 'Invalid challenge signature' );
        }

        // Check replay (each challenge can only be solved once)
        if ( $this->is_solution_used( $challenge_id ) ) {
            return array( 'valid' => false, 'reason' => 'Challenge already used' );
        }

        // Verify the hash: SHA-256(prefix + nonce) must have required leading zeros
        $computed = hash( 'sha256', $prefix . $nonce );
        if ( ! hash_equals( $computed, $hash ) ) {
            return array( 'valid' => false, 'reason' => 'Hash mismatch' );
        }

        if ( ! $this->has_required_zeros( $computed, $difficulty ) ) {
            return array( 'valid' => false, 'reason' => 'Insufficient difficulty' );
        }

        // Mark solution as used
        $this->mark_solution_used( $challenge_id );

        return array( 'valid' => true, 'reason' => 'OK' );
    }

    /**
     * Get difficulty scaled by IP signals
     *
     * Increases difficulty for IPs that are rate-limited, have failed PoW
     * before, or present suspicious user-agent strings.
     *
     * @param string $ip   Client IP address.
     * @param int    $base Base difficulty (default 4).
     * @return int Adjusted difficulty, capped at 7.
     */
    public function get_difficulty_for_ip( $ip, $base = 4 ) {
        $difficulty = $base;

        // Check if IP is rate limited
        $rate_key = 'webdecoy_rate_' . md5( $ip );
        if ( get_transient( $rate_key ) ) {
            $difficulty++;
        }

        // Check if IP has failed PoW before
        $fail_key = 'webdecoy_pow_fail_' . md5( $ip );
        $fails    = (int) get_transient( $fail_key );
        if ( $fails > 0 ) {
            $difficulty += min( $fails, 2 );
        }

        // Check for known bot UA patterns
        $ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? $_SERVER['HTTP_USER_AGENT'] : '';
        if ( $this->is_suspicious_ua( $ua ) ) {
            $difficulty++;
        }

        return min( $difficulty, 7 ); // Cap at 7
    }

    /**
     * Record a failed PoW attempt for an IP
     *
     * Increments the failure counter stored in a transient. Used by
     * get_difficulty_for_ip() to escalate difficulty for repeat offenders.
     *
     * @param string $ip Client IP address.
     * @return void
     */
    public function record_failure( $ip ) {
        $fail_key = 'webdecoy_pow_fail_' . md5( $ip );
        $fails    = (int) get_transient( $fail_key );
        set_transient( $fail_key, $fails + 1, 300 ); // Track for 5 min
    }

    /**
     * Generate a UUID v4
     *
     * @return string UUID string.
     */
    private function generate_id() {
        return bin2hex( random_bytes( 16 ) );
    }

    /**
     * Derive the HMAC signing key
     *
     * Uses WordPress AUTH_KEY salt if available, otherwise falls back to
     * a plugin-specific encryption key stored in options.
     *
     * @return string SHA-256 hex digest used as the HMAC key.
     */
    private function get_signing_key() {
        if ( defined( 'AUTH_KEY' ) && AUTH_KEY !== '' ) {
            return hash( 'sha256', AUTH_KEY . 'webdecoy_pow' );
        }

        $key = get_option( 'webdecoy_encryption_key', '' );
        if ( $key === '' ) {
            $key = bin2hex( random_bytes( 32 ) );
            update_option( 'webdecoy_encryption_key', $key, false );
        }
        return hash( 'sha256', $key . 'webdecoy_pow' );
    }

    /**
     * Sign data with HMAC-SHA256
     *
     * @param string $data Data to sign.
     * @return string Hex-encoded HMAC.
     */
    private function sign( $data ) {
        return hash_hmac( 'sha256', $data, $this->get_signing_key() );
    }

    /**
     * Verify an HMAC signature using timing-safe comparison
     *
     * @param string $data Data that was signed.
     * @param string $sig  Signature to verify.
     * @return bool True if the signature is valid.
     */
    private function verify_sig( $data, $sig ) {
        return hash_equals( $this->sign( $data ), $sig );
    }

    /**
     * Check whether a hash has the required number of leading zero hex characters
     *
     * Each hex character represents 4 bits, so difficulty=4 means 16 leading
     * zero bits in the hash.
     *
     * @param string $hash       SHA-256 hex digest.
     * @param int    $difficulty Number of leading '0' hex chars required.
     * @return bool True if the hash meets the difficulty requirement.
     */
    private function has_required_zeros( $hash, $difficulty ) {
        $prefix = substr( $hash, 0, $difficulty );
        return $prefix === str_repeat( '0', $difficulty );
    }

    /**
     * Mark a challenge solution as used (replay protection)
     *
     * @param string $challenge_id Challenge identifier.
     * @return void
     */
    private function mark_solution_used( $challenge_id ) {
        set_transient( 'webdecoy_pow_used_' . md5( $challenge_id ), true, $this->challenge_expiry );
    }

    /**
     * Check whether a challenge solution has already been used
     *
     * @param string $challenge_id Challenge identifier.
     * @return bool True if already used.
     */
    private function is_solution_used( $challenge_id ) {
        return (bool) get_transient( 'webdecoy_pow_used_' . md5( $challenge_id ) );
    }

    /**
     * Detect suspicious user-agent strings
     *
     * Checks for common bot/scraper/automation tool signatures.
     * An empty user-agent is also treated as suspicious.
     *
     * @param string $ua User-Agent header value.
     * @return bool True if the UA matches a suspicious pattern.
     */
    private function is_suspicious_ua( $ua ) {
        if ( empty( $ua ) ) {
            return true;
        }

        $suspicious = array(
            'curl',
            'wget',
            'python',
            'scrapy',
            'httpclient',
            'java/',
            'go-http',
            'libwww',
        );

        $ua_lower = strtolower( $ua );
        foreach ( $suspicious as $pattern ) {
            if ( strpos( $ua_lower, $pattern ) !== false ) {
                return true;
            }
        }

        return false;
    }
}
