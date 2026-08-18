<?php
/**
 * Canary trip email (WebDecoy/app#679).
 *
 * The honeytoken path is a canary: nothing legitimate ever requests it, so a
 * hit is worth telling the site owner about immediately. Until now a trip
 * produced a database row and nothing anyone would notice. This emails the
 * admin, canarytokens-style: place the token, trip it yourself, and the real
 * alert arrives. Works with zero cloud connection.
 *
 * Throttled to one email per hour: the first trip in a burst is the story,
 * and a scanner walking the site must not turn the inbox into a log file.
 *
 * @package WebDecoy
 */

if (!defined('ABSPATH')) {
    exit;
}

class WebDecoy_Canary_Alert
{
    private const THROTTLE_TRANSIENT = 'webdecoy_canary_email_sent';
    private const THROTTLE_SECONDS = HOUR_IN_SECONDS;

    /**
     * Send the canary email if enabled and not throttled.
     *
     * @param string $ip   Source IP of the trip.
     * @param string $path The canary path that was hit.
     * @param string $ua   User agent of the trip.
     */
    public static function maybe_send(string $ip, string $path, string $ua): void
    {
        $options = get_option('webdecoy_options', []);
        $enabled = !isset($options['canary_email_enabled']) || !empty($options['canary_email_enabled']);
        if (!$enabled) {
            return;
        }

        if (get_transient(self::THROTTLE_TRANSIENT)) {
            return;
        }
        set_transient(self::THROTTLE_TRANSIENT, time(), self::THROTTLE_SECONDS);

        $to = get_option('admin_email');
        if (!$to || !is_email($to)) {
            return;
        }

        $site = wp_parse_url(home_url(), PHP_URL_HOST);
        $subject = sprintf(
            /* translators: %s: site hostname */
            __('[WebDecoy] Your canary tripped on %s', 'webdecoy'),
            $site
        );

        $detections_url = admin_url('admin.php?page=webdecoy-detections');
        $body = sprintf(
            /* translators: 1: canary path, 2: source IP, 3: user agent, 4: UTC time, 5: detections page URL */
            __(
                "Something requested your canary path. Nothing legitimate ever does, so this is either a bot that found your hidden link, or you testing the alert pipeline. Either way: it works.\n\n" .
                "Path: %1\$s\nSource IP: %2\$s\nUser agent: %3\$s\nTime: %4\$s (UTC)\n\n" .
                "See the detection: %5\$s\n\n" .
                "You get at most one of these emails per hour. Disable them under WebDecoy settings, Tripwires tab.",
                'webdecoy'
            ),
            $path,
            $ip,
            $ua !== '' ? $ua : __('(none)', 'webdecoy'),
            gmdate('Y-m-d H:i:s'),
            $detections_url
        );

        wp_mail($to, $subject, $body);
    }
}
