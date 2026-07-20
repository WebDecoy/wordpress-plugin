<?php

declare(strict_types=1);

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Self-hosted update mechanism (CDN distribution ONLY).
 *
 * This lets self-hosted installs receive updates from cdn.webdecoy.com when the
 * WEBDECOY_SELF_HOSTED constant is defined. It is deliberately kept in its own
 * file and instantiated only under that constant.
 *
 * IMPORTANT: WordPress.org-distributed copies MUST NOT include this file.
 * The .org plugin guidelines prohibit a plugin serving its own updates — .org
 * is the sole update source there. `build.sh --org` removes this file, and the
 * main plugin guards the require with file_exists(), so its absence cleanly
 * disables self-hosted updating.
 */
class WebDecoy_Updater
{
    public function __construct()
    {
        add_filter('pre_set_site_transient_update_plugins', [$this, 'check_for_updates']);
        add_filter('plugins_api', [$this, 'plugin_info'], 10, 3);
        // Verify the downloaded package's checksum before WordPress installs it.
        add_filter('upgrader_pre_download', [$this, 'verify_update_package'], 10, 3);
    }

    /**
     * Check for updates against the CDN update manifest.
     *
     * @param object $transient Update transient
     * @return object Modified transient
     */
    public function check_for_updates($transient)
    {
        if (empty($transient->checked)) {
            return $transient;
        }

        $update_info = get_transient('webdecoy_update_info');

        if ($update_info === false) {
            $response = wp_remote_get('https://cdn.webdecoy.com/wordpress/update-info.json', [
                'timeout' => 10,
                'headers' => [
                    'Accept' => 'application/json',
                ],
            ]);

            if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
                return $transient;
            }

            $update_info = json_decode(wp_remote_retrieve_body($response), true);

            if (!$update_info || !isset($update_info['version'])) {
                return $transient;
            }

            set_transient('webdecoy_update_info', $update_info, 12 * HOUR_IN_SECONDS);
        }

        if (version_compare(WEBDECOY_VERSION, $update_info['version'], '<')) {
            // Host-pin the package URL: WordPress installs whatever is at
            // `package` with full privileges, so refuse any URL that is not an
            // HTTPS link on our own CDN (prevents a tampered manifest → RCE).
            $download_url = $update_info['download_url'] ?? '';
            if (!$this->is_trusted_package_url($download_url)) {
                return $transient;
            }

            $transient->response[WEBDECOY_PLUGIN_BASENAME] = (object) [
                'slug' => 'webdecoy',
                'plugin' => WEBDECOY_PLUGIN_BASENAME,
                'new_version' => $update_info['version'],
                'package' => $download_url,
                'url' => $update_info['details_url'] ?? 'https://webdecoy.com/wordpress',
                'icons' => $update_info['icons'] ?? [],
                'banners' => $update_info['banners'] ?? [],
                'tested' => $update_info['tested'] ?? '',
                'requires_php' => $update_info['requires_php'] ?? '7.4',
            ];
        }

        return $transient;
    }

    /**
     * Whether a package download URL is an HTTPS link on our own CDN host.
     */
    private function is_trusted_package_url(string $url): bool
    {
        if ($url === '') {
            return false;
        }
        $parts = wp_parse_url($url);
        if (empty($parts['scheme']) || empty($parts['host'])) {
            return false;
        }
        return strtolower($parts['scheme']) === 'https'
            && strtolower($parts['host']) === 'cdn.webdecoy.com';
    }

    /**
     * Verify the integrity of the self-hosted update package before installation.
     *
     * @param bool|WP_Error $reply    Short-circuit value (false to continue).
     * @param string        $package  The package URL being downloaded.
     * @param object        $upgrader The upgrader instance.
     * @return bool|string|\WP_Error
     */
    public function verify_update_package($reply, $package, $upgrader)
    {
        if (!is_string($package) || !$this->is_trusted_package_url($package)) {
            return $reply;
        }

        $update_info = get_transient('webdecoy_update_info');
        $expected = is_array($update_info) ? ($update_info['sha256'] ?? '') : '';
        $expected = is_string($expected) ? strtolower(trim($expected)) : '';

        if (!preg_match('/^[a-f0-9]{64}$/', $expected)) {
            return new \WP_Error(
                'webdecoy_no_checksum',
                __('WebDecoy update aborted: no valid checksum was provided for the package.', 'webdecoy')
            );
        }

        if (!function_exists('download_url')) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
        }

        $tmp_file = download_url($package);
        if (is_wp_error($tmp_file)) {
            return $tmp_file;
        }

        $actual = hash_file('sha256', $tmp_file);
        if (!hash_equals($expected, (string) $actual)) {
            wp_delete_file($tmp_file);
            return new \WP_Error(
                'webdecoy_checksum_mismatch',
                __('WebDecoy update aborted: package checksum did not match the expected value.', 'webdecoy')
            );
        }

        return $tmp_file;
    }

    /**
     * Plugin information for the update details popup.
     *
     * @param false|object|array $result
     * @param string $action
     * @param object $args
     * @return false|object
     */
    public function plugin_info($result, $action, $args)
    {
        if ($action !== 'plugin_information' || !isset($args->slug) || $args->slug !== 'webdecoy') {
            return $result;
        }

        $response = wp_remote_get('https://cdn.webdecoy.com/wordpress/plugin-info.json', [
            'timeout' => 10,
            'headers' => [
                'Accept' => 'application/json',
            ],
        ]);

        if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
            return $result;
        }

        $info = json_decode(wp_remote_retrieve_body($response), true);

        if (!$info) {
            return $result;
        }

        return (object) [
            'name' => $info['name'] ?? 'WebDecoy Bot Detection',
            'slug' => 'webdecoy',
            'version' => $info['version'] ?? WEBDECOY_VERSION,
            'author' => $info['author'] ?? '<a href="https://webdecoy.com">WebDecoy</a>',
            'author_profile' => $info['author_profile'] ?? 'https://webdecoy.com',
            'requires' => $info['requires'] ?? '5.6',
            'tested' => $info['tested'] ?? '',
            'requires_php' => $info['requires_php'] ?? '7.4',
            'sections' => $info['sections'] ?? [
                'description' => 'Protect your WordPress site from bots, spam, and carding attacks.',
                'changelog' => $info['changelog'] ?? '',
            ],
            'download_link' => $info['download_url'] ?? '',
            'banners' => $info['banners'] ?? [],
            'icons' => $info['icons'] ?? [],
        ];
    }
}
