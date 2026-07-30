<?php
/**
 * WebDecoy Settings Page
 *
 * @package WebDecoy
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

$options = get_option('webdecoy_options', []);

// Which tab to show active on load. Defaults to Protection; the Cloud connect
// return redirect lands here with ?tab=cloud so the connected/connect UI is
// visible without needing the JS hash router. Read-only UI selector, no state
// change, so no nonce is required.
// phpcs:ignore WordPress.Security.NonceVerification.Recommended
$wd_active_tab = isset($_GET['tab']) ? sanitize_key(wp_unslash($_GET['tab'])) : 'detection';
if ($wd_active_tab !== 'cloud') {
    $wd_active_tab = 'detection';
}

// Cloud connection state for the Cloud tab.
$wd_cloud_connected = class_exists('WebDecoy_Cloud_Connect') && WebDecoy_Cloud_Connect::is_connected();
$wd_entitlements = class_exists('WebDecoy_Cloud_Connect') ? WebDecoy_Cloud_Connect::get_entitlements() : [];
?>

<div class="wrap webdecoy-settings-wrap">
    <h1><?php echo esc_html(get_admin_page_title()); ?></h1>

    <?php settings_errors('webdecoy_options'); ?>

    <form method="post" action="options.php">
        <?php settings_fields('webdecoy_options'); ?>

        <div class="webdecoy-tabs">
            <nav class="nav-tab-wrapper">
                <a href="#tab-detection" class="nav-tab<?php echo $wd_active_tab === 'detection' ? ' nav-tab-active' : ''; ?>"><?php esc_html_e('Protection', 'webdecoy'); ?></a>
                <a href="#tab-tripwires" class="nav-tab"><?php esc_html_e('Tripwires', 'webdecoy'); ?></a>
                <a href="#tab-rules" class="nav-tab"><?php esc_html_e('Rules', 'webdecoy'); ?></a>
                <a href="#tab-bots" class="nav-tab"><?php esc_html_e('Good Bots', 'webdecoy'); ?></a>
                <a href="#tab-blocking" class="nav-tab"><?php esc_html_e('Blocking', 'webdecoy'); ?></a>
                <a href="#tab-forms" class="nav-tab"><?php esc_html_e('Forms', 'webdecoy'); ?></a>
                <a href="#tab-scanner" class="nav-tab"><?php esc_html_e('Scanner', 'webdecoy'); ?></a>
                <?php if (class_exists('WooCommerce')) : ?>
                    <a href="#tab-woocommerce" class="nav-tab"><?php esc_html_e('WooCommerce', 'webdecoy'); ?></a>
                <?php endif; ?>
                <a href="#tab-cloud" class="nav-tab<?php echo $wd_active_tab === 'cloud' ? ' nav-tab-active' : ''; ?>"><?php esc_html_e('WebDecoy Cloud', 'webdecoy'); ?></a>
            </nav>

            <!-- Detection/Protection Settings Tab -->
            <div id="tab-detection-tab" class="webdecoy-tab-content<?php echo $wd_active_tab === 'detection' ? ' active' : ''; ?>">
                <h2><?php esc_html_e('Detection Settings', 'webdecoy'); ?></h2>

                <table class="form-table">
                    <tr>
                        <th scope="row"><?php esc_html_e('Enable Protection', 'webdecoy'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="webdecoy_options[enabled]" value="1"
                                       <?php checked(!empty($options['enabled'])); ?> />
                                <?php esc_html_e('Enable bot detection and protection', 'webdecoy'); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e('Client IP / Reverse Proxy', 'webdecoy'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="webdecoy_options[behind_cloudflare]" value="1"
                                       <?php checked(!empty($options['behind_cloudflare'])); ?> />
                                <?php esc_html_e('This site is behind Cloudflare', 'webdecoy'); ?>
                            </label>
                            <p class="description">
                                <?php esc_html_e('By default WebDecoy uses the direct connection IP and ignores forwarding headers (X-Forwarded-For, CF-Connecting-IP) because they can be spoofed. Enable this only if your site is actually served through Cloudflare, so the real visitor IP is read from CF-Connecting-IP — but only when the request genuinely comes from Cloudflare.', 'webdecoy'); ?>
                            </p>
                            <br>
                            <label for="webdecoy_trusted_proxies"><strong><?php esc_html_e('Additional trusted proxy IPs / CIDRs', 'webdecoy'); ?></strong></label><br>
                            <textarea id="webdecoy_trusted_proxies" name="webdecoy_options[trusted_proxies]"
                                      rows="3" class="large-text code"
                                      placeholder="10.0.0.0/8&#10;192.168.1.10"><?php echo esc_textarea(is_array($options['trusted_proxies'] ?? '') ? implode("\n", $options['trusted_proxies']) : ($options['trusted_proxies'] ?? '')); ?></textarea>
                            <p class="description">
                                <?php esc_html_e('One IP address or CIDR range per line (e.g. your load balancer). Forwarding headers are only trusted when the request arrives from one of these (or Cloudflare, if enabled above). Leave blank for a direct setup.', 'webdecoy'); ?>
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">
                            <label for="webdecoy_sensitivity"><?php esc_html_e('Sensitivity', 'webdecoy'); ?></label>
                        </th>
                        <td>
                            <select id="webdecoy_sensitivity" name="webdecoy_options[sensitivity]">
                                <option value="low" <?php selected($options['sensitivity'] ?? 'medium', 'low'); ?>>
                                    <?php esc_html_e('Low - Fewer false positives', 'webdecoy'); ?>
                                </option>
                                <option value="medium" <?php selected($options['sensitivity'] ?? 'medium', 'medium'); ?>>
                                    <?php esc_html_e('Medium - Balanced', 'webdecoy'); ?>
                                </option>
                                <option value="high" <?php selected($options['sensitivity'] ?? 'medium', 'high'); ?>>
                                    <?php esc_html_e('High - More aggressive', 'webdecoy'); ?>
                                </option>
                            </select>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">
                            <label for="webdecoy_min_score"><?php esc_html_e('Minimum Score to Block', 'webdecoy'); ?></label>
                        </th>
                        <td>
                            <input type="number" id="webdecoy_min_score" name="webdecoy_options[min_score_to_block]"
                                   value="<?php echo esc_attr($options['min_score_to_block'] ?? 75); ?>"
                                   min="0" max="100" step="5" class="small-text" />
                            <p class="description"><?php esc_html_e('Threat score threshold (0-100). Default: 75', 'webdecoy'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e('Rate Limiting', 'webdecoy'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="webdecoy_options[rate_limit_enabled]" value="1"
                                       <?php checked(!empty($options['rate_limit_enabled'])); ?> />
                                <?php esc_html_e('Enable rate limiting', 'webdecoy'); ?>
                            </label>
                            <br><br>
                            <label>
                                <?php esc_html_e('Allow', 'webdecoy'); ?>
                                <input type="number" name="webdecoy_options[rate_limit_requests]"
                                       value="<?php echo esc_attr($options['rate_limit_requests'] ?? 60); ?>"
                                       min="1" max="1000" class="small-text" />
                                <?php esc_html_e('requests per', 'webdecoy'); ?>
                                <input type="number" name="webdecoy_options[rate_limit_window]"
                                       value="<?php echo esc_attr($options['rate_limit_window'] ?? 60); ?>"
                                       min="1" max="3600" class="small-text" />
                                <?php esc_html_e('seconds', 'webdecoy'); ?>
                            </label>
                            <br><br>
                            <label>
                                <?php esc_html_e('Algorithm', 'webdecoy'); ?>
                                <select name="webdecoy_options[rate_limit_algorithm]">
                                    <option value="fixed" <?php selected($options['rate_limit_algorithm'] ?? 'fixed', 'fixed'); ?>><?php esc_html_e('Fixed window', 'webdecoy'); ?></option>
                                    <option value="sliding" <?php selected($options['rate_limit_algorithm'] ?? 'fixed', 'sliding'); ?>><?php esc_html_e('Sliding window', 'webdecoy'); ?></option>
                                </select>
                            </label>
                            &nbsp;
                            <label>
                                <?php esc_html_e('Count by', 'webdecoy'); ?>
                                <select name="webdecoy_options[rate_limit_key]">
                                    <option value="ip" <?php selected($options['rate_limit_key'] ?? 'ip', 'ip'); ?>><?php esc_html_e('IP address', 'webdecoy'); ?></option>
                                    <option value="ip_route" <?php selected($options['rate_limit_key'] ?? 'ip', 'ip_route'); ?>><?php esc_html_e('IP + route', 'webdecoy'); ?></option>
                                    <option value="user" <?php selected($options['rate_limit_key'] ?? 'ip', 'user'); ?>><?php esc_html_e('Logged-in user', 'webdecoy'); ?></option>
                                </select>
                            </label>
                            <br><br>
                            <label>
                                <input type="checkbox" name="webdecoy_options[rate_limit_dry_run]" value="1"
                                       <?php checked(!empty($options['rate_limit_dry_run'])); ?> />
                                <?php esc_html_e('Dry run (record without throttling)', 'webdecoy'); ?>
                            </label>
                            <p class="description">
                                <?php esc_html_e('Over-limit requests get a 429 with Retry-After and X-RateLimit-* headers. Sliding window uses a persistent object cache (Redis/Memcached) when available, otherwise falls back to the fixed-window database counter.', 'webdecoy'); ?>
                            </p>
                        </td>
                    </tr>
                </table>
            </div>

            <!-- Tripwires Tab -->
            <div id="tab-tripwires-tab" class="webdecoy-tab-content">
                <h2><?php esc_html_e('Tripwires', 'webdecoy'); ?></h2>
                <p class="description">
                    <?php esc_html_e('Tripwires are hidden honeypot paths that no real visitor ever requests — scanner-bait like /.env or /.git/config. A request for one is automated by construction, so it is blocked deterministically with zero false positives. Tripwire hits are the strongest deception signal and, with a WebDecoy Cloud key, drive durable device-fingerprint lockouts.', 'webdecoy'); ?>
                </p>

                <table class="form-table">
                    <tr>
                        <th scope="row"><?php esc_html_e('Enable Tripwires', 'webdecoy'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="webdecoy_options[tripwire_enabled]" value="1"
                                       <?php checked($options['tripwire_enabled'] ?? false); ?> />
                                <?php esc_html_e('Deterministically block requests to honeypot paths', 'webdecoy'); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e('Built-in Bait Paths', 'webdecoy'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="webdecoy_options[tripwire_include_defaults]" value="1"
                                       <?php checked($options['tripwire_include_defaults'] ?? true); ?> />
                                <?php esc_html_e('Include the built-in scanner-bait list (/.env, /.git/config, /wp-config.php, and more)', 'webdecoy'); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">
                            <label for="webdecoy_tripwire_paths"><?php esc_html_e('Custom Paths', 'webdecoy'); ?></label>
                        </th>
                        <td>
                            <textarea id="webdecoy_tripwire_paths" name="webdecoy_options[tripwire_paths]"
                                      rows="4" class="large-text code" placeholder="/secret-admin&#10;/old-backup.tar.gz"><?php echo esc_textarea(implode("\n", (array) ($options['tripwire_paths'] ?? []))); ?></textarea>
                            <p class="description"><?php esc_html_e('Exact paths, one per line. Each is matched exactly (query string and fragment are ignored).', 'webdecoy'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">
                            <label for="webdecoy_tripwire_prefixes"><?php esc_html_e('Path Prefixes', 'webdecoy'); ?></label>
                        </th>
                        <td>
                            <textarea id="webdecoy_tripwire_prefixes" name="webdecoy_options[tripwire_prefixes]"
                                      rows="3" class="large-text code" placeholder="/.git/&#10;/vendor/"><?php echo esc_textarea(implode("\n", (array) ($options['tripwire_prefixes'] ?? []))); ?></textarea>
                            <p class="description"><?php esc_html_e('Any request path starting with one of these is a hit. One prefix per line.', 'webdecoy'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">
                            <label for="webdecoy_tripwire_patterns"><?php esc_html_e('Regex Patterns', 'webdecoy'); ?></label>
                        </th>
                        <td>
                            <textarea id="webdecoy_tripwire_patterns" name="webdecoy_options[tripwire_patterns]"
                                      rows="3" class="large-text code" placeholder="\.(sql|bak|old)$"><?php echo esc_textarea(implode("\n", (array) ($options['tripwire_patterns'] ?? []))); ?></textarea>
                            <p class="description"><?php esc_html_e('Advanced: PCRE patterns without delimiters, one per line. Invalid patterns are discarded on save.', 'webdecoy'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">
                            <label for="webdecoy_tripwire_action"><?php esc_html_e('Action', 'webdecoy'); ?></label>
                        </th>
                        <td>
                            <select id="webdecoy_tripwire_action" name="webdecoy_options[tripwire_action]">
                                <option value="block" <?php selected($options['tripwire_action'] ?? 'block', 'block'); ?>>
                                    <?php esc_html_e('Block (recommended)', 'webdecoy'); ?>
                                </option>
                                <option value="throttle" <?php selected($options['tripwire_action'] ?? 'block', 'throttle'); ?>>
                                    <?php esc_html_e('Throttle (429 Too Many Requests)', 'webdecoy'); ?>
                                </option>
                            </select>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">
                            <label for="webdecoy_tripwire_response"><?php esc_html_e('Response', 'webdecoy'); ?></label>
                        </th>
                        <td>
                            <select id="webdecoy_tripwire_response" name="webdecoy_options[tripwire_response]">
                                <option value="block" <?php selected($options['tripwire_response'] ?? 'block', 'block'); ?>>
                                    <?php esc_html_e('Block — 403 Forbidden (default)', 'webdecoy'); ?>
                                </option>
                                <option value="challenge" <?php selected($options['tripwire_response'] ?? 'block', 'challenge'); ?>>
                                    <?php esc_html_e('Challenge — ask for proof of work instead of blocking', 'webdecoy'); ?>
                                </option>
                                <option value="log" <?php selected($options['tripwire_response'] ?? 'block', 'log'); ?>>
                                    <?php esc_html_e('Log only — record the hit and let the request through', 'webdecoy'); ?>
                                </option>
                                <option value="notfound" <?php selected($options['tripwire_response'] ?? 'block', 'notfound'); ?>>
                                    <?php esc_html_e('Not Found — 404 (hide that anything is protected)', 'webdecoy'); ?>
                                </option>
                                <option value="decoy" <?php selected($options['tripwire_response'] ?? 'block', 'decoy'); ?>>
                                    <?php esc_html_e('Decoy — serve believable fake content with canary credentials', 'webdecoy'); ?>
                                </option>
                                <option value="tarpit" <?php selected($options['tripwire_response'] ?? 'block', 'tarpit'); ?>>
                                    <?php esc_html_e('Tarpit — slow-drip response to waste scanner time', 'webdecoy'); ?>
                                </option>
                            </select>
                            <p class="description">
                                <?php esc_html_e('Decoy mode serves fake .env / wp-config / SQL-dump / phpinfo content seeded with unique, per-site canary credentials — a later login attempt using one is logged as a critical exfiltration detection. Decoy/Not-Found/Tarpit deliberately keep feeding the scanner (no local IP block) to gather more evidence. Tarpit ties up a PHP worker for up to 10s — use sparingly.', 'webdecoy'); ?>
                            </p>
                            <p class="description">
                                <?php esc_html_e('Challenge asks the visitor to solve a small proof-of-work in their browser. It needs JavaScript and a click, so nothing automated can complete it — on a tripwire that is the point, since these paths exist nowhere on your site and no honest crawler requests them. Log only records the hit and changes nothing about the response, which is the safest way to watch a tripwire you have just armed.', 'webdecoy'); ?>
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e('Dry Run', 'webdecoy'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="webdecoy_options[tripwire_dry_run]" value="1"
                                       <?php checked($options['tripwire_dry_run'] ?? false); ?> />
                                <?php esc_html_e('Record tripwire hits without blocking (test against live traffic first)', 'webdecoy'); ?>
                            </label>
                        </td>
                    </tr>
                </table>

                <h3><?php esc_html_e('Honeytoken', 'webdecoy'); ?></h3>
                <p class="description">
                    <?php esc_html_e('Automatically plants an invisible decoy link on your pages, pointing at a secret path only a link-following scraper would ever request. A real visitor never sees it (offscreen, hidden from screen readers, marked nofollow). A hit is armed as a tripwire — deterministic, zero false positives.', 'webdecoy'); ?>
                </p>

                <table class="form-table">
                    <tr>
                        <th scope="row"><?php esc_html_e('Enable Honeytoken', 'webdecoy'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="webdecoy_options[honeytoken_enabled]" value="1"
                                       <?php checked($options['honeytoken_enabled'] ?? true); ?> />
                                <?php esc_html_e('Inject the hidden decoy link and enforce its path', 'webdecoy'); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e('Daily Rotation', 'webdecoy'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="webdecoy_options[honeytoken_rotate]" value="1"
                                       <?php checked($options['honeytoken_rotate'] ?? false); ?> />
                                <?php esc_html_e('Rotate the decoy path daily (yesterday\'s stays armed briefly so an in-progress crawl still trips)', 'webdecoy'); ?>
                            </label>
                        </td>
                    </tr>
                </table>

                <h3><?php esc_html_e('WordPress Traps', 'webdecoy'); ?></h3>
                <p class="description">
                    <?php esc_html_e('Traps targeting the recon patterns WordPress scanners run. Each turns a probe into a deterministic detection.', 'webdecoy'); ?>
                </p>

                <table class="form-table">
                    <tr>
                        <th scope="row"><?php esc_html_e('Fake Vulnerable Plugins', 'webdecoy'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="webdecoy_options[traps_fake_plugins]" value="1"
                                       <?php checked($options['traps_fake_plugins'] ?? true); ?> />
                                <?php esc_html_e('Trap requests to known scanner-targeted plugin paths (only for plugins not actually installed here)', 'webdecoy'); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e('Author Enumeration', 'webdecoy'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="webdecoy_options[traps_author_enum]" value="1"
                                       <?php checked($options['traps_author_enum'] ?? true); ?> />
                                <?php esc_html_e('Trap ?author=N and REST user enumeration — returns a canary username instead of leaking real ones (a later login with it is flagged as exfiltration)', 'webdecoy'); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e('XML-RPC', 'webdecoy'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="webdecoy_options[traps_xmlrpc]" value="1"
                                       <?php checked($options['traps_xmlrpc'] ?? false); ?> />
                                <?php esc_html_e('Trap xmlrpc.php probing', 'webdecoy'); ?>
                            </label>
                            <p class="description"><?php esc_html_e('Off by default: legitimate clients (Jetpack, the WordPress mobile app, some pingbacks) use XML-RPC. Only enable if your site does not.', 'webdecoy'); ?></p>
                        </td>
                    </tr>
                </table>
            </div>

            <!-- Rules Tab -->
            <?php
            $filter_rules = isset($options['filter_rules']) && is_array($options['filter_rules']) ? $options['filter_rules'] : [];
            $has_api_key = !empty($options['api_key']);
            ?>
            <div id="tab-rules-tab" class="webdecoy-tab-content">
                <h2><?php esc_html_e('Filter Rules', 'webdecoy'); ?></h2>
                <p class="description">
                    <?php esc_html_e('Write expression-based rules evaluated on every request, in order, before scoring. The first matching Block/Throttle rule wins. Example expressions:', 'webdecoy'); ?>
                </p>
                <ul class="webdecoy-rule-examples" style="margin-left:1.5em;list-style:disc;">
                    <li><code>ip.tor or ip.vpn</code></li>
                    <li><code>ip.country in ["CN","RU"] and req.path matches "^/wp-login"</code></li>
                    <li><code>ip.abuse_score &gt; 50</code></li>
                    <li><code>req.header("x-requested-with") == "XMLHttpRequest"</code></li>
                </ul>
                <p class="description">
                    <?php esc_html_e('Fields: ip.vpn / ip.proxy / ip.tor / ip.relay / ip.hosting, ip.country / ip.country_name / ip.city / ip.timezone, ip.asn / ip.asn_org, ip.abuse_score / ip.total_reports / ip.is_high_risk, req.path / req.method / req.ip / req.user_agent, req.header("name"). Operators: and, or, not, ==, !=, >, >=, <, <=, in, not in, matches (regex).', 'webdecoy'); ?>
                </p>
                <?php if (!$has_api_key) : ?>
                    <p class="description webdecoy-error-text">
                        <?php esc_html_e('Note: ip.* fields require a WebDecoy Cloud API key (for IP enrichment). Without one, ip.* conditions are always false; req.* rules still work.', 'webdecoy'); ?>
                    </p>
                <?php endif; ?>

                <table class="widefat webdecoy-rules-table" style="margin-top:1em;max-width:60em;">
                    <thead>
                        <tr>
                            <th><?php esc_html_e('Name (optional)', 'webdecoy'); ?></th>
                            <th><?php esc_html_e('Expression', 'webdecoy'); ?></th>
                            <th><?php esc_html_e('Action', 'webdecoy'); ?></th>
                            <th><?php esc_html_e('Dry run', 'webdecoy'); ?></th>
                            <th></th>
                        </tr>
                    </thead>
                    <tbody id="webdecoy-rules-body">
                        <?php foreach ($filter_rules as $i => $rule) : ?>
                            <tr class="webdecoy-rule-row">
                                <td><input type="text" name="webdecoy_options[filter_rules][<?php echo (int) $i; ?>][name]"
                                           value="<?php echo esc_attr($rule['name'] ?? ''); ?>" class="regular-text" /></td>
                                <td><input type="text" name="webdecoy_options[filter_rules][<?php echo (int) $i; ?>][expression]"
                                           value="<?php echo esc_attr($rule['expression'] ?? ''); ?>" class="large-text code" />
                                    <?php if (!empty($rule['error'])) : ?>
                                        <p class="description webdecoy-error-text"><?php echo esc_html($rule['error']); ?></p>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <select name="webdecoy_options[filter_rules][<?php echo (int) $i; ?>][action]">
                                        <option value="block" <?php selected($rule['action'] ?? 'block', 'block'); ?>><?php esc_html_e('Block', 'webdecoy'); ?></option>
                                        <option value="throttle" <?php selected($rule['action'] ?? 'block', 'throttle'); ?>><?php esc_html_e('Throttle', 'webdecoy'); ?></option>
                                    </select>
                                </td>
                                <td style="text-align:center;"><input type="checkbox"
                                    name="webdecoy_options[filter_rules][<?php echo (int) $i; ?>][dry_run]" value="1"
                                    <?php checked(!empty($rule['dry_run'])); ?> /></td>
                                <td><button type="button" class="button-link webdecoy-remove-rule" aria-label="<?php esc_attr_e('Remove rule', 'webdecoy'); ?>"><?php esc_html_e('Remove', 'webdecoy'); ?></button></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>

                <p><button type="button" class="button button-secondary" id="webdecoy-add-rule"><?php esc_html_e('+ Add Rule', 'webdecoy'); ?></button></p>

                <script type="text/html" id="webdecoy-rule-template">
                    <tr class="webdecoy-rule-row">
                        <td><input type="text" name="webdecoy_options[filter_rules][__IDX__][name]" value="" class="regular-text" /></td>
                        <td><input type="text" name="webdecoy_options[filter_rules][__IDX__][expression]" value="" class="large-text code" /></td>
                        <td>
                            <select name="webdecoy_options[filter_rules][__IDX__][action]">
                                <option value="block"><?php esc_html_e('Block', 'webdecoy'); ?></option>
                                <option value="throttle"><?php esc_html_e('Throttle', 'webdecoy'); ?></option>
                            </select>
                        </td>
                        <td style="text-align:center;"><input type="checkbox" name="webdecoy_options[filter_rules][__IDX__][dry_run]" value="1" /></td>
                        <td><button type="button" class="button-link webdecoy-remove-rule"><?php esc_html_e('Remove', 'webdecoy'); ?></button></td>
                    </tr>
                </script>
            </div>

            <!-- Good Bots Tab -->
            <div id="tab-bots-tab" class="webdecoy-tab-content">
                <h2><?php esc_html_e('Good Bot Handling', 'webdecoy'); ?></h2>
                <p class="description"><?php esc_html_e('Configure how known legitimate bots are handled.', 'webdecoy'); ?></p>

                <table class="form-table">
                    <tr>
                        <th scope="row"><?php esc_html_e('Search Engines', 'webdecoy'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="webdecoy_options[allow_search_engines]" value="1"
                                       <?php checked($options['allow_search_engines'] ?? true); ?> />
                                <?php esc_html_e('Allow search engine bots (Googlebot, Bingbot, etc.)', 'webdecoy'); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e('Social Media', 'webdecoy'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="webdecoy_options[allow_social_bots]" value="1"
                                       <?php checked($options['allow_social_bots'] ?? true); ?> />
                                <?php esc_html_e('Allow social media bots (Facebook, Twitter, LinkedIn, etc.)', 'webdecoy'); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e('AI Crawlers', 'webdecoy'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="webdecoy_options[block_ai_crawlers]" value="1"
                                       <?php checked(!empty($options['block_ai_crawlers'])); ?> />
                                <?php esc_html_e('Block AI crawlers (GPTBot, ClaudeBot, PerplexityBot, etc.)', 'webdecoy'); ?>
                            </label>
                            <p class="description"><?php esc_html_e('AI crawlers are allowed by default. Enable this to block them.', 'webdecoy'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">
                            <label for="webdecoy_custom_allowlist"><?php esc_html_e('Custom Allowlist', 'webdecoy'); ?></label>
                        </th>
                        <td>
                            <textarea id="webdecoy_custom_allowlist" name="webdecoy_options[custom_allowlist]"
                                      rows="5" class="large-text code"><?php echo esc_textarea(implode("\n", $options['custom_allowlist'] ?? [])); ?></textarea>
                            <p class="description"><?php esc_html_e('One bot name per line. These bots will always be allowed.', 'webdecoy'); ?></p>
                        </td>
                    </tr>
                </table>
            </div>

            <!-- Blocking Tab -->
            <div id="tab-blocking-tab" class="webdecoy-tab-content">
                <h2><?php esc_html_e('Blocking Settings', 'webdecoy'); ?></h2>

                <table class="form-table">
                    <tr>
                        <th scope="row">
                            <label for="webdecoy_monitor_mode"><?php esc_html_e('Monitor mode', 'webdecoy'); ?></label>
                        </th>
                        <td>
                            <label>
                                <input type="checkbox" id="webdecoy_monitor_mode" name="webdecoy_options[monitor_mode]"
                                       value="1" <?php checked(!array_key_exists('monitor_mode', $options) || !empty($options['monitor_mode'])); ?> />
                                <?php esc_html_e('Watch only — detect and log everything, block nothing', 'webdecoy'); ?>
                            </label>
                            <p class="description">
                                <?php esc_html_e('On by default. Every setting below still decides what WOULD happen, and the Detections page shows it, but no visitor is ever blocked, throttled or shown a 403. Turn this off once you have looked at what enforcement would have done.', 'webdecoy'); ?>
                            </p>
                            <p class="description">
                                <?php
                                printf(
                                    /* translators: %s: the PHP constant, already formatted as code */
                                    esc_html__('Emergency off switch: add %s to wp-config.php to stop the plugin acting on the front end entirely, without database access.', 'webdecoy'),
                                    '<code>define(\'WEBDECOY_DISABLE\', true);</code>'
                                );
                                ?>
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">
                            <label for="webdecoy_ip_allowlist"><?php esc_html_e('IP Allowlist', 'webdecoy'); ?></label>
                        </th>
                        <td>
                            <textarea id="webdecoy_ip_allowlist" name="webdecoy_options[ip_allowlist]"
                                      rows="3" class="large-text code"
                                      placeholder="203.0.113.10&#10;198.51.100.0/24"><?php echo esc_textarea(is_array($options['ip_allowlist'] ?? '') ? implode("\n", $options['ip_allowlist']) : ($options['ip_allowlist'] ?? '')); ?></textarea>
                            <p class="description"><?php esc_html_e('IPs or CIDR ranges that bypass all detection and blocking (e.g. your office, an uptime monitor). One per line. Invalid entries are discarded on save.', 'webdecoy'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">
                            <label for="webdecoy_block_action"><?php esc_html_e('Block Action', 'webdecoy'); ?></label>
                        </th>
                        <td>
                            <select id="webdecoy_block_action" name="webdecoy_options[block_action]">
                                <option value="block" <?php selected($options['block_action'] ?? 'block', 'block'); ?>>
                                    <?php esc_html_e('Block immediately', 'webdecoy'); ?>
                                </option>
                                <option value="challenge" <?php selected($options['block_action'] ?? 'block', 'challenge'); ?>>
                                    <?php esc_html_e('Show challenge (CAPTCHA)', 'webdecoy'); ?>
                                </option>
                                <option value="log" <?php selected($options['block_action'] ?? 'block', 'log'); ?>>
                                    <?php esc_html_e('Log only (no blocking)', 'webdecoy'); ?>
                                </option>
                            </select>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e('Challenge Page Credit', 'webdecoy'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="webdecoy_options[challenge_show_credit]" value="1"
                                       <?php checked($options['challenge_show_credit'] ?? false); ?> />
                                <?php esc_html_e('Show a "Protected by WebDecoy" link on the challenge page', 'webdecoy'); ?>
                            </label>
                            <p class="description"><?php esc_html_e('Optional attribution shown to visitors who see the challenge page. Off by default.', 'webdecoy'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">
                            <label for="webdecoy_block_duration"><?php esc_html_e('Block Duration', 'webdecoy'); ?></label>
                        </th>
                        <td>
                            <input type="number" id="webdecoy_block_duration" name="webdecoy_options[block_duration]"
                                   value="<?php echo esc_attr($options['block_duration'] ?? 1); ?>"
                                   min="0" step="1" class="small-text" />
                            <?php esc_html_e('hours (0 = permanent)', 'webdecoy'); ?>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e('Block Page', 'webdecoy'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="webdecoy_options[show_block_page]" value="1"
                                       <?php checked($options['show_block_page'] ?? true); ?> />
                                <?php esc_html_e('Show custom block page', 'webdecoy'); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">
                            <label for="webdecoy_block_message"><?php esc_html_e('Block Message', 'webdecoy'); ?></label>
                        </th>
                        <td>
                            <textarea id="webdecoy_block_message" name="webdecoy_options[block_page_message]"
                                      rows="3" class="large-text"><?php echo esc_textarea($options['block_page_message'] ?? __('Access to this site has been restricted.', 'webdecoy')); ?></textarea>
                        </td>
                    </tr>
                </table>
            </div>

            <!-- Forms Tab -->
            <div id="tab-forms-tab" class="webdecoy-tab-content">
                <h2><?php esc_html_e('Form Protection', 'webdecoy'); ?></h2>

                <table class="form-table">
                    <tr>
                        <th scope="row"><?php esc_html_e('Comments', 'webdecoy'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="webdecoy_options[protect_comments]" value="1"
                                       <?php checked($options['protect_comments'] ?? true); ?> />
                                <?php esc_html_e('Protect comment forms from spam bots', 'webdecoy'); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e('Login', 'webdecoy'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="webdecoy_options[protect_login]" value="1"
                                       <?php checked($options['protect_login'] ?? true); ?> />
                                <?php esc_html_e('Protect login form from brute force attacks', 'webdecoy'); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e('Registration', 'webdecoy'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="webdecoy_options[protect_registration]" value="1"
                                       <?php checked($options['protect_registration'] ?? true); ?> />
                                <?php esc_html_e('Protect registration form from spam', 'webdecoy'); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e('Honeypot Fields', 'webdecoy'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="webdecoy_options[inject_honeypot]" value="1"
                                       <?php checked($options['inject_honeypot'] ?? true); ?> />
                                <?php esc_html_e('Add invisible honeypot fields to forms', 'webdecoy'); ?>
                            </label>
                            <p class="description"><?php esc_html_e('Honeypot fields catch bots that auto-fill all form fields.', 'webdecoy'); ?></p>
                        </td>
                    </tr>
                </table>
            </div>

            <!-- Scanner Tab -->
            <div id="tab-scanner-tab" class="webdecoy-tab-content">
                <h2><?php esc_html_e('Client-Side Bot Scanner', 'webdecoy'); ?></h2>
                <p class="description"><?php esc_html_e('The bot scanner runs in visitors\' browsers to detect automation tools, headless browsers, and other bot indicators.', 'webdecoy'); ?></p>

                <table class="form-table">
                    <tr>
                        <th scope="row"><?php esc_html_e('Enable Scanner', 'webdecoy'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="webdecoy_options[scanner_enabled]" value="1"
                                       <?php checked($options['scanner_enabled'] ?? true); ?> />
                                <?php esc_html_e('Enable client-side bot scanner', 'webdecoy'); ?>
                            </label>
                            <p class="description"><?php esc_html_e('Adds JavaScript bot detection to your site.', 'webdecoy'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">
                            <label for="webdecoy_scanner_min_score"><?php esc_html_e('Minimum Score to Report', 'webdecoy'); ?></label>
                        </th>
                        <td>
                            <input type="number" id="webdecoy_scanner_min_score" name="webdecoy_options[scanner_min_score]"
                                   value="<?php echo esc_attr($options['scanner_min_score'] ?? 20); ?>"
                                   min="0" max="100" step="5" class="small-text" />
                            <p class="description"><?php esc_html_e('Only report detections with scores above this threshold. Default: 20 (filters out legitimate traffic).', 'webdecoy'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e('Exclude Logged-In Users', 'webdecoy'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="webdecoy_options[scanner_exclude_logged_in]" value="1"
                                       <?php checked(!empty($options['scanner_exclude_logged_in'])); ?> />
                                <?php esc_html_e('Don\'t run scanner for logged-in users', 'webdecoy'); ?>
                            </label>
                            <p class="description"><?php esc_html_e('Skip scanning for authenticated users to improve performance.', 'webdecoy'); ?></p>
                        </td>
                    </tr>
                </table>

                <h3><?php esc_html_e('Detection Techniques', 'webdecoy'); ?></h3>
                <p class="description"><?php esc_html_e('The scanner detects bots using multiple methods:', 'webdecoy'); ?></p>
                <ul class="ul-disc">
                    <li><?php esc_html_e('WebDriver detection (Selenium, Puppeteer, Playwright)', 'webdecoy'); ?></li>
                    <li><?php esc_html_e('Headless browser detection', 'webdecoy'); ?></li>
                    <li><?php esc_html_e('Chrome object inconsistency checks (catches stealth plugins)', 'webdecoy'); ?></li>
                    <li><?php esc_html_e('Permission API inconsistencies', 'webdecoy'); ?></li>
                    <li><?php esc_html_e('iframe anomaly detection', 'webdecoy'); ?></li>
                    <li><?php esc_html_e('API timing analysis', 'webdecoy'); ?></li>
                    <li><?php esc_html_e('Browser fingerprinting', 'webdecoy'); ?></li>
                    <li><?php esc_html_e('Honeypot field monitoring', 'webdecoy'); ?></li>
                    <li><?php esc_html_e('Known AI/ML crawler detection (GPTBot, ClaudeBot, etc.)', 'webdecoy'); ?></li>
                </ul>
            </div>

            <?php if (class_exists('WooCommerce')) : ?>
            <!-- WooCommerce Tab -->
            <div id="tab-woocommerce-tab" class="webdecoy-tab-content">
                <h2><?php esc_html_e('WooCommerce Protection', 'webdecoy'); ?></h2>
                <p class="description"><?php esc_html_e('Protect your WooCommerce checkout from carding attacks and fraud.', 'webdecoy'); ?></p>

                <table class="form-table">
                    <tr>
                        <th scope="row"><?php esc_html_e('Checkout Protection', 'webdecoy'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="webdecoy_options[protect_checkout]" value="1"
                                       <?php checked($options['protect_checkout'] ?? true); ?> />
                                <?php esc_html_e('Enable checkout protection', 'webdecoy'); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e('Honeytoken Coupon', 'webdecoy'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="webdecoy_options[woo_honeytoken_coupons]" value="1"
                                       <?php checked($options['woo_honeytoken_coupons'] ?? true); ?> />
                                <?php esc_html_e('Plant a hidden decoy coupon code', 'webdecoy'); ?>
                            </label>
                            <p class="description"><?php esc_html_e('A fake promo code is placed on cart/checkout pages where coupon-scraping bots look, but hidden from human shoppers. Applying it is a deterministic bot signal — recorded and (per your blocking setting) blocked. Zero false positives: no human ever sees the code.', 'webdecoy'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e('Velocity Limit', 'webdecoy'); ?></th>
                        <td>
                            <label>
                                <?php esc_html_e('Allow', 'webdecoy'); ?>
                                <input type="number" name="webdecoy_options[checkout_velocity_limit]"
                                       value="<?php echo esc_attr($options['checkout_velocity_limit'] ?? 5); ?>"
                                       min="1" max="100" class="small-text" />
                                <?php esc_html_e('checkout attempts per', 'webdecoy'); ?>
                                <select name="webdecoy_options[checkout_velocity_window]">
                                    <option value="1800" <?php selected($options['checkout_velocity_window'] ?? 3600, 1800); ?>>
                                        <?php esc_html_e('30 minutes', 'webdecoy'); ?>
                                    </option>
                                    <option value="3600" <?php selected($options['checkout_velocity_window'] ?? 3600, 3600); ?>>
                                        <?php esc_html_e('1 hour', 'webdecoy'); ?>
                                    </option>
                                    <option value="7200" <?php selected($options['checkout_velocity_window'] ?? 3600, 7200); ?>>
                                        <?php esc_html_e('2 hours', 'webdecoy'); ?>
                                    </option>
                                    <option value="86400" <?php selected($options['checkout_velocity_window'] ?? 3600, 86400); ?>>
                                        <?php esc_html_e('24 hours', 'webdecoy'); ?>
                                    </option>
                                </select>
                            </label>
                            <p class="description"><?php esc_html_e('Block IPs that exceed this number of checkout attempts.', 'webdecoy'); ?></p>
                        </td>
                    </tr>
                </table>

                <h3><?php esc_html_e('Card Testing Detection', 'webdecoy'); ?></h3>
                <p class="description"><?php esc_html_e('Automatically detects and blocks card testing attacks based on:', 'webdecoy'); ?></p>
                <ul class="ul-disc">
                    <li><?php esc_html_e('Multiple small amount transactions (< $5)', 'webdecoy'); ?></li>
                    <li><?php esc_html_e('Multiple declined transactions', 'webdecoy'); ?></li>
                    <li><?php esc_html_e('Multiple different cards from the same IP', 'webdecoy'); ?></li>
                    <li><?php esc_html_e('Rapid succession of checkout attempts', 'webdecoy'); ?></li>
                </ul>
            </div>
            <?php endif; ?>

            <!-- WebDecoy Cloud Tab -->
            <div id="tab-cloud-tab" class="webdecoy-tab-content<?php echo $wd_active_tab === 'cloud' ? ' active' : ''; ?>">
                <h2><?php esc_html_e('WebDecoy Cloud', 'webdecoy'); ?></h2>

                <?php if ($wd_cloud_connected) : ?>
                    <?php
                    $wd_org_name = isset($options['organization_name']) ? (string) $options['organization_name'] : '';
                    $wd_plan_slug = isset($options['plan']) ? (string) $options['plan'] : '';
                    $wd_plan_label = WebDecoy_Cloud_Connect::plan_label($wd_plan_slug);
                    $wd_digest_on = !empty($wd_entitlements['digest']['enabled']);
                    ?>
                    <div class="webdecoy-connected-card">
                        <div class="webdecoy-connected-head">
                            <span class="dashicons dashicons-yes-alt"></span>
                            <div class="webdecoy-connected-title">
                                <strong><?php esc_html_e('Connected to WebDecoy Cloud', 'webdecoy'); ?></strong>
                                <?php if ($wd_org_name !== '') : ?>
                                    <div class="webdecoy-connected-org"><?php echo esc_html($wd_org_name); ?></div>
                                <?php endif; ?>
                            </div>
                            <span class="webdecoy-plan-badge"><?php echo esc_html($wd_plan_label); ?></span>
                        </div>

                        <p class="webdecoy-digest-status">
                            <span class="dashicons dashicons-email"></span>
                            <?php
                            echo $wd_digest_on
                                ? esc_html__('Monthly security report: On', 'webdecoy')
                                : esc_html__('Monthly security report: Off', 'webdecoy');
                            ?>
                        </p>

                        <p class="webdecoy-connected-actions">
                            <a href="<?php echo esc_url(WebDecoy_Cloud_Connect::wp_upgrade_url('wp_pro')); ?>" class="button button-primary" target="_blank" rel="noopener">
                                <?php esc_html_e('Upgrade', 'webdecoy'); ?>
                            </a>
                            <button type="submit" form="webdecoy-disconnect-form" class="button button-secondary">
                                <?php esc_html_e('Disconnect', 'webdecoy'); ?>
                            </button>
                        </p>
                    </div>
                <?php else : ?>
                    <p class="description"><?php esc_html_e('Connect this site to WebDecoy Cloud in one click for threat intelligence, IP reputation data, cross-site protection, and centralized monitoring. No data leaves your site until you click Connect.', 'webdecoy'); ?></p>

                    <div class="webdecoy-connect-cta">
                        <label class="webdecoy-digest-consent">
                            <input type="checkbox" name="digest" value="1" form="webdecoy-connect-form" />
                            <?php esc_html_e('Send me a monthly security report', 'webdecoy'); ?>
                        </label>
                        <button type="submit" form="webdecoy-connect-form" class="button button-primary button-hero">
                            <?php esc_html_e('Connect to WebDecoy Cloud', 'webdecoy'); ?>
                        </button>
                        <p class="description"><?php esc_html_e('Opens WebDecoy Cloud to approve the connection, then returns here automatically.', 'webdecoy'); ?></p>
                    </div>

                    <div class="webdecoy-cloud-upsell">
                        <h3><?php esc_html_e('What WebDecoy Cloud adds', 'webdecoy'); ?></h3>
                        <ul>
                            <li><?php esc_html_e('IP reputation data (AbuseIPDB integration)', 'webdecoy'); ?></li>
                            <li><?php esc_html_e('VPN, proxy, and Tor exit node detection', 'webdecoy'); ?></li>
                            <li><?php esc_html_e('Cross-site threat intelligence from all WebDecoy users', 'webdecoy'); ?></li>
                            <li><?php esc_html_e('Advanced cloud analytics with indefinite data retention', 'webdecoy'); ?></li>
                            <li><?php esc_html_e('Webhook and email alert automation', 'webdecoy'); ?></li>
                        </ul>
                        <p>
                            <a href="https://webdecoy.com/pricing" class="webdecoy-text-link" target="_blank" rel="noopener">
                                <?php esc_html_e('Explore plans and pricing', 'webdecoy'); ?>
                            </a>
                        </p>
                    </div>
                <?php endif; ?>

                <details class="webdecoy-advanced-config">
                    <summary><?php esc_html_e('Advanced: manual configuration', 'webdecoy'); ?></summary>
                    <p class="description"><?php esc_html_e('Enter API credentials by hand instead of using one-click connect. Most sites do not need this.', 'webdecoy'); ?></p>
                    <table class="form-table">
                        <tr>
                            <th scope="row">
                                <label for="webdecoy_api_key"><?php esc_html_e('API Key', 'webdecoy'); ?></label>
                            </th>
                            <td>
                                <input type="password" id="webdecoy_api_key" name="webdecoy_options[api_key]"
                                       value="<?php echo esc_attr($options['api_key'] ?? ''); ?>"
                                       class="regular-text" autocomplete="off" />
                                <button type="button" class="button button-secondary webdecoy-toggle-visibility">
                                    <?php esc_html_e('Show', 'webdecoy'); ?>
                                </button>
                                <p class="description"><?php esc_html_e('Your WebDecoy API key (starts with sk_live_)', 'webdecoy'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">
                                <label for="webdecoy_site_key"><?php esc_html_e('Site Key', 'webdecoy'); ?></label>
                            </th>
                            <td>
                                <input type="text" id="webdecoy_site_key" name="webdecoy_options[site_key]"
                                       value="<?php echo esc_attr($options['site_key'] ?? ''); ?>"
                                       class="regular-text" autocomplete="off" />
                                <p class="description">
                                    <?php esc_html_e('Your publishable site key (organization ID). Unlike the API key this is not secret — it enables the browser to silently obtain a clearance token so that tripwire and decoy hits durably lock out the offending device. Required for enforcement; safe to leave blank for detection-only.', 'webdecoy'); ?>
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('API Status', 'webdecoy'); ?></th>
                            <td>
                                <?php
                                $api_status = get_transient('webdecoy_api_status');
                                $last_check = get_option('webdecoy_api_last_check');
                                $last_error = get_option('webdecoy_api_last_error');
                                ?>
                                <?php if ($api_status === 'active') : ?>
                                    <span class="webdecoy-status webdecoy-status-active">
                                        <span class="dashicons dashicons-yes-alt"></span>
                                        <?php esc_html_e('Active', 'webdecoy'); ?>
                                    </span>
                                <?php elseif ($api_status === 'inactive') : ?>
                                    <span class="webdecoy-status webdecoy-status-inactive">
                                        <span class="dashicons dashicons-warning"></span>
                                        <?php esc_html_e('Inactive', 'webdecoy'); ?>
                                    </span>
                                    <?php if ($last_error) : ?>
                                        <p class="description webdecoy-error-text">
                                            <?php echo esc_html($last_error); ?>
                                        </p>
                                    <?php endif; ?>
                                <?php elseif ($api_status === 'error') : ?>
                                    <span class="webdecoy-status webdecoy-status-error">
                                        <span class="dashicons dashicons-info"></span>
                                        <?php esc_html_e('Connection Error', 'webdecoy'); ?>
                                    </span>
                                <?php else : ?>
                                    <span class="webdecoy-status webdecoy-status-unknown">
                                        <span class="dashicons dashicons-minus"></span>
                                        <?php esc_html_e('Not checked yet', 'webdecoy'); ?>
                                    </span>
                                <?php endif; ?>
                                <?php if ($last_check) : ?>
                                    <p class="description">
                                        <?php printf(
                                            /* translators: %s: date and time the API connection was last checked */
                                            esc_html__('Last checked: %s', 'webdecoy'),
                                            esc_html(date_i18n(get_option('date_format') . ' ' . get_option('time_format'), strtotime($last_check)))
                                        ); ?>
                                    </p>
                                <?php endif; ?>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Connection Test', 'webdecoy'); ?></th>
                            <td>
                                <button type="button" id="webdecoy-test-connection" class="button button-secondary">
                                    <?php esc_html_e('Test Connection', 'webdecoy'); ?>
                                </button>
                                <span id="webdecoy-connection-status"></span>
                                <p class="description"><?php esc_html_e('Test your API credentials and refresh the status.', 'webdecoy'); ?></p>
                            </td>
                        </tr>
                    </table>
                </details>
            </div>
        </div>

        <?php submit_button(); ?>
    </form>

    <?php
    // Standalone forms for the Cloud connect/disconnect actions. They live
    // outside the settings form to avoid invalid nested forms; the Cloud-tab
    // controls (the digest checkbox, Connect, and Disconnect buttons) are
    // associated with them via the HTML5 form="" attribute. Each posts to
    // admin-post.php and is nonce-protected in WebDecoy_Cloud_Connect.
    ?>
    <form id="webdecoy-connect-form" method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" class="webdecoy-action-form">
        <input type="hidden" name="action" value="webdecoy_cloud_connect" />
        <?php wp_nonce_field('webdecoy_cloud_connect'); ?>
    </form>
    <form id="webdecoy-disconnect-form" method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" class="webdecoy-action-form">
        <input type="hidden" name="action" value="webdecoy_cloud_disconnect" />
        <?php wp_nonce_field('webdecoy_cloud_disconnect'); ?>
    </form>
</div>
