<?php
/**
 * WebDecoy Detections Page
 *
 * @package WebDecoy
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Capability check
if (!current_user_can('manage_options')) {
    wp_die(esc_html__('You do not have sufficient permissions to access this page.', 'webdecoy'));
}

global $wpdb;

$table = $wpdb->prefix . 'webdecoy_detections';
$page = isset($_GET['paged']) ? max(1, intval($_GET['paged'])) : 1;
$per_page = 50;
$offset = ($page - 1) * $per_page;

// Filters
$threat_level = isset($_GET['threat_level']) ? sanitize_text_field($_GET['threat_level']) : '';
$source = isset($_GET['source']) ? sanitize_text_field($_GET['source']) : '';

// Date range handling
$date_from = isset($_GET['date_from']) ? sanitize_text_field($_GET['date_from']) : '';
$date_to = isset($_GET['date_to']) ? sanitize_text_field($_GET['date_to']) : '';
$range = isset($_GET['range']) ? sanitize_text_field($_GET['range']) : '';

if ($range === 'today') {
    $date_from = date('Y-m-d');
    $date_to = date('Y-m-d');
} elseif ($range === '7d') {
    $date_from = date('Y-m-d', strtotime('-7 days'));
    $date_to = date('Y-m-d');
} elseif ($range === '30d') {
    $date_from = date('Y-m-d', strtotime('-30 days'));
    $date_to = date('Y-m-d');
}

// Build query with always using prepare() for safety
$where_clauses = ['1=%d']; // Always have at least one placeholder
$params = [1]; // Value for the 1=%d placeholder

if ($threat_level) {
    $where_clauses[] = 'threat_level = %s';
    $params[] = $threat_level;
}

if ($source) {
    $where_clauses[] = 'source = %s';
    $params[] = $source;
}

if ($date_from) {
    $where_clauses[] = 'created_at >= %s';
    $params[] = $date_from . ' 00:00:00';
}
if ($date_to) {
    $where_clauses[] = 'created_at <= %s';
    $params[] = $date_to . ' 23:59:59';
}

$where = implode(' AND ', $where_clauses);

// Handle CSV export
if (isset($_GET['action']) && $_GET['action'] === 'export_csv' && wp_verify_nonce($_GET['_wpnonce'] ?? '', 'webdecoy_export')) {
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="webdecoy-detections-' . date('Y-m-d') . '.csv"');

    $output = fopen('php://output', 'w');
    fputcsv($output, ['Date', 'IP Address', 'Score', 'Threat Level', 'Source', 'User Agent', 'Flags']);

    $export_query = "SELECT * FROM {$table} WHERE {$where} ORDER BY created_at DESC";
    // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- Query built dynamically with safe table/column names
    $export_results = $wpdb->get_results($wpdb->prepare($export_query, $params), ARRAY_A);

    foreach ($export_results as $row) {
        fputcsv($output, [
            $row['created_at'],
            $row['ip_address'],
            $row['score'],
            $row['threat_level'],
            $row['source'],
            $row['user_agent'],
            $row['flags'],
        ]);
    }

    fclose($output);
    exit;
}

// Get total - always use prepare()
$total_query = "SELECT COUNT(*) FROM {$table} WHERE {$where}";
// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- Query built dynamically with safe table/column names
$total = $wpdb->get_var($wpdb->prepare($total_query, $params));
$total_pages = ceil($total / $per_page);

// Get detections - always use prepare()
$query = "SELECT * FROM {$table} WHERE {$where} ORDER BY created_at DESC LIMIT %d OFFSET %d";
$query_params = array_merge($params, [$per_page, $offset]);
// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- Query built dynamically with safe table/column names
$detections = $wpdb->get_results($wpdb->prepare($query, $query_params), ARRAY_A);

// Get stats
$detector = new WebDecoy_Detector();
$stats = $detector->get_stats(7);

// Instantiate blocker once for the loop (performance optimization)
$blocker = new WebDecoy_Blocker();
?>

<div class="wrap">
    <h1><?php esc_html_e('Bot Detections', 'webdecoy'); ?></h1>

    <div class="webdecoy-detection-stats">
        <div class="webdecoy-stat-box">
            <span class="value"><?php echo esc_html(number_format($stats['total'])); ?></span>
            <span class="label"><?php esc_html_e('Total (7 days)', 'webdecoy'); ?></span>
        </div>
        <div class="webdecoy-stat-box webdecoy-stat-danger">
            <span class="value"><?php echo esc_html(number_format($stats['high_risk'])); ?></span>
            <span class="label"><?php esc_html_e('High/Critical', 'webdecoy'); ?></span>
        </div>
        <div class="webdecoy-stat-box">
            <span class="value"><?php echo esc_html(number_format($detector->get_unique_ips(7))); ?></span>
            <span class="label"><?php esc_html_e('Unique IPs', 'webdecoy'); ?></span>
        </div>
    </div>

    <div class="tablenav top">
        <div class="webdecoy-actions-bar">
            <form method="get" class="webdecoy-filters">
                <input type="hidden" name="page" value="webdecoy-detections" />

                <!-- Date Range Quick Buttons -->
                <div class="webdecoy-date-buttons">
                    <?php
                    $active_range = '';
                    if (!empty($_GET['date_from']) || !empty($_GET['date_to'])) {
                        $active_range = 'custom';
                    } elseif (isset($_GET['range'])) {
                        $active_range = sanitize_text_field($_GET['range']);
                    }
                    ?>
                    <a href="<?php echo esc_url(add_query_arg(['page' => 'webdecoy-detections', 'range' => 'today'], admin_url('admin.php'))); ?>"
                       class="button <?php echo $active_range === 'today' ? 'button-primary' : ''; ?>">
                        <?php esc_html_e('Today', 'webdecoy'); ?>
                    </a>
                    <a href="<?php echo esc_url(add_query_arg(['page' => 'webdecoy-detections', 'range' => '7d'], admin_url('admin.php'))); ?>"
                       class="button <?php echo $active_range === '7d' ? 'button-primary' : ''; ?>">
                        <?php esc_html_e('7 Days', 'webdecoy'); ?>
                    </a>
                    <a href="<?php echo esc_url(add_query_arg(['page' => 'webdecoy-detections', 'range' => '30d'], admin_url('admin.php'))); ?>"
                       class="button <?php echo $active_range === '30d' ? 'button-primary' : ''; ?>">
                        <?php esc_html_e('30 Days', 'webdecoy'); ?>
                    </a>
                    <a href="<?php echo esc_url(admin_url('admin.php?page=webdecoy-detections')); ?>"
                       class="button <?php echo empty($active_range) ? 'button-primary' : ''; ?>">
                        <?php esc_html_e('All Time', 'webdecoy'); ?>
                    </a>
                </div>

                <!-- Custom Date Range -->
                <label>
                    <input type="date" name="date_from" value="<?php echo esc_attr($date_from); ?>" placeholder="From" />
                </label>
                <label>
                    <input type="date" name="date_to" value="<?php echo esc_attr($date_to); ?>" placeholder="To" />
                </label>

                <select name="threat_level">
                    <option value=""><?php esc_html_e('All Threat Levels', 'webdecoy'); ?></option>
                    <option value="MINIMAL" <?php selected($threat_level, 'MINIMAL'); ?>><?php esc_html_e('Minimal', 'webdecoy'); ?></option>
                    <option value="LOW" <?php selected($threat_level, 'LOW'); ?>><?php esc_html_e('Low', 'webdecoy'); ?></option>
                    <option value="MEDIUM" <?php selected($threat_level, 'MEDIUM'); ?>><?php esc_html_e('Medium', 'webdecoy'); ?></option>
                    <option value="HIGH" <?php selected($threat_level, 'HIGH'); ?>><?php esc_html_e('High', 'webdecoy'); ?></option>
                    <option value="CRITICAL" <?php selected($threat_level, 'CRITICAL'); ?>><?php esc_html_e('Critical', 'webdecoy'); ?></option>
                </select>

                <select name="source">
                    <option value=""><?php esc_html_e('All Sources', 'webdecoy'); ?></option>
                    <option value="wordpress_plugin" <?php selected($source, 'wordpress_plugin'); ?>><?php esc_html_e('Server Detection', 'webdecoy'); ?></option>
                    <option value="bot_scanner" <?php selected($source, 'bot_scanner'); ?>><?php esc_html_e('Bot Scanner', 'webdecoy'); ?></option>
                    <option value="form_comment" <?php selected($source, 'form_comment'); ?>><?php esc_html_e('Comment Form', 'webdecoy'); ?></option>
                    <option value="form_login" <?php selected($source, 'form_login'); ?>><?php esc_html_e('Login Form', 'webdecoy'); ?></option>
                </select>

                <button type="submit" class="button"><?php esc_html_e('Filter', 'webdecoy'); ?></button>
            </form>

            <div class="webdecoy-export-actions">
                <button type="button" id="webdecoy-bulk-block" class="button" style="display:none;">
                    <?php esc_html_e('Block Selected', 'webdecoy'); ?> (<span id="webdecoy-selected-count">0</span>)
                </button>
                <?php
                $export_args = array_filter([
                    'page'         => 'webdecoy-detections',
                    'action'       => 'export_csv',
                    'threat_level' => $threat_level,
                    'source'       => $source,
                    'date_from'    => $date_from,
                    'date_to'      => $date_to,
                    'range'        => $range,
                ]);
                ?>
                <a href="<?php echo esc_url(wp_nonce_url(add_query_arg($export_args, admin_url('admin.php')), 'webdecoy_export')); ?>" class="button">
                    <?php esc_html_e('Export CSV', 'webdecoy'); ?>
                </a>
            </div>
        </div>
    </div>

    <?php if (empty($detections)) : ?>
        <p><?php esc_html_e('No detections found.', 'webdecoy'); ?></p>
    <?php else : ?>
        <table class="wp-list-table widefat fixed striped">
            <thead>
                <tr>
                    <th class="check-column"><input type="checkbox" id="webdecoy-select-all" /></th>
                    <th class="column-date"><?php esc_html_e('Date', 'webdecoy'); ?></th>
                    <th class="column-ip"><?php esc_html_e('IP Address', 'webdecoy'); ?></th>
                    <th class="column-score"><?php esc_html_e('Score', 'webdecoy'); ?></th>
                    <th class="column-level"><?php esc_html_e('Level', 'webdecoy'); ?></th>
                    <th class="column-mitre"><?php esc_html_e('MITRE Tactic', 'webdecoy'); ?></th>
                    <th class="column-source"><?php esc_html_e('Source', 'webdecoy'); ?></th>
                    <th class="column-ua"><?php esc_html_e('User Agent', 'webdecoy'); ?></th>
                    <th class="column-actions"><?php esc_html_e('Actions', 'webdecoy'); ?></th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($detections as $detection) : ?>
                <tr class="webdecoy-expandable-row">
                    <td class="check-column">
                        <input type="checkbox" class="webdecoy-select-ip" value="<?php echo esc_attr($detection['ip_address']); ?>" />
                    </td>
                    <td>
                        <?php echo esc_html(date_i18n(get_option('date_format') . ' ' . get_option('time_format'), strtotime($detection['created_at']))); ?>
                    </td>
                    <td>
                        <code><?php echo esc_html($detection['ip_address']); ?></code>
                    </td>
                    <td>
                        <strong><?php echo esc_html($detection['score']); ?></strong>
                    </td>
                    <td>
                        <span class="webdecoy-level webdecoy-level-<?php echo esc_attr(strtolower($detection['threat_level'])); ?>">
                            <?php echo esc_html($detection['threat_level']); ?>
                        </span>
                    </td>
                    <td>
                        <?php
                        // Parse MITRE tactic from flags JSON
                        $mitre_tactic = '';
                        $mitre_name = '';
                        if (!empty($detection['flags'])) {
                            $flags_data = json_decode($detection['flags'], true);
                            if (is_array($flags_data)) {
                                // Check for structured metadata format
                                if (isset($flags_data['metadata']['mitre_tactic'])) {
                                    $mitre_tactic = $flags_data['metadata']['mitre_tactic'];
                                    $mitre_name = $flags_data['metadata']['mitre_tactic_name'] ?? '';
                                }
                                // Check for simple flags array (client-side detections)
                                elseif (isset($flags_data['f']) && is_array($flags_data['f'])) {
                                    // Look for tactic flags like 'admin_probing', 'config_files', etc.
                                    foreach ($flags_data['f'] as $flag) {
                                        if (in_array($flag, ['admin_probing', 'config_files', 'version_control', 'debug_endpoints', 'backup_files'])) {
                                            $tactic_map = [
                                                'admin_probing' => ['TA0043', 'Reconnaissance'],
                                                'config_files' => ['TA0006', 'Credential Access'],
                                                'version_control' => ['TA0006', 'Credential Access'],
                                                'debug_endpoints' => ['TA0007', 'Discovery'],
                                                'backup_files' => ['TA0009', 'Collection'],
                                            ];
                                            if (isset($tactic_map[$flag])) {
                                                $mitre_tactic = $tactic_map[$flag][0];
                                                $mitre_name = $tactic_map[$flag][1];
                                                break;
                                            }
                                        }
                                    }
                                }
                                // Check for flags array at root level
                                elseif (isset($flags_data['flags']) && is_array($flags_data['flags'])) {
                                    foreach ($flags_data['flags'] as $flag) {
                                        if (in_array($flag, ['admin_probing', 'config_files', 'version_control', 'debug_endpoints', 'backup_files'])) {
                                            $tactic_map = [
                                                'admin_probing' => ['TA0043', 'Reconnaissance'],
                                                'config_files' => ['TA0006', 'Credential Access'],
                                                'version_control' => ['TA0006', 'Credential Access'],
                                                'debug_endpoints' => ['TA0007', 'Discovery'],
                                                'backup_files' => ['TA0009', 'Collection'],
                                            ];
                                            if (isset($tactic_map[$flag])) {
                                                $mitre_tactic = $tactic_map[$flag][0];
                                                $mitre_name = $tactic_map[$flag][1];
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        if ($mitre_tactic) :
                        ?>
                            <span class="webdecoy-mitre webdecoy-mitre-<?php echo esc_attr(strtolower(str_replace(' ', '-', $mitre_name))); ?>" title="<?php echo esc_attr($mitre_name); ?>">
                                <?php echo esc_html($mitre_tactic); ?>
                            </span>
                            <small class="webdecoy-mitre-name"><?php echo esc_html($mitre_name); ?></small>
                        <?php else : ?>
                            <span class="webdecoy-mitre-na">—</span>
                        <?php endif; ?>
                    </td>
                    <td>
                        <?php echo esc_html(str_replace('_', ' ', ucfirst($detection['source']))); ?>
                    </td>
                    <td class="column-ua">
                        <span title="<?php echo esc_attr($detection['user_agent']); ?>">
                            <?php echo esc_html(wp_trim_words($detection['user_agent'], 10, '...')); ?>
                        </span>
                    </td>
                    <td>
                        <?php
                        // Use pre-instantiated $blocker from above (performance optimization)
                        if (!$blocker->is_blocked($detection['ip_address'])) :
                        ?>
                            <a href="<?php echo esc_url(wp_nonce_url(add_query_arg([
                                'page' => 'webdecoy-blocked',
                                'action' => 'block',
                                'ip' => $detection['ip_address'],
                            ], admin_url('admin.php')), 'webdecoy_quick_block')); ?>"
                               class="button button-small">
                                <?php esc_html_e('Block', 'webdecoy'); ?>
                            </a>
                        <?php else : ?>
                            <span class="webdecoy-badge webdecoy-badge-blocked">
                                <?php esc_html_e('Blocked', 'webdecoy'); ?>
                            </span>
                        <?php endif; ?>
                    </td>
                </tr>
                <tr class="webdecoy-detail-row" style="display:none;">
                    <td colspan="9">
                        <div class="webdecoy-detection-detail">
                            <strong><?php esc_html_e('User Agent:', 'webdecoy'); ?></strong>
                            <code><?php echo esc_html($detection['user_agent']); ?></code>
                            <br>
                            <strong><?php esc_html_e('Flags:', 'webdecoy'); ?></strong>
                            <?php
                            $flags_parsed = json_decode($detection['flags'], true);
                            if (is_array($flags_parsed)) {
                                // Structured format with 'flags' key
                                if (isset($flags_parsed['flags']) && is_array($flags_parsed['flags'])) {
                                    echo '<code>' . esc_html(implode(', ', $flags_parsed['flags'])) . '</code>';
                                }
                                // Simple array format (client-side 'f' key)
                                elseif (isset($flags_parsed['f']) && is_array($flags_parsed['f'])) {
                                    echo '<code>' . esc_html(implode(', ', $flags_parsed['f'])) . '</code>';
                                }
                                // Direct array
                                elseif (array_values($flags_parsed) === $flags_parsed) {
                                    echo '<code>' . esc_html(implode(', ', $flags_parsed)) . '</code>';
                                }
                                // Other structured data
                                else {
                                    echo '<code>' . esc_html(wp_json_encode($flags_parsed)) . '</code>';
                                }

                                // Show metadata if present
                                if (isset($flags_parsed['metadata']) && is_array($flags_parsed['metadata'])) {
                                    echo '<br><strong>' . esc_html__('Metadata:', 'webdecoy') . '</strong> ';
                                    echo '<code>' . esc_html(wp_json_encode($flags_parsed['metadata'])) . '</code>';
                                }
                            } else {
                                echo '<code>' . esc_html($detection['flags']) . '</code>';
                            }
                            ?>
                        </div>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>

        <?php if ($total_pages > 1) : ?>
        <div class="tablenav bottom">
            <div class="tablenav-pages">
                <?php
                $pagination_args = [
                    'base' => add_query_arg('paged', '%#%'),
                    'format' => '',
                    'prev_text' => '&laquo;',
                    'next_text' => '&raquo;',
                    'total' => $total_pages,
                    'current' => $page,
                ];
                // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- paginate_links returns safe HTML
                echo paginate_links($pagination_args);
                ?>
            </div>
        </div>
        <?php endif; ?>
    <?php endif; ?>
</div>

<!-- Styles are loaded via webdecoy-admin.css -->
