<?php
/**
 * AI Traffic page: says when a page cache hides crawler page views, and offers
 * the opt-in that lets known crawlers through supported cache plugins.
 *
 * @package WebDecoy
 */

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- This partial is included through statistics_page(). Its variables stay in that method.
if (!defined('ABSPATH')) {
    exit;
}
if (!class_exists('WebDecoy_Page_Cache') || !current_user_can('manage_options')) {
    return;
}

$wd_cache = WebDecoy_Page_Cache::detect();
if ($wd_cache['kind'] === 'none') {
    return;
}
$wd_cache_on = (bool) get_option(WebDecoy_Page_Cache::OPTION);
$wd_cache_name = $wd_cache['name'] !== '' ? $wd_cache['name'] : __('A page cache', 'webdecoy');
$wd_cloud_url = admin_url('admin.php?page=webdecoy&tab=cloud');
?>
<div class="notice notice-info inline wd-cache-notice">
    <p><strong><?php esc_html_e('Some crawler visits are not counted', 'webdecoy'); ?></strong></p>
    <p>
        <?php
        echo esc_html(sprintf(
            /* translators: %s: page cache name, e.g. WP Rocket or WP Engine */
            __('%s serves cached pages before WordPress runs, so crawler visits to those pages never reach WebDecoy.', 'webdecoy'),
            $wd_cache_name
        ));
        echo ' ';
        esc_html_e('These counts include crawlers fetching robots.txt, sitemaps and llms.txt, but miss their visits to cached pages.', 'webdecoy');
        ?>
    </p>

    <?php if ($wd_cache['bypass_supported']) : ?>
    <form method="post" action="options.php">
        <?php settings_fields(WebDecoy_Page_Cache::SETTINGS_GROUP); ?>
        <p>
            <label>
                <input type="checkbox" name="<?php echo esc_attr(WebDecoy_Page_Cache::OPTION); ?>" value="1" <?php checked($wd_cache_on); ?> />
                <?php esc_html_e('Count crawlers on cached pages', 'webdecoy'); ?>
            </label>
        </p>
        <p class="description">
            <?php
            echo esc_html(sprintf(
                /* translators: %s: page cache plugin name, e.g. WP Rocket */
                __('Asks %s to skip its cache for known AI and search crawlers, so their page views reach WordPress and are counted. Those crawler requests are no longer served from cache, which adds server load on sites that crawlers visit often. Turning this off removes only the entries WebDecoy added.', 'webdecoy'),
                $wd_cache_name
            ));
            ?>
        </p>
        <?php if ($wd_cache_on) : ?>
        <p><?php esc_html_e('On. New crawler page views appear here as they arrive.', 'webdecoy'); ?></p>
        <?php endif; ?>
        <?php submit_button(__('Save', 'webdecoy'), 'secondary', 'submit', false); ?>
    </form>
    <?php else : ?>
    <p>
        <?php
        if ($wd_cache['kind'] === 'host') {
            esc_html_e('Your host answers these requests itself, so no WordPress setting can let crawlers through.', 'webdecoy');
        } else {
            esc_html_e('WebDecoy has no supported way to ask this cache to let crawlers through.', 'webdecoy');
        }
        echo ' ';
        esc_html_e('To count those visits, connect WebDecoy Cloud: if your site runs through Cloudflare, WebDecoy can count crawlers there, before any cache.', 'webdecoy');
        ?>
        <a href="<?php echo esc_url($wd_cloud_url); ?>"><?php esc_html_e('Connect WebDecoy Cloud', 'webdecoy'); ?></a>
    </p>
    <?php endif; ?>
</div>
