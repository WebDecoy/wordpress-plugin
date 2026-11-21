<?php
/** Chart-first local traffic overview. @package WebDecoy */
if (!defined('ABSPATH')) {
    exit;
}
if (!isset($traffic_report) || !is_array($traffic_report)) {
    return;
}
$traffic_days = (int) $traffic_report['days'];
$crawler_summary = $traffic_report['crawler_ready'] ? $traffic_report['crawlers'] : null;
$ai_referral_summary = $traffic_report['referral_ready'] ? $traffic_report['referrals'] : null;
$wd_bot_total = (int) ($crawler_summary['total'] ?? 0);
$wd_ref_total = (int) ($ai_referral_summary['total'] ?? 0);
?>
<header class="wd-analytics-header">
    <div>
        <div class="wd-brand"><img src="<?php echo esc_url(WEBDECOY_PLUGIN_URL . 'assets/duck.png'); ?>" alt="" width="42" height="42" /><span>WebDecoy</span><span class="wd-brand-divider">/</span><span class="wd-eyebrow"><?php esc_html_e('TRAFFIC INTELLIGENCE', 'webdecoy'); ?></span></div>
        <h2 class="wd-page-title"><?php esc_html_e('Know your bot traffic.', 'webdecoy'); ?></h2>
        <p><?php esc_html_e('Who crawls your site. Who sends visitors back.', 'webdecoy'); ?></p>
    </div>
    <nav class="wd-period" aria-label="<?php esc_attr_e('Traffic reporting period', 'webdecoy'); ?>">
        <?php foreach ([7, 30] as $wd_days) : ?>
        <a href="<?php echo esc_url(add_query_arg(['page' => 'webdecoy-statistics', 'traffic_days' => $wd_days], admin_url('admin.php'))); ?>" <?php if ($traffic_days === $wd_days) : ?>aria-current="page"<?php endif; ?>><?php echo esc_html(sprintf(/* translators: %d: reporting window in days */ __('%d days', 'webdecoy'), $wd_days)); ?></a>
        <?php endforeach; ?>
    </nav>
</header>
<div class="wd-report-caption"><span class="wd-status-dot" aria-hidden="true"></span><?php esc_html_e('Local reporting', 'webdecoy'); ?><span>·</span><?php esc_html_e('UTC calendar days, including today', 'webdecoy'); ?><span>·</span><?php esc_html_e('Refreshes within a minute', 'webdecoy'); ?></div>
<div class="wd-metrics">
    <?php foreach ([
        [__('Known bot visits', 'webdecoy'), $crawler_summary !== null ? $wd_bot_total : null, __('Observed crawler requests', 'webdecoy'), 'bots'],
        [__('AI crawler visits', 'webdecoy'), $crawler_summary['groups']['ai'] ?? null, __('Training, search & agents', 'webdecoy'), 'ai'],
        [__('AI-referred visits', 'webdecoy'), $ai_referral_summary !== null ? $wd_ref_total : null, __('Visits sent by AI assistants', 'webdecoy'), 'referrals'],
        [__('Distinct bot identities', 'webdecoy'), $crawler_summary !== null ? count($crawler_summary['agents']) : null, __('Named agents, not unique visitors', 'webdecoy'), 'identities'],
    ] as $wd_metric) : ?>
    <div class="wd-metric" data-metric="<?php echo esc_attr($wd_metric[3]); ?>">
        <span class="wd-metric-label"><?php echo esc_html($wd_metric[0]); ?></span>
        <strong><?php echo $wd_metric[1] === null ? '&mdash;' : esc_html(number_format((int) $wd_metric[1])); ?></strong>
        <span class="wd-metric-note"><?php echo esc_html($wd_metric[2]); ?></span>
    </div>
    <?php endforeach; ?>
</div>
<div class="wd-chart-grid">
    <section class="wd-panel wd-panel-main" aria-labelledby="wd-crawler-title">
        <div class="wd-panel-heading"><div><span class="wd-eyebrow"><?php esc_html_e('CRAWL ACTIVITY', 'webdecoy'); ?></span><h2 id="wd-crawler-title"><?php esc_html_e('Bots over time', 'webdecoy'); ?></h2></div><span class="wd-panel-meta"><?php esc_html_e('Requests / day', 'webdecoy'); ?></span></div>
        <?php if ($crawler_summary === null || $wd_bot_total === 0) : ?>
        <div class="wd-chart-empty"><span class="dashicons dashicons-chart-area" aria-hidden="true"></span><h3><?php echo $crawler_summary === null ? esc_html__('Counters are getting ready', 'webdecoy') : esc_html__('Crawlers usually show up within a few hours', 'webdecoy'); ?></h3><p><?php
            $wd_known_agents = class_exists('\WebDecoy\AgentRegistry') ? \WebDecoy\AgentRegistry::count() : 0;
            echo esc_html(
                $wd_known_agents > 0
                    /* translators: %s: number of known bots, e.g. 250 */
                    ? sprintf(__('WebDecoy is counting now. GPTBot, ClaudeBot, Googlebot and %s other known bots appear here as they reach your site. No account or API key needed.', 'webdecoy'), number_format_i18n(max(0, $wd_known_agents - 3)))
                    : __('WebDecoy is counting now. GPTBot, ClaudeBot, Googlebot and other known bots appear here as they reach your site. No account or API key needed.', 'webdecoy')
            );
        ?></p></div>
        <?php else : ?>
        <div class="wd-chart-canvas wd-chart-large"><canvas id="wdCrawlerChart" role="img" aria-label="<?php esc_attr_e('Daily crawler requests by AI, search engines and other known bots. Exact totals appear in the cards and detail tables.', 'webdecoy'); ?>"></canvas></div>
        <?php endif; ?>
        <ul class="wd-chart-legend"><li><i class="wd-dot-ai"></i><?php esc_html_e('AI crawlers & agents', 'webdecoy'); ?></li><li><i class="wd-dot-search"></i><?php esc_html_e('Search engines', 'webdecoy'); ?></li><li><i class="wd-dot-other"></i><?php esc_html_e('Other known bots', 'webdecoy'); ?></li></ul>
    </section>
    <section class="wd-panel" aria-labelledby="wd-mix-title">
        <div class="wd-panel-heading"><div><span class="wd-eyebrow"><?php esc_html_e('THE BREAKDOWN', 'webdecoy'); ?></span><h2 id="wd-mix-title"><?php esc_html_e('Bot mix', 'webdecoy'); ?></h2></div></div>
        <?php if ($crawler_summary !== null && $wd_bot_total > 0) : ?>
        <div class="wd-chart-canvas wd-chart-ring"><canvas id="wdBotMixChart" role="img" aria-label="<?php esc_attr_e('Share of observed known bot requests, grouped by type. This does not compare bots with human traffic.', 'webdecoy'); ?>"></canvas></div>
        <ul class="wd-breakdown"><?php foreach (['ai' => __('AI crawlers & agents', 'webdecoy'), 'search' => __('Search engines', 'webdecoy'), 'other' => __('Other known bots', 'webdecoy')] as $wd_key => $wd_label) : ?><li><span><i class="wd-dot-<?php echo esc_attr($wd_key); ?>"></i><?php echo esc_html($wd_label); ?></span><strong><?php echo esc_html(number_format((int) $crawler_summary['groups'][$wd_key])); ?></strong></li><?php endforeach; ?></ul>
        <?php else : ?>
        <div class="wd-chart-empty wd-chart-empty-small"><span class="dashicons dashicons-chart-pie" aria-hidden="true"></span><p><?php esc_html_e('A breakdown appears when known bots are observed.', 'webdecoy'); ?></p></div>
        <?php endif; ?>
    </section>
    <section class="wd-panel" aria-labelledby="wd-top-title">
        <div class="wd-panel-heading"><div><span class="wd-eyebrow"><?php esc_html_e('WHO IS VISITING', 'webdecoy'); ?></span><h2 id="wd-top-title"><?php esc_html_e('Top crawlers', 'webdecoy'); ?></h2></div></div>
        <?php if ($crawler_summary !== null && $wd_bot_total > 0) : ?>
        <div class="wd-chart-canvas wd-chart-ranked"><canvas id="wdTopAgentsChart" role="img" aria-label="<?php esc_attr_e('The six busiest bot identities by request count. See the detail table for identity evidence.', 'webdecoy'); ?>"></canvas></div>
        <?php else : ?>
        <div class="wd-chart-empty wd-chart-empty-small"><span class="dashicons dashicons-search" aria-hidden="true"></span><p><?php esc_html_e('See your busiest crawlers here once they visit.', 'webdecoy'); ?></p></div>
        <?php endif; ?>
        <p class="wd-panel-footnote"><?php esc_html_e('A crawler name is a claim unless its address is verified. Check identity evidence in the details below.', 'webdecoy'); ?></p>
    </section>
    <section class="wd-panel wd-panel-main" aria-labelledby="wd-ref-title">
        <div class="wd-panel-heading"><div><span class="wd-eyebrow"><?php esc_html_e('TRAFFIC COMING BACK', 'webdecoy'); ?></span><h2 id="wd-ref-title"><?php esc_html_e('Visitors from AI', 'webdecoy'); ?></h2></div><span class="wd-panel-meta"><?php esc_html_e('Referred visits / day', 'webdecoy'); ?></span></div>
        <?php if ($ai_referral_summary !== null && $wd_ref_total > 0) : ?>
        <div class="wd-chart-canvas wd-chart-referrals"><canvas id="wdReferralChart" role="img" aria-label="<?php esc_attr_e('Daily visits carrying a recognized AI referrer. These are separate from crawler requests.', 'webdecoy'); ?>"></canvas></div>
        <ul class="wd-referral-sources"><?php foreach (array_slice($ai_referral_summary['platforms'], 0, 5) as $wd_platform) : ?><li><span><?php echo esc_html($wd_platform['platform']); ?></span><strong><?php echo esc_html(number_format((int) $wd_platform['referrals'])); ?></strong></li><?php endforeach; ?></ul>
        <?php else : ?>
        <div class="wd-chart-empty wd-chart-empty-small"><span class="dashicons dashicons-external" aria-hidden="true"></span><h3><?php echo $ai_referral_summary === null ? esc_html__('Referral counters are getting ready', 'webdecoy') : esc_html__('No AI referrals yet', 'webdecoy'); ?></h3><p><?php esc_html_e('Visits from links in ChatGPT, Perplexity, Claude and other AI assistants appear separately from crawling.', 'webdecoy'); ?></p></div>
        <?php endif; ?>
    </section>
</div>
<details class="wd-coverage"><summary><?php esc_html_e('What this dashboard measures', 'webdecoy'); ?></summary><p><?php esc_html_e('Only requests reaching WordPress are counted; page-cache hits and traffic stopped upstream are outside this view. Crawler names can be spoofed. AI referral counts require a recognizable referrer and do not establish human identity. No overall human-traffic denominator is collected. All traffic cards and charts use the selected UTC calendar window.', 'webdecoy'); ?></p></details>
