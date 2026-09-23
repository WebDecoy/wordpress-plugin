<?php

declare(strict_types=1);

/**
 * The generated registry is the one crawler table (#86).
 *
 * Three claims, each of which fails on its own:
 *  - the artifact is the shape this plugin reads, and carries every agent;
 *  - every cross-language parity vector matches here exactly as it does in
 *    Go, the Worker and the Node SDK, so a User-Agent means one thing
 *    everywhere WebDecoy runs;
 *  - the plugin's coarser categories are a stated function of the registry's,
 *    and the crawlers that were good bots before the switch still are.
 *
 * Run: php tests/run.php
 */

if (!defined('ABSPATH')) {
    define('ABSPATH', '/tmp/');
}
foreach (['AgentRegistry', 'GoodBotList'] as $class) {
    require_once dirname(__DIR__) . '/sdk/src/' . $class . '.php';
}

$t = ['TestRunner', 'test'];
$same = ['TestRunner', 'assertSame'];
$true = ['TestRunner', 'assertTrue'];

$t('the artifact is the schema this plugin reads and is complete', function () use ($same, $true) {
    $same(\WebDecoy\AgentRegistry::SCHEMA, 2);
    $same(count(\WebDecoy\AgentRegistry::all()), \WebDecoy\AgentRegistry::count());
    $true(\WebDecoy\AgentRegistry::count() >= 182, 'the registry lost agents');
    $true(in_array('training_crawler', \WebDecoy\AgentRegistry::categories(), true), 'customer-facing category names');
    foreach (\WebDecoy\AgentRegistry::all() as $agent) {
        $true(array_key_exists('behavior', $agent), 'agent ' . $agent['id'] . ' has no behavior key');
    }
});

$t('every shared parity vector matches as it does in Go', function () use ($same) {
    $path = dirname(__DIR__) . '/sdk/src/registry/parity-vectors.generated.json';
    $vectors = json_decode((string) file_get_contents($path), true);
    if (!is_array($vectors) || count($vectors) === 0) {
        throw new \RuntimeException('no parity vectors');
    }
    foreach ($vectors as $v) {
        $hit = \WebDecoy\AgentRegistry::match((string) $v['userAgent']);
        if (!$v['matched']) {
            $same($hit, null, 'expected no match for ' . $v['userAgent']);
            continue;
        }
        $same($hit['id'] ?? null, $v['id'], 'id for ' . $v['userAgent']);
        $same($hit['category'] ?? null, $v['category'], 'category for ' . $v['userAgent']);
    }
});

$t('a deliberately changed generated entry is caught', function () use ($same) {
    // The vectors pin ids; a hand edit that renamed an agent or reordered two
    // overlapping patterns would fail the parity test above. This pins the
    // one ordering case that bit the Node SDK: applebot-extended must be
    // taken before applebot.
    $same(\WebDecoy\AgentRegistry::match('Mozilla/5.0 (compatible; Applebot-Extended/0.1)')['id'], 'applebot-extended');
    $same(\WebDecoy\AgentRegistry::match('Mozilla/5.0 (compatible; Applebot/0.1)')['id'], 'applebot');
});

$t('plugin categories are a stated function of registry categories', function () use ($same) {
    $list = new \WebDecoy\GoodBotList();
    $cases = [
        'Googlebot/2.1' => \WebDecoy\GoodBotList::CATEGORY_SEARCH_ENGINE,
        'Mozilla/5.0 (compatible; Exabot/3.0)' => \WebDecoy\GoodBotList::CATEGORY_SEARCH_ENGINE,
        'GPTBot/1.2' => \WebDecoy\GoodBotList::CATEGORY_AI_CRAWLER,
        'ChatGPT-User/1.0' => \WebDecoy\GoodBotList::CATEGORY_AI_CRAWLER,
        'Claude-User/1.0' => \WebDecoy\GoodBotList::CATEGORY_AI_CRAWLER,
        'facebookexternalhit/1.1' => \WebDecoy\GoodBotList::CATEGORY_SOCIAL,
        'UptimeRobot/2.0' => \WebDecoy\GoodBotList::CATEGORY_MONITORING,
        'AhrefsBot/7.0' => \WebDecoy\GoodBotList::CATEGORY_SEO,
        'Feedly/1.0' => \WebDecoy\GoodBotList::CATEGORY_FEED,
        'ia_archiver' => \WebDecoy\GoodBotList::CATEGORY_ARCHIVE,
    ];
    foreach ($cases as $ua => $want) {
        $same($list->identify($ua)['category'] ?? null, $want, $ua);
    }
    // Not good bots: identified by the registry, but not here.
    foreach (['python-requests/2.32', 'HeadlessChrome/120', 'Nikto/2.1', 'Mozilla/5.0 (compatible; Bright Data)'] as $ua) {
        $same($list->identify($ua), null, $ua . ' is not a good bot');
    }
});

$t('every crawler the old table named is still identified', function () use ($true) {
    $list = new \WebDecoy\GoodBotList();
    // The old GoodBotList patterns, minus the two W3C validators that were
    // dropped (they were never allowed; see the changelog).
    $old = [
        'googlebot', 'google-inspectiontool', 'bingbot', 'msnbot', 'yandexbot', 'baiduspider', 'duckduckbot',
        'slurp', 'sogou', 'exabot', 'qwantify', 'applebot', 'gptbot', 'chatgpt-user', 'oai-searchbot',
        'claudebot', 'claude-web', 'anthropic-ai', 'perplexitybot', 'ccbot', 'cohere-ai', 'google-extended',
        'meta-externalagent', 'amazonbot', 'twitterbot', 'facebookexternalhit', 'facebot', 'linkedinbot',
        'pinterestbot', 'slackbot', 'telegrambot', 'whatsapp', 'discordbot', 'redditbot', 'pingdom',
        'uptimerobot', 'newrelicpinger', 'datadogsynthetics', 'statuscake', 'site24x7', 'gtmetrix',
        'chrome-lighthouse', 'semrushbot', 'ahrefsbot', 'mj12bot', 'dotbot', 'screaming frog', 'feedfetcher',
        'feedly', 'newsblur', 'archive.org_bot', 'ia_archiver',
    ];
    foreach ($old as $ua) {
        $true($list->identify($ua) !== null, $ua . ' lost its identity');
    }
});

$t('verification is keyed by registry id and reachable by matched pattern', function () use ($true, $same) {
    $list = new \WebDecoy\GoodBotList();
    $bot = $list->identify('Mozilla/5.0 (compatible; Pinterestbot/1.0)');
    $same($bot['id'], 'pinterestbot');
    $true($list->requiresVerification($bot['id']), 'by id');
    $true($list->requiresVerification($bot['pattern']), 'by matched pattern');
    $true(!$list->requiresVerification('uptimerobot'), 'monitoring does not verify');
    $same($list->identify('GPTBot/1.2')['behavior'], 'training');
    $same($list->identify('Googlebot/2.1')['behavior'], 'search');
});
