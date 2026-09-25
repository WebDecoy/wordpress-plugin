<?php

declare(strict_types=1);

/**
 * The plugin's AI referral classifier agrees with WebDecoy's own, vector for
 * vector: the golden vectors are generated from it with the platform table.
 *
 * Run: php tests/run.php
 */

if (!defined('ABSPATH')) {
    define('ABSPATH', '/tmp/');
}
require_once dirname(__DIR__) . '/sdk/src/LlmReferral.php';

$t = ['TestRunner', 'test'];
$same = ['TestRunner', 'assertSame'];

$t('every AI referral vector classifies as it does in Go', function () use ($same) {
    $path = dirname(__DIR__) . '/sdk/src/registry/llm-referral-vectors.generated.json';
    $vectors = json_decode((string) file_get_contents($path), true);
    if (!is_array($vectors) || count($vectors) < 50) {
        throw new \RuntimeException('no AI referral vectors');
    }
    foreach ($vectors as $v) {
        $same(
            \WebDecoy\LlmReferral::classify((string) $v['referer'], (string) $v['page_url']),
            (string) $v['platform'],
            'referer ' . $v['referer'] . ' page ' . $v['page_url']
        );
    }
});

$t('only a page navigation an AI product sent is counted', function () use ($same) {
    if (!class_exists('WebDecoy_AI_Referrals')) {
        require_once dirname(__DIR__) . '/includes/class-webdecoy-ai-referrals.php';
    }
    $r = ['WebDecoy_AI_Referrals', 'classifyRequest'];
    $same($r('GET', 'navigate', 'document', 'https://chatgpt.com/c/1', '/pricing?session=x'), 'ChatGPT');
    $same($r('GET', 'navigate', '', '', '/blog?utm_source=perplexity.ai'), 'Perplexity');
    $same($r('POST', 'navigate', 'document', 'https://chatgpt.com/', '/pricing'), '');
    $same($r('GET', 'no-cors', 'image', 'https://chatgpt.com/', '/logo.png'), '');
    $same($r('GET', '', '', 'https://chatgpt.com/', '/pricing'), '');
    $same($r('GET', 'navigate', 'document', 'https://www.google.com/', '/pricing'), '');
});

$t('the landing path carries no query string and fits the column', function () use ($same) {
    if (!class_exists('WebDecoy_AI_Referrals')) {
        require_once dirname(__DIR__) . '/includes/class-webdecoy-ai-referrals.php';
    }
    $p = ['WebDecoy_AI_Referrals', 'landingPath'];
    $same($p('/pricing?session=secret&email=a%40b.c'), '/pricing');
    $same($p(''), '/');
    $same(strlen($p('/' . str_repeat('a', 900))), 500);
});
