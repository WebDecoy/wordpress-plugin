<?php

declare(strict_types=1);

/**
 * Cloud alert entry points describe entitlement separately from delivery.
 *
 * The plugin receives features.alerts, which answers only whether the plan may
 * configure and deliver alerts. It receives no Slack/webhook configuration
 * state, so claiming that alerts are "On" would invent operational status.
 */

echo "\nCloud alert entry points\n";

$settings = (string) file_get_contents(dirname(__DIR__) . '/admin/partials/settings-page.php');

TestRunner::test('an alert entitlement is presented as availability, not delivery state', function () use ($settings) {
    TestRunner::assertTrue(
        strpos($settings, 'Slack and webhook alerts are available with your plan.') !== false,
        'the paid state should say the channels are available'
    );
    TestRunner::assertTrue(
        strpos($settings, 'Slack and webhook alerts: On.') === false,
        'features.alerts cannot prove that either channel is configured or delivering'
    );
});

TestRunner::test('Slack and webhook links reach their separate configuration surfaces', function () use ($settings) {
    TestRunner::assertTrue(
        strpos($settings, 'https://app.webdecoy.com/integrations/slack') !== false,
        'Slack is an integration, not a response-action type'
    );
    TestRunner::assertTrue(
        strpos($settings, 'https://app.webdecoy.com/integrations/webhooks') !== false,
        'webhooks link to their integration configuration'
    );
    TestRunner::assertTrue(
        strpos($settings, 'Configure Slack') !== false && strpos($settings, 'Configure webhooks') !== false,
        'each channel has an explicit link label'
    );
});
