<?php
/**
 * One plain sentence for what a stored detection was.
 *
 * The Detections page "What happened" column and the post-CRITICAL admin
 * notice both describe a detection. They used to answer separately: the
 * column only knew decoy hits and showed nothing else, and the notice said
 * "a deception trap was just tripped" for every CRITICAL row, including a
 * visitor that merely claimed to be Googlebot. This is the one answer both
 * read.
 *
 * @package WebDecoy
 */

if (!defined('ABSPATH')) {
    exit;
}

final class WebDecoy_Detection_Summary
{
    /**
     * Sentence for a detection row's stored flags JSON
     * (`{"flags":[...],"metadata":{...}}`), or '' when there is nothing more
     * specific to say than the technical columns already show.
     *
     * Only for rows the server recorded. Rows from the in-page bot check are
     * reported by the visitor's own browser, so their flags are not evidence
     * of anything and must not be put into words here.
     */
    public static function sentence(?string $flags_json): string
    {
        if (class_exists('\WebDecoy\HitExplanation')) {
            $trap = \WebDecoy\HitExplanation::forLocalFlags($flags_json);
            if ($trap !== '') {
                return $trap;
            }
        }

        $data = json_decode((string) $flags_json, true);
        if (!is_array($data) || !isset($data['flags']) || !is_array($data['flags'])) {
            return '';
        }
        $flags = $data['flags'];
        $meta = isset($data['metadata']) && is_array($data['metadata']) ? $data['metadata'] : [];
        $has = static function (string $flag) use ($flags): bool {
            return in_array($flag, $flags, true);
        };

        if ($has('canary_credential_use')) {
            return __('Someone tried to log in with a decoy password that only exists to catch stolen credentials.', 'webdecoy');
        }
        if ($has('fake_bot') || $has('bot_verification_failed')) {
            $name = self::agent_name($meta['claimed_bot'] ?? '');
            return $name !== ''
                /* translators: %s: crawler name, e.g. Googlebot */
                ? sprintf(__('A visitor claimed to be %s, but its address failed the check that confirms it.', 'webdecoy'), $name)
                : __('A visitor claimed to be a known crawler, but its address failed the check that confirms it.', 'webdecoy');
        }
        if ($has('ai_crawler_blocked')) {
            $name = self::agent_name($meta['bot_info']['name'] ?? '');
            return $name !== ''
                /* translators: %s: crawler name, e.g. GPTBot */
                ? sprintf(__('%s was refused by your AI crawler setting.', 'webdecoy'), $name)
                : __('An AI crawler was refused by your AI crawler setting.', 'webdecoy');
        }
        if ($has('crawler_refused')) {
            $name = self::agent_name($meta['bot_info']['name'] ?? '');
            return $name !== ''
                /* translators: %s: crawler name */
                ? sprintf(__('%s was refused by a crawler rule set in WebDecoy Cloud.', 'webdecoy'), $name)
                : __('A crawler was refused by a crawler rule set in WebDecoy Cloud.', 'webdecoy');
        }
        if ($has('honeypot_triggered')) {
            return __('A form was submitted with a hidden field filled in that only bots can see.', 'webdecoy');
        }
        if ($has('headless') || $has('automation_tool')) {
            return __('The request came from an automated browser.', 'webdecoy');
        }
        if ($has('cli_tool')) {
            return __('The request came from a command-line tool, not a browser.', 'webdecoy');
        }
        if ($has('empty_user_agent')) {
            return __('The request did not say what software sent it.', 'webdecoy');
        }
        return '';
    }

    /**
     * A crawler name from our own registry match, trimmed to something safe to
     * print. It names the agent the request claimed, which is the point.
     *
     * @param mixed $name
     */
    private static function agent_name($name): string
    {
        if (!is_string($name)) {
            return '';
        }
        $name = trim(preg_replace('/[^\p{L}\p{N} ._-]/u', '', $name) ?? '');
        return function_exists('mb_substr') ? mb_substr($name, 0, 60) : substr($name, 0, 60);
    }
}
