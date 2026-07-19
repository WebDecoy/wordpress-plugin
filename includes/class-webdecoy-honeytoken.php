<?php

declare(strict_types=1);

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Honeytoken (F4 deception layer) — automatic sitewide hidden-link injection.
 *
 * Plants a visually-hidden, non-followable link on front-end pages pointing at a
 * secret per-site path (`/__wd/{token}`). A real visitor never sees or clicks it
 * (offscreen, aria-hidden, tabindex -1, nofollow/noindex); only a client that
 * parses the HTML and follows links — a scraper — requests the path. The path is
 * armed as a tripwire, so a hit is a deterministic, zero-false-positive
 * automated-intent signal.
 *
 * WordPress owns page rendering, so injection is automatic — unlike @webdecoy/node
 * where the developer must embed the link by hand.
 *
 * The token is derived by HMAC from a stored per-site secret, so it is
 * unguessable and needs no extra storage. With rotation enabled it changes daily
 * (yesterday's token stays armed as a grace window so a crawler mid-crawl still
 * trips).
 *
 * Deliberately no robots.txt Disallow entry: a `Disallow: /__wd/` line would
 * advertise the trap, and robots-honoring good bots never follow a nofollow
 * hidden link anyway.
 */
class WebDecoy_Honeytoken
{
    /** Base path for honeytoken tripwires (mirrors @webdecoy/node's default). */
    private const BASE_PATH = '/__wd';

    /** Token length (hex chars), matching node's randomBytes(6).toString('hex'). */
    private const TOKEN_LEN = 12;

    /** @var bool */
    private $rotate;

    public function __construct(bool $rotate = false)
    {
        $this->rotate = $rotate;
    }

    /**
     * Get (or lazily create) the per-site secret the tokens are derived from.
     */
    private function secret(): string
    {
        $secret = get_option('webdecoy_honeytoken_secret', '');
        if (!is_string($secret) || $secret === '') {
            $secret = bin2hex(random_bytes(16));
            // Autoload so it's cheap to read on every request.
            add_option('webdecoy_honeytoken_secret', $secret, '', 'yes');
        }
        return $secret;
    }

    /**
     * Derive a token from the secret for a given label.
     */
    private function token(string $label): string
    {
        return substr(hash_hmac('sha256', $label, $this->secret()), 0, self::TOKEN_LEN);
    }

    /**
     * The path advertised in the injected link (today's, or the stable one).
     */
    public function primary_path(): string
    {
        if ($this->rotate) {
            return self::BASE_PATH . '/' . $this->token('day:' . gmdate('Y-m-d'));
        }
        return self::BASE_PATH . '/' . $this->token('stable');
    }

    /**
     * All paths that should be armed as tripwires right now. With rotation this
     * is today + yesterday (grace window); otherwise just the stable path.
     *
     * @return string[]
     */
    public function active_paths(): array
    {
        if (!$this->rotate) {
            return [self::BASE_PATH . '/' . $this->token('stable')];
        }

        $today = self::BASE_PATH . '/' . $this->token('day:' . gmdate('Y-m-d'));
        $yesterday = self::BASE_PATH . '/' . $this->token('day:' . gmdate('Y-m-d', time() - DAY_IN_SECONDS));

        return array_values(array_unique([$today, $yesterday]));
    }

    /**
     * The hidden decoy link HTML. Byte-for-byte the same hiding technique as
     * @webdecoy/node's honeytoken() so behavior matches across SDKs.
     */
    public function render_link(): string
    {
        $path = esc_attr($this->primary_path());
        return '<a href="' . $path . '" aria-hidden="true" tabindex="-1" rel="nofollow noindex" '
            . 'style="position:absolute;left:-9999px;top:auto;width:1px;height:1px;overflow:hidden">.</a>';
    }

    /**
     * Whether the honeytoken link should be injected on the current request.
     * Skips logged-in users, feeds, and non-HTML contexts so a genuine visitor
     * or authenticated session can never trip it.
     */
    public function should_inject(): bool
    {
        if (is_admin() || wp_doing_ajax() || is_feed()) {
            return false;
        }
        if (defined('REST_REQUEST') && REST_REQUEST) {
            return false;
        }
        if (defined('DOING_CRON') && DOING_CRON) {
            return false;
        }
        if (is_user_logged_in()) {
            return false;
        }
        return true;
    }
}
