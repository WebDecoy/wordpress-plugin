<?php

declare(strict_types=1);

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Sends detections to WebDecoy Cloud after the visitor has their page
 * (WebDecoy/app#1245).
 *
 * Detections used to be sent inline, during `init`, before the block
 * decision, with a 10 second timeout and, on installs without a stored
 * organization id, a second 10 second key lookup in front of it. When ingest
 * was slow or down, every flagged page view waited up to 20 seconds on it.
 *
 * Now a detection is queued during the request and sent from a shutdown
 * handler, after fastcgi_finish_request() has handed the response back (where
 * the server supports it). Blocking and logging never wait on the cloud.
 *
 * While ingest is refusing work (rate limited, shedding, or unreachable) the
 * sender backs off for BACKOFF_SECONDS across all requests, so an outage costs
 * one failed attempt per window instead of one per flagged page view. Those
 * detections are dropped, not retried: they are already in the local log, and
 * the cloud copy is best effort.
 */
class WebDecoy_Detection_Sender
{
    /** Transient that marks ingest as refusing work; shared by every request. */
    public const BACKOFF_TRANSIENT = 'webdecoy_ingest_backoff';

    /** How long one refusal pauses sending. */
    public const BACKOFF_SECONDS = 60;

    /** Cap on detections one request may queue. */
    private const MAX_PER_REQUEST = 5;

    /** @var array<int,callable():void> */
    private static $queue = [];

    /** @var bool */
    private static $registered = false;

    /**
     * Test seam: replaces the transient store. Null uses WordPress transients.
     *
     * @var array<string,mixed>|null
     */
    public static $store = null;

    /**
     * Queue one send for after the response. $send performs the request and
     * throws on failure.
     *
     * @param callable():void $send
     */
    public static function defer(callable $send): void
    {
        if (self::backing_off() || count(self::$queue) >= self::MAX_PER_REQUEST) {
            return;
        }
        self::$queue[] = $send;
        if (!self::$registered) {
            self::$registered = true;
            register_shutdown_function([self::class, 'flush']);
        }
    }

    /**
     * Shutdown handler: release the visitor first, then send.
     */
    public static function flush(): void
    {
        if (self::$queue === []) {
            return;
        }
        if (function_exists('fastcgi_finish_request')) {
            @fastcgi_finish_request(); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
        }
        self::send_queued();
    }

    /**
     * Send everything queued, stopping at the first refusal. Separate from
     * flush() so tests can run it without finishing the request.
     */
    public static function send_queued(): void
    {
        $queue = self::$queue;
        self::$queue = [];
        foreach ($queue as $send) {
            if (self::backing_off()) {
                return;
            }
            try {
                $send();
            } catch (\Throwable $e) {
                if (self::is_refusal($e)) {
                    self::note_refusal();
                }
                error_log('WebDecoy API error: ' . $e->getMessage());
            }
        }
    }

    /** Whether ingest is currently refusing work. */
    public static function backing_off(): bool
    {
        if (self::$store !== null) {
            return !empty(self::$store[self::BACKOFF_TRANSIENT]);
        }
        return (bool) get_transient(self::BACKOFF_TRANSIENT);
    }

    /**
     * Record that ingest refused work, pausing every cloud call that checks
     * backing_off() (detection sends here, IP enrichment) for BACKOFF_SECONDS.
     * The one answer to "is ingest refusing right now" for the plugin.
     */
    public static function note_refusal(): void
    {
        if (self::$store !== null) {
            self::$store[self::BACKOFF_TRANSIENT] = 1;
            return;
        }
        set_transient(self::BACKOFF_TRANSIENT, 1, self::BACKOFF_SECONDS);
    }

    /**
     * A refusal means "come back later": rate limited (429), shedding or down
     * (5xx), or no HTTP answer at all (code 0). A 4xx other than 429 is an
     * answer about this request, not about ingest, and does not pause sending.
     */
    public static function is_refusal(\Throwable $e): bool
    {
        $code = (int) $e->getCode();
        return $code === 0 || $code === 429 || $code >= 500;
    }

    /** Test seam: forget queued sends and registration. */
    public static function reset(): void
    {
        self::$queue = [];
        self::$registered = false;
        self::$store = [];
    }

    /** Test seam: how many sends are queued. */
    public static function queued(): int
    {
        return count(self::$queue);
    }
}
