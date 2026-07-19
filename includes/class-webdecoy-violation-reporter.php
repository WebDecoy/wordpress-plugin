<?php

declare(strict_types=1);

use WebDecoy\Rules\ViolationEvent;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Buffers rule-engine violations and flushes them to the ingest service.
 *
 * PHP has no persistent process, so unlike @webdecoy/node's timer-based
 * reporter this buffers per request and flushes once on `shutdown` with a
 * single non-blocking POST (fire-and-forget: timeout 1s, blocking false) — the
 * same pattern the plugin already uses for page-serve and detection forwarding.
 * A typical request produces 0–1 events, so per-request flush is the natural
 * unit and never adds latency to the response.
 *
 * Best-effort by design, mirroring node: on failure events are dropped rather
 * than allowed to become a reliability liability. (Durable DB spooling +
 * cron-based retry is the P1 follow-up in #7.)
 *
 * Reporting is a cloud feature: with no API key configured, nothing is sent —
 * rules still enforce locally. This mirrors node, whose reporter is only wired
 * when an apiKey is present.
 */
class WebDecoy_Violation_Reporter
{
    /** Ingest batch endpoint. */
    private const ENDPOINT = 'https://ingest.webdecoy.com/api/v1/sdk/violations/batch';

    /** Max events per POST body, matching node's batch size. */
    private const BATCH_SIZE = 100;

    /** @var WebDecoy_Violation_Reporter|null */
    private static $instance = null;

    /** @var ViolationEvent[] */
    private $buffer = [];

    /** @var string */
    private $apiKey;

    /** @var bool Whether the shutdown flush has been registered. */
    private $registered = false;

    public function __construct(string $apiKey)
    {
        $this->apiKey = $apiKey;
    }

    /**
     * Get (or lazily create) the per-request reporter singleton.
     *
     * @return WebDecoy_Violation_Reporter|null Null when reporting is disabled
     *                                          (no API key).
     */
    public static function instance(string $apiKey): ?self
    {
        if ($apiKey === '') {
            return null;
        }
        if (self::$instance === null) {
            self::$instance = new self($apiKey);
        }
        return self::$instance;
    }

    /**
     * Queue violations for reporting and ensure a flush is scheduled.
     *
     * @param ViolationEvent[] $events
     */
    public function report(array $events): void
    {
        if ($events === []) {
            return;
        }
        foreach ($events as $event) {
            $this->buffer[] = $event;
        }
        $this->ensureShutdownHook();
    }

    /**
     * Register the shutdown flush exactly once. On a DENY the request often ends
     * via exit() before shutdown handlers that were registered later — so when a
     * flush is needed and we're already tearing down, flush inline instead.
     */
    private function ensureShutdownHook(): void
    {
        if ($this->registered) {
            return;
        }
        $this->registered = true;
        if (function_exists('add_action')) {
            add_action('shutdown', [$this, 'flush'], 0);
        }
        // Also flush on PHP shutdown as a backstop for early exit() paths
        // (e.g. block responses that call exit before WP's shutdown action).
        register_shutdown_function([$this, 'flush']);
    }

    /**
     * Flush the buffer to ingest. Idempotent: safe to call more than once (the
     * buffer is drained on first call).
     */
    public function flush(): void
    {
        if ($this->buffer === [] || $this->apiKey === '') {
            return;
        }

        $events = $this->buffer;
        $this->buffer = [];

        foreach (array_chunk($events, self::BATCH_SIZE) as $batch) {
            $payload = [];
            foreach ($batch as $event) {
                $payload[] = $event->toApiPayload();
            }

            if (!function_exists('wp_remote_post')) {
                continue;
            }

            wp_remote_post(self::ENDPOINT, [
                'timeout'  => 1,
                'blocking' => false,
                'headers'  => [
                    'Content-Type'  => 'application/json',
                    'Authorization' => 'Bearer ' . $this->apiKey,
                ],
                'body' => wp_json_encode(['events' => $payload]),
            ]);
        }
    }
}
