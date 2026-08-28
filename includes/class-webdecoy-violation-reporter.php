<?php

declare(strict_types=1);

use WebDecoy\Rules\ViolationEvent;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Reports rule-engine violations to the ingest service, resiliently.
 *
 * PHP has no persistent worker, so violations are spooled to a DB table
 * (webdecoy_violation_queue) the moment they occur, then delivered:
 *
 *  1. Immediately, on request shutdown — after fastcgi_finish_request() (when
 *     available) hands the response back to the client, so the blocking send
 *     never adds user-facing latency. This keeps enforcement near-instant: a
 *     tripwire hit reaches the deny-list within seconds.
 *  2. As a safety net, by a cron job (webdecoy_flush_violations) that drains
 *     anything left behind if the ingest service was briefly unreachable.
 *
 * Delivery is retried once then dropped, and the queue is hard-capped, so
 * reporting can never become a reliability or storage liability (best-effort,
 * matching @webdecoy/node).
 *
 * Cloud feature: only used when a Cloud API key is set. Local-only installs
 * still enforce rules; they just don't report.
 */
class WebDecoy_Violation_Reporter
{
    /** Ingest batch endpoint. */
    private const ENDPOINT = 'https://in.webdecoy.com/api/v1/sdk/violations/batch';

    /** Max events per POST body, matching node's batch size. */
    private const BATCH_SIZE = 100;

    /** Deliveries are retried this many times total before the event is dropped. */
    private const MAX_ATTEMPTS = 2;

    /** Hard cap on spooled rows; oldest beyond this are discarded. */
    private const MAX_QUEUE = 1000;

    /** @var WebDecoy_Violation_Reporter|null */
    private static $instance = null;

    /** @var string */
    private $apiKey;

    /** @var bool Whether the shutdown drain has been registered. */
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
     * Spool violations for delivery and ensure a shutdown drain is scheduled.
     *
     * @param ViolationEvent[] $events
     */
    public function report(array $events): void
    {
        if ($events === [] || $this->apiKey === '') {
            return;
        }

        global $wpdb;
        $table = $wpdb->prefix . 'webdecoy_violation_queue';
        $now = current_time('mysql');

        foreach ($events as $event) {
            $wpdb->insert($table, [
                'payload' => wp_json_encode($event->toApiPayload()),
                'attempts' => 0,
                'created_at' => $now,
            ]);
        }

        $this->ensureShutdownDrain();
    }

    /**
     * Register the shutdown drain exactly once.
     */
    private function ensureShutdownDrain(): void
    {
        if ($this->registered) {
            return;
        }
        $this->registered = true;
        register_shutdown_function([$this, 'flush']);
    }

    /**
     * Shutdown handler: hand the response back to the client first (so the
     * blocking send costs the visitor nothing), then drain the queue.
     */
    public function flush(): void
    {
        if (function_exists('fastcgi_finish_request')) {
            @fastcgi_finish_request(); // phpcs:ignore
        }
        self::drain_queue($this->apiKey);
    }

    /**
     * Drain the spool: send the oldest batch to ingest, delete on success, bump
     * attempts (and drop past the retry limit) on failure, and enforce the hard
     * cap. Shared by the shutdown flush and the cron job. Safe to call with an
     * empty queue.
     */
    public static function drain_queue(string $apiKey): void
    {
        if ($apiKey === '' || !function_exists('wp_remote_post')) {
            return;
        }

        global $wpdb;
        $table = $wpdb->prefix . 'webdecoy_violation_queue';

        // Enforce the hard cap first: discard the oldest overflow so a prolonged
        // ingest outage can't grow the table without bound.
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name from $wpdb->prefix, not user input
        $total = (int) $wpdb->get_var("SELECT COUNT(*) FROM {$table}");
        if ($total > self::MAX_QUEUE) {
            $overflow = $total - self::MAX_QUEUE;
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
            $wpdb->query($wpdb->prepare("DELETE FROM {$table} ORDER BY id ASC LIMIT %d", $overflow));
        }

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        $rows = $wpdb->get_results($wpdb->prepare("SELECT id, payload FROM {$table} ORDER BY id ASC LIMIT %d", self::BATCH_SIZE));
        if (!$rows) {
            return;
        }

        $ids = [];
        $events = [];
        foreach ($rows as $row) {
            $decoded = json_decode((string) $row->payload, true);
            if (is_array($decoded)) {
                $events[] = $decoded;
                $ids[] = (int) $row->id;
            } else {
                // Unparseable row — drop it immediately.
                $wpdb->delete($table, ['id' => (int) $row->id]);
            }
        }

        if ($events === []) {
            return;
        }

        $ok = self::send($apiKey, $events);

        $idList = implode(',', array_map('intval', $ids));
        if ($ok) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
            $wpdb->query("DELETE FROM {$table} WHERE id IN ({$idList})");
        } else {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
            $wpdb->query("UPDATE {$table} SET attempts = attempts + 1 WHERE id IN ({$idList})");
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
            $wpdb->query($wpdb->prepare("DELETE FROM {$table} WHERE attempts >= %d", self::MAX_ATTEMPTS));
        }
    }

    /**
     * Blocking POST of a batch to ingest. Returns true on a 2xx response.
     *
     * @param array<int,array<string,mixed>> $events
     */
    private static function send(string $apiKey, array $events): bool
    {
        $response = wp_remote_post(self::ENDPOINT, [
            'timeout' => 3,
            'blocking' => true,
            'headers' => [
                'Content-Type' => 'application/json',
                'Authorization' => 'Bearer ' . $apiKey,
            ],
            'body' => wp_json_encode(['events' => $events]),
        ]);

        if (is_wp_error($response)) {
            return false;
        }
        $code = (int) wp_remote_retrieve_response_code($response);
        return $code >= 200 && $code < 300;
    }
}
