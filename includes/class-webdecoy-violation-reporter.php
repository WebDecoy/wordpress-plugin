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

    /**
     * Option used as a drain lock (WebDecoy/app#1245). Every request that
     * recorded a violation drains at shutdown, and the cron drains too; two
     * drains at once read the same oldest rows and sent them twice.
     * add_option() is atomic on the option name, so only one holder wins.
     */
    private const DRAIN_LOCK = 'webdecoy_violation_drain_lock';

    /** A lock older than this belonged to a request that died; it is taken over. */
    private const DRAIN_LOCK_TTL = 60;

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
        // While WebDecoy is refusing work, keep the spool (it is capped) rather
        // than spend its rows' attempts on requests that cannot succeed.
        if (class_exists('WebDecoy_Detection_Sender') && WebDecoy_Detection_Sender::backing_off()) {
            return;
        }
        if (!self::acquire_drain_lock()) {
            return;
        }
        try {
            self::drain_locked($apiKey);
        } finally {
            delete_option(self::DRAIN_LOCK);
        }
    }

    /**
     * Take the drain lock, or take over one left by a request that died.
     */
    private static function acquire_drain_lock(): bool
    {
        if (add_option(self::DRAIN_LOCK, (string) time(), '', 'no')) {
            return true;
        }
        $held = (int) get_option(self::DRAIN_LOCK, 0);
        if ($held > 0 && time() - $held < self::DRAIN_LOCK_TTL) {
            return false;
        }
        delete_option(self::DRAIN_LOCK);
        return add_option(self::DRAIN_LOCK, (string) time(), '', 'no');
    }

    private static function drain_locked(string $apiKey): void
    {
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

        $result = self::send($apiKey, $events);

        $idList = implode(',', array_map('intval', $ids));
        if ($result === 'refused') {
            // Ingest is unavailable, not the batch: keep its attempts for when
            // it is back. The shared pause stops further drains meanwhile.
            return;
        }
        if ($result === 'ok') {
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
     * Blocking POST of a batch to ingest: 'ok' on 2xx, 'refused' when ingest is
     * unavailable (no answer, 429, 5xx; this also pauses cloud calls), and
     * 'rejected' for any other answer.
     *
     * @param array<int,array<string,mixed>> $events
     */
    private static function send(string $apiKey, array $events): string
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

        $code = is_wp_error($response) ? 0 : (int) wp_remote_retrieve_response_code($response);
        if ($code === 0 || $code === 429 || $code >= 500) {
            if (class_exists('WebDecoy_Detection_Sender')) {
                WebDecoy_Detection_Sender::note_refusal();
            }
            return 'refused';
        }
        return ($code >= 200 && $code < 300) ? 'ok' : 'rejected';
    }
}
