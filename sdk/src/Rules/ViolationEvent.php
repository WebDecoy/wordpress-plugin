<?php

declare(strict_types=1);

namespace WebDecoy\Rules;

/**
 * A single non-ALLOW rule outcome, recorded for reporting.
 *
 * The wire shape matches the ingest service's `ViolationEventRequest`
 * (ingest/internal/handlers/violation_handler.go) and @webdecoy/node's
 * `ViolationEvent` so the same /api/v1/sdk/violations/batch endpoint accepts
 * events from either SDK.
 */
class ViolationEvent
{
    /** @var string */
    public $rule;

    /** @var string ALLOW/DENY/THROTTLE (dry-run tripwires record ALLOW here per node). */
    public $action;

    /** @var string */
    public $ip;

    /** @var string|null */
    public $path;

    /** @var string|null */
    public $method;

    /** @var string|null */
    public $userAgent;

    /** @var string|null */
    public $reason;

    /**
     * The request's wd_clearance token, attached ONLY to tripwire violations so
     * the backend can bind the deception hit to the actor's device fingerprint
     * and deny it durably. Heuristic rules never carry it. (WebDecoy/app#136.)
     *
     * @var string|null
     */
    public $clearance;

    /** @var array<string,mixed>|null */
    public $metadata;

    /** @var bool */
    public $dryRun;

    /** @var string ISO-8601 timestamp. */
    public $timestamp;

    /**
     * @param array<string,mixed>|null $metadata
     */
    public function __construct(
        string $rule,
        string $action,
        string $ip,
        ?string $path,
        ?string $method,
        ?string $userAgent,
        ?string $reason,
        ?string $clearance,
        ?array $metadata,
        bool $dryRun,
        string $timestamp
    ) {
        $this->rule = $rule;
        $this->action = $action;
        $this->ip = $ip;
        $this->path = $path;
        $this->method = $method;
        $this->userAgent = $userAgent;
        $this->reason = $reason;
        $this->clearance = $clearance;
        $this->metadata = $metadata;
        $this->dryRun = $dryRun;
        $this->timestamp = $timestamp;
    }

    /**
     * Serialize to the ingest batch wire format. Field names match the Go
     * struct's JSON tags exactly (rule, action, ip, path, method, userAgent,
     * reason, clearance, metadata, dryRun, timestamp).
     *
     * @return array<string,mixed>
     */
    public function toApiPayload(): array
    {
        $payload = [
            'rule' => $this->rule,
            'action' => $this->action,
            'ip' => $this->ip,
            'dryRun' => $this->dryRun,
            'timestamp' => $this->timestamp,
        ];

        // Optional fields are omitted when null so the payload stays compact and
        // matches the pointer/omitempty semantics on the Go side.
        if ($this->path !== null) {
            $payload['path'] = $this->path;
        }
        if ($this->method !== null) {
            $payload['method'] = $this->method;
        }
        if ($this->userAgent !== null) {
            $payload['userAgent'] = $this->userAgent;
        }
        if ($this->reason !== null) {
            $payload['reason'] = $this->reason;
        }
        if ($this->clearance !== null) {
            $payload['clearance'] = $this->clearance;
        }
        if ($this->metadata !== null) {
            $payload['metadata'] = $this->metadata;
        }

        return $payload;
    }
}
