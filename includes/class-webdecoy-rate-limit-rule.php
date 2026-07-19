<?php

declare(strict_types=1);

use WebDecoy\Rules\RuleContext;
use WebDecoy\Rules\RuleResult;
use WebDecoy\Rules\RuleInterface;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Rate-limit rule — a {@see RuleInterface} so rate limiting flows through the
 * same engine as tripwires and filters, and produces a proper THROTTLE (429 +
 * Retry-After + X-RateLimit-* headers) instead of merely nudging the bot score.
 *
 * Faithful to @webdecoy/node's RateLimitRule (increment-then-check, THROTTLE
 * default, retryAfter metadata), adapted to PHP's stateless model:
 *
 *  - fixed window  → DB (webdecoy_rate_limits), survives across processes.
 *  - sliding window → the classic two-bucket weighted approximation in a
 *    persistent object cache (Redis/Memcached). Most serious WP hosts run one,
 *    giving shared cross-process state node's in-memory limiter can't keep
 *    across restarts. When no persistent object cache is present, sliding
 *    transparently falls back to the fixed-window DB path.
 *
 *  keyBy: 'ip' (default), 'ip_route' (IP + path), or 'user' (logged-in user id,
 *  falling back to IP for anonymous requests).
 */
class WebDecoy_Rate_Limit_Rule implements RuleInterface
{
    /** Object-cache group for sliding-window buckets. */
    private const CACHE_GROUP = 'webdecoy_rl';

    /** @var int */
    private $limit;

    /** @var int */
    private $window;

    /** @var string 'fixed' | 'sliding' */
    private $algorithm;

    /** @var string 'ip' | 'ip_route' | 'user' */
    private $keyBy;

    /** @var string DENY | THROTTLE */
    private $action;

    /** @var bool */
    private $dryRun;

    /**
     * @param array<string,mixed> $config
     */
    public function __construct(array $config)
    {
        $this->limit = max(1, (int) ($config['limit'] ?? 60));
        $this->window = max(1, (int) ($config['window'] ?? 60));

        $algorithm = $config['algorithm'] ?? 'fixed';
        $this->algorithm = in_array($algorithm, ['fixed', 'sliding'], true) ? $algorithm : 'fixed';

        $keyBy = $config['keyBy'] ?? 'ip';
        $this->keyBy = in_array($keyBy, ['ip', 'ip_route', 'user'], true) ? $keyBy : 'ip';

        $this->action = ($config['action'] ?? RuleResult::THROTTLE) === RuleResult::DENY ? RuleResult::DENY : RuleResult::THROTTLE;
        $this->dryRun = !empty($config['dryRun']);
    }

    public function getName(): string
    {
        return 'rate-limit:' . $this->limit . '/' . $this->window . 's';
    }

    public function evaluate(RuleContext $context): RuleResult
    {
        $key = $this->resolveKey($context);

        $useSliding = $this->algorithm === 'sliding'
            && function_exists('wp_using_ext_object_cache')
            && wp_using_ext_object_cache();

        $res = $useSliding ? $this->checkSliding($key) : $this->checkFixed($key);

        $remaining = max(0, $this->limit - (int) $res['current']);
        $resetIn = max(1, (int) $res['resetAt'] - time());

        if (!$res['allowed']) {
            return new RuleResult(
                $this->dryRun ? RuleResult::ALLOW : $this->action,
                $this->getName(),
                'Rate limit exceeded: ' . $res['current'] . '/' . $this->limit . ' requests in ' . $this->window . 's window',
                [
                    'current' => (int) $res['current'],
                    'max' => $this->limit,
                    'window' => $this->window,
                    'remaining' => 0,
                    'retryAfter' => $resetIn,
                    'resetAt' => (int) $res['resetAt'],
                    'dryRun' => $this->dryRun,
                ]
            );
        }

        // Allowed: still carry the counters so the caller can emit X-RateLimit-*.
        return new RuleResult(RuleResult::ALLOW, $this->getName(), null, [
            'current' => (int) $res['current'],
            'max' => $this->limit,
            'remaining' => $remaining,
            'resetAt' => (int) $res['resetAt'],
        ]);
    }

    /**
     * Build the counting key. Composite keys are hashed to a fixed length so
     * they fit the DB column; a plain IP is kept readable for stats/debugging.
     */
    private function resolveKey(RuleContext $context): string
    {
        if ($this->keyBy === 'user') {
            $uid = function_exists('get_current_user_id') ? (int) get_current_user_id() : 0;
            if ($uid > 0) {
                return 'u' . $uid;
            }
            return $context->ip; // anonymous → fall back to IP
        }

        if ($this->keyBy === 'ip_route') {
            $path = explode('?', $context->path, 2)[0];
            return substr(sha1($context->ip . '|' . $path), 0, 40);
        }

        return $context->ip;
    }

    /**
     * Fixed-window check-and-increment via the DB. Increment first, then compare
     * (node parity: count > max after increment → denied).
     *
     * @return array{allowed:bool,current:int,resetAt:int}
     */
    private function checkFixed(string $key): array
    {
        $limiter = new WebDecoy_Rate_Limiter($this->limit, $this->window);
        return $limiter->check_and_increment($key);
    }

    /**
     * Sliding-window via a two-bucket weighted approximation in the object cache.
     * estimate = prev_bucket_count * overlap_fraction + current_bucket_count.
     *
     * @return array{allowed:bool,current:int,resetAt:int}
     */
    private function checkSliding(string $key): array
    {
        $now = time();
        $win = $this->window;
        $idx = intdiv($now, $win);
        $currKey = $key . ':' . $idx;
        $prevKey = $key . ':' . ($idx - 1);

        $curr = wp_cache_incr($currKey, 1, self::CACHE_GROUP);
        if ($curr === false) {
            wp_cache_add($currKey, 1, self::CACHE_GROUP, $win * 2);
            $curr = 1;
        }

        $prev = (int) wp_cache_get($prevKey, self::CACHE_GROUP);
        $elapsed = $now % $win;
        $weight = ($win - $elapsed) / $win;
        $estimate = ($prev * $weight) + $curr;

        return [
            'allowed' => $estimate <= $this->limit,
            'current' => (int) ceil($estimate),
            'resetAt' => ($idx + 1) * $win,
        ];
    }
}
