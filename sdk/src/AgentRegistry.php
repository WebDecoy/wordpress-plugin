<?php

declare(strict_types=1);

namespace WebDecoy;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * The canonical crawler registry, generated from WebDecoy/app.
 *
 * The plugin used to carry its own table of known bots. That table and the
 * one the dashboard, the edge sensor and the Node SDK use drifted apart, so a
 * crawler could be named one thing in this plugin and another in the report
 * about it. `registry/agents.generated.php` is the shared table in PHP form,
 * and this class is the only reader of it.
 *
 * Matching is by lower-cased User-Agent containing an agent's pattern, first
 * hit in file order. The order is the same one every other consumer uses,
 * which is what keeps the answers equal.
 */
final class AgentRegistry
{
    /**
     * The artifact shape this class was written against. A regenerated file
     * with a different shape is refused rather than misread.
     */
    public const SCHEMA = 2;

    /** @var array<string,mixed>|null */
    private static $table = null;

    /**
     * Load the generated table once per process.
     *
     * @return array{schema:int,agent_count:int,categories:list<string>,agents:list<array<string,mixed>>}
     */
    private static function table(): array
    {
        if (self::$table === null) {
            $loaded = require __DIR__ . '/registry/agents.generated.php';
            if (!is_array($loaded) || (int) ($loaded['schema'] ?? 0) !== self::SCHEMA) {
                throw new \RuntimeException(
                    'WebDecoy agent registry schema mismatch: expected ' . self::SCHEMA
                    . ', found ' . (string) ($loaded['schema'] ?? 'none')
                );
            }
            self::$table = $loaded;
        }
        return self::$table;
    }

    /**
     * Identify the agent a User-Agent claims to be.
     *
     * A claim, not a verification: the User-Agent header is whatever the
     * client chose to send. Callers that need more ask GoodBotList to verify
     * the source address.
     *
     * @return array{id:string,name:string,category:string,behavior:string,organization:string,pattern:string,website:string,robots_name:string}|null
     */
    public static function match(string $userAgent): ?array
    {
        if ($userAgent === '') {
            return null;
        }
        $ua = strtolower($userAgent);
        foreach (self::table()['agents'] as $agent) {
            foreach ($agent['patterns'] as $pattern) {
                if ($pattern !== '' && strpos($ua, $pattern) !== false) {
                    return [
                        'id' => (string) $agent['id'],
                        'name' => (string) $agent['name'],
                        'category' => (string) $agent['category'],
                        'behavior' => (string) ($agent['behavior'] ?? ''),
                        'organization' => (string) $agent['organization'],
                        'pattern' => (string) $pattern,
                        'website' => (string) $agent['website'],
                        'robots_name' => (string) $agent['robots_name'],
                    ];
                }
            }
        }
        return null;
    }

    /**
     * Every agent, in match order.
     *
     * @return list<array<string,mixed>>
     */
    public static function all(): array
    {
        return self::table()['agents'];
    }

    /**
     * The category vocabulary the table uses (the customer-facing names).
     *
     * @return list<string>
     */
    public static function categories(): array
    {
        return self::table()['categories'];
    }

    /** How many agents the table carries, for drift checks. */
    public static function count(): int
    {
        return (int) self::table()['agent_count'];
    }
}
