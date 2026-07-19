<?php

declare(strict_types=1);

/**
 * Minimal, dependency-free test bootstrap + runner.
 *
 * The plugin has no PHPUnit setup; these parity tests exercise the pure SDK
 * rule primitives (no WordPress required) so they can run anywhere PHP does:
 *
 *   php tests/run.php
 */

// Load the pure SDK rule classes directly — no WordPress, no Composer needed.
$src = dirname(__DIR__) . '/sdk/src/Rules/';
require_once $src . 'RuleInterface.php';
require_once $src . 'RuleContext.php';
require_once $src . 'RuleResult.php';
require_once $src . 'RuleEngineResult.php';
require_once $src . 'ViolationEvent.php';
require_once $src . 'RuleEngine.php';
require_once $src . 'TripwireRule.php';

final class TestRunner
{
    /** @var int */
    public static $passed = 0;
    /** @var int */
    public static $failed = 0;
    /** @var string */
    private static $current = '';

    public static function test(string $name, callable $fn): void
    {
        self::$current = $name;
        try {
            $fn();
        } catch (\Throwable $e) {
            self::$failed++;
            echo "  ✗ {$name}\n    " . $e->getMessage() . "\n";
            return;
        }
        self::$passed++;
        echo "  ✓ {$name}\n";
    }

    /**
     * @param mixed $expected
     * @param mixed $actual
     */
    public static function assertSame($expected, $actual, string $msg = ''): void
    {
        if ($expected !== $actual) {
            throw new \Exception(
                ($msg !== '' ? $msg . ': ' : '') .
                'expected ' . var_export($expected, true) . ', got ' . var_export($actual, true)
            );
        }
    }

    public static function assertTrue(bool $cond, string $msg = ''): void
    {
        if (!$cond) {
            throw new \Exception($msg !== '' ? $msg : 'expected true, got false');
        }
    }

    public static function assertNull($value, string $msg = ''): void
    {
        if ($value !== null) {
            throw new \Exception(($msg !== '' ? $msg . ': ' : '') . 'expected null, got ' . var_export($value, true));
        }
    }

    public static function assertMatches(string $pattern, string $subject, string $msg = ''): void
    {
        if (preg_match($pattern, $subject) !== 1) {
            throw new \Exception(($msg !== '' ? $msg . ': ' : '') . "'{$subject}' does not match {$pattern}");
        }
    }

    public static function summary(): int
    {
        echo "\n" . self::$passed . ' passed, ' . self::$failed . " failed\n";
        return self::$failed === 0 ? 0 : 1;
    }
}
