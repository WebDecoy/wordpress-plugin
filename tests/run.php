<?php

declare(strict_types=1);

/**
 * Dependency-free test entry point. Runs every tests/*Test.php file and exits
 * non-zero on any failure. Usage: php tests/run.php
 */

require __DIR__ . '/bootstrap.php';

foreach (glob(__DIR__ . '/*Test.php') ?: [] as $file) {
    require $file;
}

exit(TestRunner::summary());
