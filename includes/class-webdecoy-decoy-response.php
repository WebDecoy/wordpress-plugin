<?php

declare(strict_types=1);

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Deceptive tripwire responses (deception layer, beyond @webdecoy/node parity).
 *
 * WordPress owns the whole HTTP response, so a tripwire can *deceive* a scanner
 * instead of just denying it. A deceived scanner keeps digging (each fetch
 * another confidence-100 violation feeding enforcement) rather than pivoting
 * tools. Modes:
 *
 *   - block   : 403 (default; handled by the caller, not here)
 *   - notfound: 404 — indistinguishable from an unprotected site
 *   - decoy   : 200 with believable fake content containing UNIQUE per-site
 *               canary credentials
 *   - tarpit  : a slow-drip response that burns scanner time (bounded)
 *
 * Safety rails: decoy content is generated ENTIRELY from templates seeded by a
 * per-site secret — it never reads a real configuration value. If a template
 * can't be produced for the requested path, it fails closed (returns false so
 * the caller serves the normal 403).
 *
 * Canary credentials are deterministic per site and recomputable, so any later
 * *use* of one (e.g. a login attempt with the fake DB password) is attributable
 * evidence of exfiltration — see {@see is_canary_credential()}.
 */
class WebDecoy_Decoy_Response
{
    /** Max wall-clock seconds a tarpit will hold a connection. */
    private const TARPIT_MAX_SECONDS = 10;

    /**
     * Per-site canary secret (lazily created). Distinct from other secrets so
     * canaries can't be derived from an unrelated leaked value.
     */
    private static function secret(): string
    {
        $secret = get_option('webdecoy_canary_secret', '');
        if (!is_string($secret) || $secret === '') {
            $secret = bin2hex(random_bytes(16));
            add_option('webdecoy_canary_secret', $secret, '', 'yes');
        }
        return $secret;
    }

    private static function derive(string $label, int $len = 16): string
    {
        return substr(hash_hmac('sha256', $label, self::secret()), 0, $len);
    }

    /**
     * The full set of canary credentials for this site (deterministic).
     *
     * @return array<string,string>
     */
    public static function canaries(): array
    {
        return [
            'db_name' => 'wp_' . self::derive('db_name', 6),
            'db_user' => 'wpuser_' . self::derive('db_user', 6),
            'db_password' => 'Wd' . self::derive('db_password', 20),
            'db_host' => 'localhost',
            'auth_key' => self::derive('auth_key', 40),
            'admin_user' => 'admin_' . self::derive('admin_user', 6),
            'admin_password' => 'Wd' . self::derive('admin_password', 18),
            'author_user' => 'editor_' . self::derive('author_user', 6),
            'aws_key' => 'AKIA' . strtoupper(self::derive('aws_key', 16)),
            'aws_secret' => self::derive('aws_secret', 40),
        ];
    }

    /**
     * Is a submitted credential value one of this site's canaries? A match means
     * the value could only have come from a decoy we served — strong exfil
     * evidence. Compared with hash_equals to avoid timing leaks.
     */
    public static function is_canary_credential(string $value): bool
    {
        if ($value === '') {
            return false;
        }
        foreach (self::canaries() as $canary) {
            if (hash_equals($canary, $value)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Serve a deceptive response for a tripwire hit and exit. Returns false
     * (without emitting anything) when the mode is 'block' or when a decoy can't
     * be produced for this path — the caller then serves the normal 403.
     *
     * @return bool false = fall back to the default block
     */
    public function serve(string $path, string $mode): bool
    {
        if ($mode === 'notfound') {
            $this->serve_404();
            return true; // exits
        }

        if ($mode === 'tarpit') {
            $this->serve_tarpit();
            return true; // exits
        }

        if ($mode === 'decoy') {
            $content = $this->decoy_for($path);
            if ($content === null) {
                return false; // no believable template — fail closed to 403
            }
            $this->serve_body($content['body'], $content['type']);
            return true; // exits
        }

        return false; // 'block' or unknown — caller handles
    }

    /**
     * Build believable fake content for a known bait path, embedding canaries.
     * Returns null when the path has no template (caller falls back to 403).
     *
     * @return array{body:string,type:string}|null
     */
    private function decoy_for(string $path): ?array
    {
        $p = strtolower($path);
        $c = self::canaries();

        // Fake .env
        if (substr($p, -4) === '.env' || strpos($p, '/.env') !== false) {
            $body = "APP_ENV=production\n"
                . "APP_DEBUG=false\n"
                . "APP_KEY=base64:" . base64_encode($c['auth_key']) . "\n"
                . "DB_CONNECTION=mysql\n"
                . "DB_HOST={$c['db_host']}\n"
                . "DB_PORT=3306\n"
                . "DB_DATABASE={$c['db_name']}\n"
                . "DB_USERNAME={$c['db_user']}\n"
                . "DB_PASSWORD={$c['db_password']}\n"
                . "AWS_ACCESS_KEY_ID={$c['aws_key']}\n"
                . "AWS_SECRET_ACCESS_KEY={$c['aws_secret']}\n";
            return ['body' => $body, 'type' => 'text/plain'];
        }

        // Fake wp-config backup
        if (strpos($p, 'wp-config') !== false) {
            $body = "<?php\n"
                . "// WordPress configuration\n"
                . "define('DB_NAME', '{$c['db_name']}');\n"
                . "define('DB_USER', '{$c['db_user']}');\n"
                . "define('DB_PASSWORD', '{$c['db_password']}');\n"
                . "define('DB_HOST', '{$c['db_host']}');\n"
                . "define('AUTH_KEY', '{$c['auth_key']}');\n"
                . "\$table_prefix = 'wp_';\n";
            // Serve as text/plain so it isn't executed anywhere and is readable.
            return ['body' => $body, 'type' => 'text/plain'];
        }

        // Fake SQL dump
        if (substr($p, -4) === '.sql' || strpos($p, 'backup') !== false || strpos($p, 'dump') !== false) {
            $body = "-- MySQL dump\n"
                . "-- Host: {$c['db_host']}    Database: {$c['db_name']}\n"
                . "CREATE TABLE `wp_users` (\n"
                . "  `ID` bigint(20) unsigned NOT NULL AUTO_INCREMENT,\n"
                . "  `user_login` varchar(60) NOT NULL,\n"
                . "  `user_pass` varchar(255) NOT NULL,\n"
                . "  PRIMARY KEY (`ID`)\n"
                . ") ENGINE=InnoDB;\n"
                . "INSERT INTO `wp_users` VALUES "
                . "(1,'{$c['admin_user']}','\$P\$B" . self::derive('pw_hash', 30) . "');\n";
            return ['body' => $body, 'type' => 'text/plain'];
        }

        // Fake phpinfo
        if (strpos($p, 'phpinfo') !== false) {
            $body = "<!DOCTYPE html><html><head><title>phpinfo()</title></head><body>"
                . "<h1>PHP Version 7.4.33</h1>"
                . "<table><tr><td>System</td><td>Linux web01 5.4.0</td></tr>"
                . "<tr><td>DOCUMENT_ROOT</td><td>/var/www/html</td></tr>"
                . "<tr><td>DB_USER</td><td>{$c['db_user']}</td></tr></table>"
                . "</body></html>";
            return ['body' => $body, 'type' => 'text/html'];
        }

        return null; // no believable template for this path
    }

    /**
     * The canaries served for a given path (for recording in detection metadata).
     * Empty when the path has no decoy template.
     *
     * @return array<string,string>
     */
    public function served_canaries(string $path): array
    {
        return $this->decoy_for($path) === null ? [] : self::canaries();
    }

    private function serve_404(): void
    {
        nocache_headers();
        status_header(404);
        header('Content-Type: text/html; charset=UTF-8');
        echo '<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>';
        exit;
    }

    private function serve_body(string $body, string $type): void
    {
        nocache_headers();
        status_header(200);
        header('Content-Type: ' . $type . '; charset=UTF-8');
        // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- template content, not user input
        echo $body;
        exit;
    }

    /**
     * Slow-drip response to burn scanner time, streamed and bounded. Ties up a
     * PHP worker for up to TARPIT_MAX_SECONDS — hence off by default and
     * documented as such.
     */
    private function serve_tarpit(): void
    {
        nocache_headers();
        status_header(200);
        header('Content-Type: text/html; charset=UTF-8');

        // Cap by both our limit and any configured max_execution_time headroom.
        $maxExec = (int) ini_get('max_execution_time');
        $budget = self::TARPIT_MAX_SECONDS;
        if ($maxExec > 0) {
            $budget = min($budget, max(1, $maxExec - 2));
        }

        echo '<!DOCTYPE html><html><head><title>Loading…</title></head><body>';
        $start = time();
        $i = 0;
        while ((time() - $start) < $budget) {
            echo '<!-- ' . str_repeat('.', 8) . " {$i} -->\n"; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- template-generated decoy content, contains no user input
            if (function_exists('flush')) {
                @flush(); // phpcs:ignore
            }
            $i++;
            usleep(500000); // 0.5s between drips
        }
        echo '</body></html>';
        exit;
    }
}
