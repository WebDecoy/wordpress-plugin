<?php
// Disposable offline compatibility site. These credentials are test-only.
define('DB_NAME','wp'); define('DB_USER','wp'); define('DB_PASSWORD','fixture-db-password'); define('DB_HOST','127.0.0.1');
define('DB_CHARSET','utf8mb4'); define('DB_COLLATE','');
define('AUTH_KEY','local-compat-auth'); define('SECURE_AUTH_KEY','local-compat-secure'); define('LOGGED_IN_KEY','local-compat-login'); define('NONCE_KEY','local-compat-nonce');
define('AUTH_SALT','local-compat-auth-salt'); define('SECURE_AUTH_SALT','local-compat-secure-salt'); define('LOGGED_IN_SALT','local-compat-login-salt'); define('NONCE_SALT','local-compat-nonce-salt');
$table_prefix='wp_';
define('WP_HOME','http://127.0.0.1:8080'); define('WP_SITEURL','http://127.0.0.1:8080');
define('WP_DEBUG',true); define('WP_DEBUG_DISPLAY',false); define('WP_DEBUG_LOG','/scratch/wp-debug.log');
define('DISABLE_WP_CRON',true); define('WP_HTTP_BLOCK_EXTERNAL',true); define('AUTOMATIC_UPDATER_DISABLED',true); define('DISALLOW_FILE_MODS',true);
define('WP_MEMORY_LIMIT','128M'); define('WP_MAX_MEMORY_LIMIT','128M');
if(!defined('ABSPATH'))define('ABSPATH','/site/');
require_once ABSPATH.'wp-settings.php';
