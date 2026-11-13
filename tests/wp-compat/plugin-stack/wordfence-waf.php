<?php
// Same bootstrap path used by Wordfence auto_prepend_file configuration.
// The observer runs first solely to retain a receipt for pre-WordPress blocks.
require_once '/fixture/access.php';
define('WFWAF_LOG_PATH','/site/wp-content/wflogs/');
require_once '/site/wp-content/plugins/wordfence/waf/bootstrap.php';
