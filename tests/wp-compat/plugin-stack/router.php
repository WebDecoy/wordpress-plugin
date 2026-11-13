<?php
require_once '/fixture/access.php';
$path=rawurldecode(parse_url($_SERVER['REQUEST_URI'],PHP_URL_PATH) ?: '/');
if($path !== '/' && is_file('/site'.$path))return false;
require '/site/index.php';
