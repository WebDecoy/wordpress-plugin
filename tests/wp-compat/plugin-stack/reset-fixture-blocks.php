<?php
global $wpdb;$n=$wpdb->query("DELETE FROM {$wpdb->prefix}webdecoy_blocked_ips WHERE ip_address IN ('127.0.0.1','192.0.2.42')");wp_cache_flush();echo json_encode(['removed_fixture_blocks'=>$n]);
