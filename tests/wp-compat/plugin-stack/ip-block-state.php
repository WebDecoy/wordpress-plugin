<?php
global $wpdb;echo json_encode(['blocks'=>$wpdb->get_results("SELECT ip_address,reason FROM {$wpdb->prefix}webdecoy_blocked_ips",ARRAY_A),'db_error'=>$wpdb->last_error]);
