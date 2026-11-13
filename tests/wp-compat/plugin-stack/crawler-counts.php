<?php
global $wpdb;$t=WebDecoy_Crawler_Visits::table();echo json_encode(['rows'=>$wpdb->get_results("SELECT agent_id,verification,SUM(hits) AS hits FROM {$t} GROUP BY agent_id,verification",ARRAY_A),'db_error'=>$wpdb->last_error]);
