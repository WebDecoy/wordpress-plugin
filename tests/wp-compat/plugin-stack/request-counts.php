<?php
// Loaded only by the CLI control in the labeled disposable fixture.
if(PHP_SAPI !== 'cli' || !defined('ABSPATH'))exit(1);
global $wpdb;
$action=$argv[3]??'summary';
if($action==='configure'){
 $o=get_option('webdecoy_options',[]);$patch=json_decode($argv[4],true,512,JSON_THROW_ON_ERROR);
 update_option('webdecoy_options',array_merge($o,$patch));echo json_encode(['configured'=>array_keys($patch)]);return;
}
if($action==='reset'){
 $wpdb->query("DELETE FROM {$wpdb->prefix}webdecoy_request_counts");
 $wpdb->query("DELETE FROM {$wpdb->prefix}webdecoy_blocked_ips WHERE ip_address IN ('127.0.0.1','192.0.2.42')");
 $wpdb->query("DELETE FROM {$wpdb->prefix}webdecoy_rate_limits");
 echo json_encode(['reset'=>true]);return;
}
if($action==='pre-upgrade'){
 $wpdb->query("DROP TABLE {$wpdb->prefix}webdecoy_request_counts");
 delete_option('webdecoy_request_counts_started_at');update_option('webdecoy_db_version','2.11.0');
 echo json_encode(['db_version'=>get_option('webdecoy_db_version')]);return;
}
if($action==='upgrade'){
 WebDecoy_Activator::maybe_upgrade();
 echo json_encode(['db_version'=>get_option('webdecoy_db_version'),'started_at'=>(int)get_option('webdecoy_request_counts_started_at',0)]);return;
}
if($action==='cli-mark'){
 WebDecoy_Request_Counts::mark('blocked');WebDecoy_Request_Counts::flush();echo json_encode(['marked_cli'=>true]);return;
}
if($action==='uninstall'){
 define('WP_UNINSTALL_PLUGIN','webdecoy/webdecoy.php');
 require '/site/wp-content/plugins/webdecoy/uninstall.php';
 $name=$wpdb->prefix.'webdecoy_request_counts';
 echo json_encode(['counter_table_present'=>$wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s',$wpdb->esc_like($name)))===$name,'start_metadata_present'=>get_option('webdecoy_request_counts_started_at',false)!==false]);return;
}
if($action==='retention'){
 $window=WebDecoy_Request_Counts::window(30);$table=WebDecoy_Request_Counts::table();
 $old=gmdate('Y-m-d H:00:00',strtotime($window['from'].' UTC')-3600);
 $wpdb->query($wpdb->prepare("INSERT INTO {$table} (bucket,outcome,hits) VALUES (%s,'blocked',99),(%s,'blocked',7) ON DUPLICATE KEY UPDATE hits=VALUES(hits)",$old,$window['from']));
 WebDecoy_Request_Counts::prune();
 echo json_encode(['old_rows'=>(int)$wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM {$table} WHERE bucket < %s",$window['from'])),'boundary'=>(int)$wpdb->get_var($wpdb->prepare("SELECT hits FROM {$table} WHERE bucket=%s AND outcome='blocked'",$window['from'])),'summary'=>WebDecoy_Request_Counts::summary(30)]);return;
}
if($action!=='summary')throw new Exception('Unknown counter fixture action');
$table=WebDecoy_Request_Counts::table();
$summary=WebDecoy_Request_Counts::summary(1);
echo json_encode(['today'=>$summary,'week'=>WebDecoy_Request_Counts::summary(7),'month'=>WebDecoy_Request_Counts::summary(30),'columns'=>$summary['available']?$wpdb->get_col("SHOW COLUMNS FROM {$table}"):[],'rows'=>$summary['available']?$wpdb->get_results("SELECT bucket,outcome,hits FROM {$table} ORDER BY bucket,outcome",ARRAY_A):[],'legacy_withheld_actions'=>(int)(get_option('webdecoy_suppressed_actions',[])[gmdate('Y-m-d')]['count']??0),'db_version'=>get_option('webdecoy_db_version'),'db_error'=>$wpdb->last_error]);
