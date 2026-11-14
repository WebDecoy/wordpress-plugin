<?php
// CLI-only setup/inspection. No HTTP endpoint is exposed.
if(PHP_SAPI!=='cli')exit(1);
$cmd=$argv[1]??'state';
define('WEBDECOY_DISABLE',true);
if($cmd==='install')define('WP_INSTALLING',true);
$_SERVER['HTTP_HOST']='127.0.0.1:8080';$_SERVER['REQUEST_URI']='/';$_SERVER['SERVER_PORT']='8080';$_SERVER['REQUEST_METHOD']='GET';$_SERVER['REMOTE_ADDR']='127.0.0.1';$_SERVER['HTTP_USER_AGENT']='Compatibility control';
require '/site/wp-load.php'; require_once ABSPATH.'wp-admin/includes/plugin.php';
if($cmd==='install'){
 require_once ABSPATH.'wp-admin/includes/upgrade.php';
 if(!is_blog_installed())wp_install('WebDecoy offline compatibility','compat-admin','compat@example.invalid',false,'','fixture-admin-password');
 update_option('permalink_structure','/%postname%/');
 $id=wp_insert_post(['post_title'=>'Compatibility target','post_name'=>'compat-target','post_type'=>'page','post_status'=>'publish','post_content'=>'COMPAT_TARGET_CONTENT']);
 echo json_encode(['installed'=>is_blog_installed(),'target_id'=>$id]);exit;
}
if($cmd==='plugins'){
 $want=array_filter(explode(',',$argv[2]??'webdecoy/webdecoy.php'));
 foreach(get_option('active_plugins',[]) as $plugin)if(!in_array($plugin,$want,true))deactivate_plugins($plugin,true);
 foreach($want as $plugin){$e=activate_plugin($plugin);if(is_wp_error($e))throw new Exception($e->get_error_message());}
 echo json_encode(['active'=>get_option('active_plugins')]);exit;
}
if($cmd==='configure'){
 $o=get_option('webdecoy_options',[]);$o['enabled']=true;$o['api_key']='';$o['monitor_mode']=($argv[2]??'monitor')==='monitor';
 $o['trusted_proxies']=($argv[3]??'')==='proxy'?'127.0.0.1':'';
 $o['scanner_enabled']=false;$o['honeytoken_enabled']=false;$o['traps_fake_plugins']=false;$o['traps_xmlrpc']=false;
 $o['rate_limit_enabled']=false;$o['tripwire_enabled']=true;$o['tripwire_include_defaults']=false;$o['tripwire_paths']=['/compat-trap/'];$o['tripwire_prefixes']=[];$o['tripwire_patterns']=[];$o['tripwire_action']='block';$o['tripwire_response']='block';$o['tripwire_dry_run']=false;
 update_option('webdecoy_options',$o); update_option('whl_page','compat-login');update_option('whl_redirect_admin','compat-hidden');
 echo json_encode(['monitor_mode'=>$o['monitor_mode']]);exit;
}
if($cmd==='order'){ update_option('active_plugins',explode(',',$argv[2]));echo json_encode(['active'=>get_option('active_plugins')]);exit; }
if($cmd==='query'){
 global $wpdb;$marker=$argv[2]??'';
 $rows=$wpdb->get_results($wpdb->prepare("SELECT id,ip_address,user_agent,score,threat_level,source,flags FROM {$wpdb->prefix}webdecoy_detections WHERE user_agent LIKE %s ORDER BY id",'%'.$wpdb->esc_like($marker).'%'),ARRAY_A);
 echo json_encode(['rows'=>$rows,'db_error'=>$wpdb->last_error]);exit;
}
if($cmd==='state'){
 global $wp_version;echo json_encode(['request_counts_supported'=>class_exists('WebDecoy_Request_Counts'),'wp'=>$wp_version,'php'=>PHP_VERSION,'plugins'=>get_option('active_plugins',[]),'webdecoy'=>get_option('webdecoy_options',[]),'wordfence_api_key_configured'=>class_exists('wfConfig') ? (bool)wfConfig::get('apiKey','') : null]);exit;
}
if($cmd==='eval'){
 // Trusted fixture file supplied by the test runner, never an HTTP parameter.
 require '/fixture/'.$argv[2];exit;
}
throw new Exception('Unknown control command');
