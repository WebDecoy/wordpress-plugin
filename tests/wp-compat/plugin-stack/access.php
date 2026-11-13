<?php
if(!isset($GLOBALS['compat_access_started'])) {
 $GLOBALS['compat_access_started']=true;
 $receipt=['marker'=>$_SERVER['HTTP_X_COMPAT_CASE']??'','method'=>$_SERVER['REQUEST_METHOD'],'uri'=>$_SERVER['REQUEST_URI'],'ua'=>$_SERVER['HTTP_USER_AGENT']??''];
 register_shutdown_function(static function()use($receipt){$receipt['status']=http_response_code();$receipt['auto_prepend']=defined('WFWAF_AUTO_PREPEND') && WFWAF_AUTO_PREPEND;$receipt['wp_init_count']=function_exists('did_action')?did_action('init'):null;file_put_contents('/scratch/server-access.jsonl',json_encode($receipt)."\n",FILE_APPEND|LOCK_EX);});
}
