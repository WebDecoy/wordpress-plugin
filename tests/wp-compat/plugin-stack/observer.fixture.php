<?php
/** Plugin Name: Offline compatibility request observer (test only) */
add_filter('pre_wp_mail', '__return_true');
if (PHP_SAPI === 'cli') return;
$compat_original_uri = $_SERVER['REQUEST_URI'] ?? '';
$compat_marker = $_SERVER['HTTP_X_COMPAT_CASE'] ?? '';
register_shutdown_function(static function () use ($compat_original_uri, $compat_marker) {
    $error=error_get_last();
    $row=['marker'=>$compat_marker,'original_uri'=>$compat_original_uri,'final_uri'=>$_SERVER['REQUEST_URI'] ?? '', 'status'=>http_response_code(),'init'=>did_action('init'),'webdecoy_registered'=>function_exists('webdecoy') ? has_action('init',[webdecoy(),'early_check']) : false];
    if($error && in_array($error['type'],[E_ERROR,E_PARSE,E_COMPILE_ERROR],true))$row['fatal']=$error['message'];
    file_put_contents('/scratch/request-observer.jsonl',json_encode($row)."\n",FILE_APPEND|LOCK_EX);
});
