<?php
$install=\Redirection\Database\Database::get_latest_database()->install();
if(is_wp_error($install))throw new Exception($install->get_error_message());
global $wpdb;
if ($wpdb->get_var("SELECT id FROM {$wpdb->prefix}redirection_items WHERE url='/compat-old/' LIMIT 1")) { echo json_encode(['redirection_installed'=>true,'rule_exists'=>true]); return; }
$redirect=\Redirection\Redirect\Redirect::create(['url'=>'/compat-old/','action_type'=>'url','action_code'=>301,'action_data'=>['url'=>'http://127.0.0.1:8080/compat-target/'],'match_type'=>'url','group_id'=>1]);
if(is_wp_error($redirect))throw new Exception($redirect->get_error_message());
echo json_encode(['redirection_installed'=>true,'rule_created'=>true]);
