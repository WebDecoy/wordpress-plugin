<?php
echo json_encode(['api_key_configured'=>(bool)wfConfig::get('apiKey',''),'is_paid'=>(bool)wfConfig::get('isPaid',false),'waf_status'=>wfWAF::getInstance()->getStorageEngine()->getConfig('wafStatus'),'waf_rules_file_present'=>is_file(WP_CONTENT_DIR.'/wflogs/rules.php'),'basic_protection'=>defined('WFWAF_OPERATIONAL')?WFWAF_OPERATIONAL:null]);
