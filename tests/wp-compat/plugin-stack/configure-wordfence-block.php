<?php
wfConfig::set('wafStatus','enabled');
wfWAF::getInstance()->getStorageEngine()->setConfig('wafStatus','enabled');
$found=false;foreach(wfBlock::patternBlocks(true) as $pattern){if($pattern->userAgent==='*Compat-wf-rule-block*')$found=true;}
if(!$found)wfBlock::createPattern('Offline compatibility user-agent block','','','*Compat-wf-rule-block*','',600);
echo json_encode(['waf_status'=>wfWAF::getInstance()->getStorageEngine()->getConfig('wafStatus'),'pattern_count'=>count(wfBlock::patternBlocks(true)),'license_configured'=>(bool)wfConfig::get('apiKey','')]);
