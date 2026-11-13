<?php
// Test-only simulated reverse proxy; no public listener exists.
wfConfig::set('howGetIPs','HTTP_X_REAL_IP');
wfConfig::set('howGetIPs_trusted_proxies','127.0.0.1');
wfWAF::getInstance()->getStorageEngine()->setConfig('howGetIPs','HTTP_X_REAL_IP','synced');
wfWAF::getInstance()->getStorageEngine()->setConfig('howGetIPs_trusted_proxies_unified','127.0.0.1','synced');
echo json_encode(['header'=>'HTTP_X_REAL_IP','proxy'=>'127.0.0.1']);
