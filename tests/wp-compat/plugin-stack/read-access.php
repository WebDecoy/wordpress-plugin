<?php
$rows=[];foreach(file('/scratch/server-access.jsonl',FILE_IGNORE_NEW_LINES|FILE_SKIP_EMPTY_LINES)?:[] as $line){$r=json_decode($line,true);if($r && !empty($r['marker']))$rows[]=$r;}echo json_encode($rows);
