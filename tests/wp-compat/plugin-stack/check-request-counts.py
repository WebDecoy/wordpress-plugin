import subprocess,json,time,sys,uuid,os
from pathlib import Path
ROOT=Path(os.environ['WP_COMPAT_OUTPUT']).resolve()
ROOT.mkdir(parents=True,exist_ok=True)
CONTAINER=os.environ['WP_COMPAT_CONTAINER']
# Refuse unlabeled containers, writable roots, or exposed host ports.
probe=subprocess.run(['docker','inspect','--format','{{index .Config.Labels "webdecoy.task"}}|{{.HostConfig.ReadonlyRootfs}}|{{json .HostConfig.PortBindings}}|{{.HostConfig.NetworkMode}}',CONTAINER],capture_output=True,text=True,check=True,timeout=10).stdout.strip().split('|')
if not (probe[0].startswith('wp-stack-compat') and probe[1]=='true' and probe[2] in ('{}','null') and probe[3].startswith('container:')):
 raise SystemExit('Use only a labeled, read-only, private-loopback compatibility container.')
db_id=probe[3][len('container:'):]
db_mode=subprocess.run(['docker','inspect','--format','{{.HostConfig.NetworkMode}}',db_id],capture_output=True,text=True,check=True,timeout=10).stdout.strip()
if db_mode!='none':raise SystemExit('The shared database namespace must use network none.')

from concurrent.futures import ThreadPoolExecutor
RUN_ID=uuid.uuid4().hex[:8]
REQUESTS=[]
CHECKS=[]
MEASUREMENTS={}
BROWSER='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'
def php(file,*args):
 result=subprocess.run(['docker','exec',CONTAINER,'php','-d','memory_limit=128M','-d','max_execution_time=15','/fixture/'+file,*args],capture_output=True,text=True,timeout=30)
 if result.returncode:raise RuntimeError(result.stderr+' '+result.stdout[-700:])
 return json.loads(result.stdout)
def ctl(*args):return php('control.php',*args)
def action(name,*args):return ctl('eval','request-counts.php',name,*args)
def state():
 s=action('summary');assert s['db_error']=='',s
 return s
def configure(**patch):return action('configure',json.dumps(patch))
def request(name,path='/compat-target/',browser=False,**extra):
 marker=RUN_ID+'-'+name
 p={'path':path,'marker':marker,'jar':RUN_ID+'-browser' if browser else marker,'headers':['X-Real-IP: 192.0.2.42']}
 if browser:p.update(browser=True,ua=BROWSER)
 p.update(extra)
 result=php('client.php',json.dumps(p));assert not result['critical_error'],result
 REQUESTS.append(result)
 return result
def check(name):CHECKS.append(name);print('PASS '+name,flush=True)
def reset():action('reset')
def same(expected,actual):assert expected==actual,(expected,actual)

try:
 ctl('plugins','webdecoy/webdecoy.php');ctl('configure','monitor','proxy');reset()
 s=state();assert s['today']['available'];same('2.11.1',s['db_version']);assert s['today']['started_at']>0
 same([],s['rows']);same(['bucket','outcome','hits'],s['columns']);check('new schema and tracking-start metadata')

 # Reserved 403 setup tests create a labeled finding, never a request denial.
 r=request('setup',ua='WebDecoy-Test/1.0 Compat-'+RUN_ID+'-setup');same(403,r['status']);assert r['test_receipt']
 s=state();same(0,s['today']['blocked']);same([],s['rows']);check('setup-test 403 excluded')

 # Login scoring and a honeypot can both withhold enforcement in one request.
 reset();configure(monitor_mode=True,min_score_to_block=40,tripwire_response='block')
 request('monitor-form','/wp-login.php',jar=RUN_ID+'-dedupe')
 reset();before=state()
 r=request('monitor','/wp-login.php',jar=RUN_ID+'-dedupe',post={'log':'compat-admin','pwd':'fixture-admin-password','testcookie':'1','webdecoy_hp_login':'synthetic-fixture'})
 same(302,r['status']);after=state()
 same(1,after['today']['withheld']);same(0,after['today']['blocked']);assert after['legacy_withheld_actions']-before['legacy_withheld_actions']>=2
 MEASUREMENTS['monitor']={'request_count':after['today']['withheld'],'withheld_actions':after['legacy_withheld_actions']-before['legacy_withheld_actions']}
 same(1,sum(int(row['hits']) for row in after['rows']));check('multiple monitor decisions deduplicated per request')

 reset();configure(monitor_mode=False,min_score_to_block=75)
 r=request('first-block','/compat-trap/');same(403,r['status']);same(1,state()['today']['blocked'])
 before=state();r=request('repeat-block');same(403,r['status']);after=state();same(2,after['today']['blocked']);same(before['today']['detections'],after['today']['detections'])
 check('fresh and repeated IP blocks counted without duplicate findings')

 # Two server processes share the SQL table; no read-modify-write lost updates.
 before=state()
 def hit(index):return request('concurrent-'+str(index),extended=bool(index%2))
 with ThreadPoolExecutor(max_workers=4) as workers:responses=list(workers.map(hit,range(40)))
 assert all(r['status']==403 for r in responses)
 after=state();same(40,after['today']['blocked']-before['today']['blocked']);same(before['today']['detections'],after['today']['detections'])
 same(42,sum(int(row['hits']) for row in after['rows'] if row['outcome']=='blocked'))
 assert 1 <= len([row for row in after['rows'] if row['outcome']=='blocked']) <= 2  # UTC-hour boundary may split the run
 MEASUREMENTS['repeat_blocks']={'initial_and_repeat_count':2,'concurrent_requests':40,'counter_delta':after['today']['blocked']-before['today']['blocked'],'detection_delta':after['today']['detections']-before['today']['detections'],'aggregate_rows':len([row for row in after['rows'] if row['outcome']=='blocked'])}
 check('40 concurrent repeat blocks reconcile with hourly aggregates')

 reset();configure(tripwire_response='challenge',monitor_mode=False)
 r=request('challenge','/compat-trap/');same(403,r['status']);s=state();same(1,s['today']['challenged']);same(0,s['today']['blocked'])
 check('challenge responses separate from blocks')

 reset();configure(tripwire_enabled=False,tripwire_response='block',rate_limit_enabled=True,rate_limit_requests=1,rate_limit_window=60,rate_limit_dry_run=False,min_score_to_block=75)
 same(200,request('rate-first')['status']);same(429,request('rate-second')['status']);same(429,request('rate-third')['status'])
 s=state();same(2,s['today']['throttled']);same(0,s['today']['blocked']);same(0,s['today']['withheld'])
 check('actual 429 throttles separate from 403 blocks')

 reset();configure(rate_limit_enabled=False,tripwire_enabled=True,monitor_mode=True)
 r=request('ajax-no-nonce','/wp-admin/admin-ajax.php',post={'action':'webdecoy_client_detection'});same(403,r['status']);same([],state()['rows'])
 action('cli-mark');same([],state()['rows']);check('nonce rejection and CLI operations excluded')

 # Authenticated screens must show the real counter, not a detection-row proxy.
 configure(monitor_mode=False);same(403,request('ui-seed','/compat-trap/')['status']);configure(monitor_mode=True)
 same(200,request('login-form','/wp-login.php',True)['status'])
 r=request('login-submit','/wp-login.php',True,post={'log':'compat-admin','pwd':'fixture-admin-password','wp-submit':'Log In','redirect_to':'http://127.0.0.1:8080/wp-admin/','testcookie':'1'});same(302,r['status'])
 expected=state()['today'];r=request('dashboard','/wp-admin/',True);same(200,r['status']);same(expected['blocked'],r['widget_counts']['blocked']);same(expected['detections'],r['widget_counts']['detections']);assert r['tracking_start_visible']
 r=request('statistics','/wp-admin/admin.php?page=webdecoy-statistics',True);same(200,r['status'])
 for metric in ['detections','blocked','throttled','challenged','withheld']:same(expected[metric],r['request_count_cells'][metric]['1'])
 check('authenticated dashboard and Statistics show separate measured counts')

 # Simulate an old install. Denials must survive unavailable storage, then retry.
 before=state()['today']['detections'];action('pre-upgrade');configure(monitor_mode=False)
 root=['docker','exec',db_id,'mariadb','-uroot','-pfixture-root-password','-e']
 try:
  subprocess.run(root+["REVOKE CREATE ON wp.* FROM 'wp'@'%';"],check=True,capture_output=True,text=True,timeout=15)
  r=request('failed-upgrade-ui','/wp-admin/admin.php?page=webdecoy-statistics',True);same(200,r['status'])
  same('2.11.0',state()['db_version']);assert state()['today']['available'] is False
  same(403,request('no-storage-block')['status'])
 finally:
  subprocess.run(root+["GRANT CREATE ON wp.* TO 'wp'@'%';"],check=True,capture_output=True,text=True,timeout=15)
 configure(monitor_mode=True)
 r=request('retry-upgrade','/wp-admin/admin.php?page=webdecoy-statistics',True);same(200,r['status']);s=state();same('2.11.1',s['db_version']);assert s['today']['available'];same(0,s['today']['blocked']);same(before,s['today']['detections'])
 started=s['today']['started_at'];action('upgrade');same(started,state()['today']['started_at'])
 check('failed upgrade preserves protection and retries without backfilling')

 reset();retention=action('retention');same(0,retention['old_rows']);same(7,retention['boundary']);same(7,retention['summary']['blocked'])
 check('30 UTC calendar-day retention preserves the boundary bucket')

 access=php('read-access.php')
 for response in REQUESTS:
  receipts=[row for row in access if row['marker']==response['marker']]
  same(1,len(receipts));same(response['status'],receipts[0]['status'])
 check('all HTTP results matched independent server receipts')
 if '--uninstall' in sys.argv:
  removed=action('uninstall');same(False,removed['counter_table_present']);same(False,removed['start_metadata_present'])
  check('actual WordPress uninstall removes counters and start metadata')
except Exception as error:
 (ROOT/'request-counts-results.json').write_text(json.dumps({'complete':False,'checks':CHECKS,'measurements':MEASUREMENTS,'requests':REQUESTS,'error':str(error)},indent=2)+'\n')
 raise
(ROOT/'request-counts-results.json').write_text(json.dumps({'complete':True,'checks':CHECKS,'measurements':MEASUREMENTS,'requests':REQUESTS,'final':state()},indent=2)+'\n')
print(f'{len(CHECKS)} checks passed; {len(REQUESTS)} HTTP requests reconciled',flush=True)
