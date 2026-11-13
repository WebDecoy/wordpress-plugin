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
RESULTS=[]
RUN_ID=uuid.uuid4().hex[:8]
EXTENDED='--extended' in sys.argv
WAF_ENABLED='--waf-enabled' in sys.argv or EXTENDED
OUTPUT='matrix-extended-results.json' if EXTENDED else ('matrix-waf-enabled-results.json' if WAF_ENABLED else 'matrix-results.json')
BROWSER='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'
PLUGINS={'redirection':'redirection/redirection.php','hide':'wps-hide-login/wps-hide-login.php','wordfence':'wordfence/wordfence.php'}
def php(file,*args):
 r=subprocess.run(['docker','exec',CONTAINER,'php','-d','memory_limit=128M','-d','max_execution_time=15','/fixture/'+file,*args],capture_output=True,text=True,timeout=30)
 if r.returncode:raise RuntimeError(r.stderr+' '+r.stdout[-500:])
 try:return json.loads(r.stdout)
 except Exception:raise RuntimeError('Non-JSON fixture output: '+r.stdout[-600:])
def ctl(*args):
 if WAF_ENABLED and args and args[0]=='configure':args=(*args,'proxy')
 return php('control.php',*args)
def req(stage,name,path,browser=False,**extra):
 marker=RUN_ID+'-'+stage+'-'+name
 p={'path':path,'marker':marker,'jar':RUN_ID+'-'+stage+'-browser' if browser else marker}
 if browser:p.update(browser=True,ua=BROWSER)
 p.update(extra)
 if WAF_ENABLED:p['headers']=['X-Real-IP: 192.0.2.42']
 if EXTENDED:p['extended']=True
 response=php('client.php',json.dumps(p));response['detections']=ctl('query','Compat-'+marker)['rows'];response['stage']=stage;response['case']=name
 RESULTS.append(response);return response
def expect(r,condition,detail):
 if not condition:raise AssertionError(r['marker']+': '+detail+' '+json.dumps(r))
def flags(r,flag):return any(flag in json.loads(row['flags'])['flags'] for row in r['detections'])
def total_gptbot(data):return sum(int(r['hits']) for r in data['rows'] if r['agent_id']=='gptbot')
scenarios=[('baseline',[]),('redirection',['redirection']),('hide',['hide']),('wordfence',['wordfence']),('all',['redirection','hide','wordfence']),('all-reverse',['wordfence','hide','redirection'])]
if WAF_ENABLED:scenarios=[('all-waf-enabled',['redirection','hide','wordfence']),('all-waf-enabled-reverse',['redirection','hide','wordfence'])]
if EXTENDED:scenarios=[('all-extended',['redirection','hide','wordfence']),('all-extended-reverse',['redirection','hide','wordfence'])]
metadata=[]
try:
 for stage,names in scenarios:
  active=['webdecoy/webdecoy.php']+[PLUGINS[n] for n in names]
  ctl('plugins',','.join(active));ctl('configure','monitor');ctl('eval','reset-fixture-blocks.php')
  if 'redirection' in names:ctl('eval','configure-redirection.php')
  if WAF_ENABLED:ctl('eval','configure-wordfence-block.php');ctl('eval','configure-wordfence-proxy.php')
  if stage=='all-reverse':ctl('order',','.join([PLUGINS[n] for n in names]+['webdecoy/webdecoy.php']))
  if WAF_ENABLED:ctl('order',','.join(sorted(active,reverse=stage.endswith('reverse'))))
  record={'stage':stage,'active':ctl('state')['plugins'],'wordfence':ctl('eval','inspect-wordfence.php') if 'wordfence' in names else None};metadata.append(record)
  r=req(stage,'browser','/compat-target/',True);expect(r,r['status']==200 and r['target_content'] and not r['critical_error'],'browser page')
  r=req(stage,'bot','/compat-target/');expect(r,r['status']==200 and r['target_content'] and flags(r,'cli_tool'),'bot scoring and real SQL record')
  marker=stage+'-test';r=req(stage,'test','/compat-target/',ua='WebDecoy-Test/1.0 Compat-'+RUN_ID+'-'+marker);expect(r,r['status']==403 and r['test_receipt'] and flags(r,'test_trigger'),'reserved test control')
  before=ctl('eval','crawler-counts.php');r=req(stage,'ai','/compat-target/',ua='Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)');after=ctl('eval','crawler-counts.php')
  r['ai_count_before']=before;r['ai_count_after']=after
  expect(r,r['status']==200 and total_gptbot(after)==total_gptbot(before)+1,'AI counter increment')
  expect(r,all(row['verification']!='verified' for row in after['rows'] if row['agent_id']=='gptbot'),'synthetic GPTBot must not be verified')
  login='/compat-login/' if 'hide' in names else '/wp-login.php'
  r=req(stage,'login-form',login,True);expect(r,r['status']==200 and r['login_form'],'login form')
  r=req(stage,'login-submit',login,True,post={'log':'compat-admin','pwd':'fixture-admin-password','wp-submit':'Log In','redirect_to':'http://127.0.0.1:8080/wp-admin/','testcookie':'1'})
  expect(r,r['status'] in (302,303) and '/wp-admin/' in r['headers'].get('location',''),'successful administrator login')
  r=req(stage,'admin','/wp-admin/',True);expect(r,r['status']==200 and r['admin_screen'] and not r['critical_error'],'authenticated admin access')
  r=req(stage,'ajax-no-nonce','/wp-admin/admin-ajax.php',post={'action':'webdecoy_client_detection'})
  expect(r,r['status'] in (400,403) and not r['detections'],'unauthenticated AJAX refusal without general front-end record')
  r=req(stage,'trap-monitor','/compat-trap/');expect(r,r['status']==404 and flags(r,'tripwire_rule'),'monitor records and allows routing')
  ctl('configure','block');r=req(stage,'trap-block','/compat-trap/');expect(r,r['status']==403 and flags(r,'tripwire_rule'),'block mode denies and records')
  if WAF_ENABLED:
   r=req(stage,'repeat-block','/compat-target/');expect(r,r['status']==403 and not r['target_content'] and not r['detections'],'existing IP block denies without rescoring')
  ctl('configure','monitor')
  if WAF_ENABLED:
   wf_marker=RUN_ID+'-'+stage+'-wf-rule-block'
   r=req(stage,'wf-rule-block','/compat-target/',ua='python-requests/2.32.3 Compat-wf-rule-block Compat-'+wf_marker)
   expect(r,r['status']==503 and r['wordfence_block'] and not r['target_content'] and not r['detections'],'Wordfence manual block before WebDecoy detection')
  if 'redirection' in names:
   r=req(stage,'redirect','/compat-old/');expect(r,r['status']==301 and r['headers'].get('location')=='http://127.0.0.1:8080/compat-target/' and flags(r,'cli_tool'),'Redirection redirect retains detection')
  if 'hide' in names:
   r=req(stage,'hidden-login','/wp-login.php');expect(r,r['status']==404 and not r['login_form'] and flags(r,'cli_tool'),'default login hidden while detection recorded')
  print(stage+': PASS',flush=True)
except Exception as error:
 print('FAILED: '+str(error),flush=True)
 (ROOT/OUTPUT).write_text(json.dumps({'complete':False,'error':str(error),'scenarios':metadata,'requests':RESULTS},indent=2)+'\n')
 raise
access=php('read-access.php')
for response in RESULTS:
 receipts=[row for row in access if row['marker']==response['marker']]
 expect(response,len(receipts)==1,'one independent server receipt')
 receipt=receipts[0]
 expect(response,receipt['status']==response['status'],'server and client HTTP status agree')
 if EXTENDED:
  expect(response,receipt.get('auto_prepend') is True,'native auto_prepend_file actually ran')
  if response['case']=='wf-rule-block':expect(response,receipt.get('wp_init_count') is None,'Wordfence block before WordPress loads')
 response['server_receipt']=receipt
(ROOT/OUTPUT).write_text(json.dumps({'complete':True,'scenarios':metadata,'requests':RESULTS},indent=2)+'\n')
print(str(len(RESULTS))+' HTTP request cases passed',flush=True)
