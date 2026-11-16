import {test} from 'node:test';
import assert from 'node:assert/strict';
import {buildPlan} from './plan.mjs';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
const s=()=>JSON.parse(readFileSync(new URL('./examples/snapshot.json',import.meta.url)));
const p=()=>JSON.parse(readFileSync(new URL('./examples/policy.json',import.meta.url)));
const now=Date.parse('2026-11-15T12:01:00Z');
const plan=(a=s(),b=p())=>buildPlan(a,b,{now});
test('preserves unrelated groups, produces reversible payload and never mutates input',()=>{
 const a=s(),b=p(),original=JSON.stringify(a);const out=plan(a,b);
 assert.deepEqual(out.after[0],a.groups[0]);assert.equal(JSON.stringify(a),original);
 assert.deepEqual(out.rollbackRequest.variables.input.groups,out.before);
 assert.deepEqual(out.proposedRequest.variables.input.groups,out.after);
 assert.equal(out.mode,'offline-preview');assert.equal(out.liveValidated,false);
});
test('updates only its stable ID and is idempotent',()=>{
 const a=s();a.groups=plan().after;
 const out=plan(a);assert.equal(out.changed,false);assert.equal(out.after.length,2);
});
test('normalizes case and duplicate tokens without adding duplicate rules',()=>{
 const b=p();b.tokens=['ExampleCrawler','examplecrawler'];assert.equal(plan(s(),b).after.at(-1).rules.length,1);
});
for(const [name,change] of [
 ['missing groups',a=>delete a.groups],['stale snapshot',a=>a.capturedAt='2026-11-14T12:00:00Z'],
 ['future snapshot',a=>a.capturedAt='2026-11-16T12:00:00Z'],['invalid environment',a=>a.environmentId='42'],
 ['unknown group field',a=>a.groups[0].action='allow'],['unknown rule operator',a=>a.groups[0].rules[0].operator='regex'],
 ['duplicate group ID',a=>a.groups.push(a.groups[0])],['missing existing rules',a=>delete a.groups[0].rules],
]) test('rejects '+name,()=>{const a=s();change(a);assert.throws(()=>plan(a));});
for(const token of ['Mozilla','Safari','Chrome','Firefox','WPVIP','WordPress.com','Jetpack','UptimeRobot','VIP','*','bot','a\nbot'])
 test('rejects broad or protected token '+JSON.stringify(token),()=>{const b=p();b.tokens=[token];assert.throws(()=>plan(s(),b));});
test('checks the total limit across unrelated and managed groups',()=>{
 const a=s();a.groups[0].rules=Array.from({length:25},(_,i)=>({operator:'equals',value:'Existing'+i}));assert.throws(()=>plan(a),/25-rule/);
});
test('accepts exactly 25 total rules',()=>{
 const a=s();a.groups[0].rules=Array.from({length:24},(_,i)=>({operator:'equals',value:'Existing'+i}));assert.equal(plan(a).ruleCount,25);
});
test('refuses ownership collisions, empty policy and environment mismatch',()=>{
 const a=s(),b=p();a.groups[0].notes='Managed by WebDecoy';assert.throws(()=>plan(a,b),/ownership/);
 a.groups[0].id=b.managedGroupId;a.groups[0].notes='Not ours';assert.throws(()=>plan(a,b),/take over/);
 b.tokens=[];assert.throws(()=>plan(s(),b));b.environmentId=99;assert.throws(()=>plan(s(),b));
});
test('protects site-specific service agents',()=>{
 const b=p();b.tokens=['MyMonitor'];b.protectedUserAgents=['MyMonitor/1.0'];assert.throws(()=>plan(s(),b),/protected/);
});
test('CLI refuses apply flag; no accidental mutation interface',()=>{
 const r=spawnSync(process.execPath,[new URL('./plan.mjs',import.meta.url).pathname,'--apply'],{encoding:'utf8'});
 assert.equal(r.status,1);assert.equal(r.stdout,'');
});
