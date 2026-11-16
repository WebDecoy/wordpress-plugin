#!/usr/bin/env node
// Offline prototype: no network access, credentials, scheduler, or apply command.
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
import {parseArgs} from 'node:util';
const notes = 'Managed by WebDecoy';
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const protectedUAs = [
  'Mozilla/5.0 AppleWebKit/537.36 Chrome/130.0 Safari/537.36',
  'Mozilla/5.0 AppleWebKit/605.1.15 Version/18.0 Mobile/15E148 Safari/604.1',
  'Mozilla/5.0 Firefox/132.0',
  "WPVIP Let's Encrypt Certificates (+https://docs.wpvip.com/vip-user-agents)",
  'WordPress.com; https://acme.wordpress.com',
  'WordPress.com; https://clitools.wordpress.com',
  "Mozilla/5.0 (compatible; Let's Encrypt validation server; +https://www.letsencrypt.org)",
  'WPVIP Media (+https://docs.wpvip.com/vip-user-agents)',
  'VIP Webhooks (+https://docs.wpvip.com/vip-user-agents)',
  'VIP Webhooks (+https://vip.wordpress.com)',
  'Mozilla/5.0+(compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)',
  'Jetpack by WordPress.com',
];
function requireValue(ok, message) { if (!ok) throw new Error(message); }
function keys(value, allowed, required) {
  requireValue(value && typeof value === 'object' && !Array.isArray(value), 'Expected an object');
  requireValue(Object.keys(value).every(k => allowed.includes(k)), 'Unsupported input field; review schema before planning');
  requireValue(required.every(k => Object.hasOwn(value, k)), 'Missing required input field');
}
export function fingerprint(groups) {
  return createHash('sha256').update(JSON.stringify(groups)).digest('hex');
}
const mutation = 'mutation WebDecoyVipRestrictions($input: EdgeConfigUpdateUserAgentAccessRestrictionsInput) { updateUserAgentAccessRestrictions(input: $input) { groups { id notes } } }';
export function buildPlan(snapshot, policy, {now = Date.now()} = {}) {
  keys(snapshot, ['environmentId', 'capturedAt', 'groups'], ['environmentId', 'capturedAt', 'groups']);
  keys(policy, ['environmentId', 'managedGroupId', 'tokens', 'protectedUserAgents'], ['environmentId', 'managedGroupId', 'tokens', 'protectedUserAgents']);
  requireValue(Number.isInteger(snapshot.environmentId) && snapshot.environmentId > 0 && snapshot.environmentId <= 2147483647, 'Invalid VIP environment ID');
  requireValue(policy.environmentId === snapshot.environmentId, 'Environment mismatch');
  requireValue(typeof snapshot.capturedAt === 'string' && /T.*Z$/.test(snapshot.capturedAt), 'capturedAt must be UTC');
  const age = now - Date.parse(snapshot.capturedAt);
  requireValue(Number.isFinite(age) && age >= -30000 && age <= 15 * 60 * 1000, 'Snapshot is stale or future-dated; recapture the full configuration');
  requireValue(typeof policy.managedGroupId === 'string' && uuid.test(policy.managedGroupId), 'A stable managedGroupId UUID is required');
  requireValue(Array.isArray(snapshot.groups), 'Full groups array is required; missing data is not an empty list');
  const ids = new Set();
  const before = snapshot.groups.map(g => {
    keys(g, ['id', 'notes', 'rules', 'createdAt', 'updatedAt'], ['id', 'notes', 'rules']);
    requireValue(typeof g.id === 'string' && uuid.test(g.id) && !ids.has(g.id.toLowerCase()), 'Invalid or duplicate existing group ID');
    ids.add(g.id.toLowerCase());
    requireValue(typeof g.notes === 'string' && Array.isArray(g.rules) && g.rules.length > 0, 'Invalid existing group');
    requireValue(!(g.notes === notes && g.id.toLowerCase() !== policy.managedGroupId.toLowerCase()), 'Managed notes belong to another group; resolve ownership explicitly');
    requireValue(!(g.id.toLowerCase() === policy.managedGroupId.toLowerCase() && g.notes !== notes), 'Refusing to take over an unrelated group');
    const rules = g.rules.map(r => {
      keys(r, ['operator', 'value'], ['operator', 'value']);
      requireValue(['contains', 'equals'].includes(r.operator) && typeof r.value === 'string' && r.value.trim().length > 0, 'Invalid existing rule');
      return {operator:r.operator, value:r.value};
    });
    return {id:g.id, notes:g.notes, rules};
  });
  requireValue(Array.isArray(policy.protectedUserAgents) && policy.protectedUserAgents.every(s => typeof s === 'string' && s.length > 0), 'protectedUserAgents must be an explicit array');
  requireValue(Array.isArray(policy.tokens) && policy.tokens.length > 0, 'Empty token policy refused; removals need an explicit operator review');
  const tokens = [...new Set(policy.tokens.map(t => {
    requireValue(typeof t === 'string' && /^[a-z][a-z0-9._/-]{3,127}$/i.test(t), 'Use specific UA tokens (4–128 ASCII characters), not globs or expressions');
    const token = t.toLowerCase();
    requireValue(![...protectedUAs, ...policy.protectedUserAgents].some(ua => ua.toLowerCase().includes(token)), 'Token would match a protected browser or VIP service');
    return token;
  }))].sort();
  const managed = {id:policy.managedGroupId, notes, rules:tokens.map(value => ({operator:'contains', value}))};
  const existingIndex = before.findIndex(g => g.id.toLowerCase() === policy.managedGroupId.toLowerCase());
  const after = structuredClone(before);
  if (existingIndex < 0) after.push(managed); else after[existingIndex] = managed;
  requireValue(after.reduce((n,g) => n + g.rules.length, 0) <= 25, 'Combined configuration exceeds the default VIP 25-rule limit');
  const request = groups => ({query:mutation, variables:{input:{environmentId:snapshot.environmentId, groups}}});
  return {
    mode:'offline-preview', liveValidated:false, environmentId:snapshot.environmentId,
    capturedAt:snapshot.capturedAt, baselineSha256:fingerprint(before),
    changed:JSON.stringify(before) !== JSON.stringify(after),
    ruleCount:after.reduce((n,g) => n + g.rules.length, 0),
    before, after, proposedRequest:request(after), rollbackRequest:request(before),
    warnings:[
      'UA matching is a declared-name policy, not verified identity or behavioral detection.',
      'Rules apply globally at the VIP edge, including cached pages, media and logged-in requests.',
      'Read and compare the complete live configuration immediately before any manual write; this offline hash does not prevent races.',
      'Rollback is a full-list replacement too. Reconcile intervening changes before restoring.',
      'Browser/VIP sample protection is incomplete. Check the site’s actual HTTP logs and service UAs in staging.',
      'No crawler analytics ingestion or VIP integration approval is established by this plan.',
    ],
  };
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const {values} = parseArgs({options:{snapshot:{type:'string'}, policy:{type:'string'}}, strict:true});
    requireValue(values.snapshot && values.policy, 'Usage: node plan.mjs --snapshot snapshot.json --policy policy.json');
    const plan = buildPlan(JSON.parse(readFileSync(values.snapshot,'utf8')), JSON.parse(readFileSync(values.policy,'utf8')));
    process.stdout.write(JSON.stringify(plan,null,2)+'\n');
  } catch (error) {
    // Do not echo config contents or raw exception details from file/JSON parsing.
    process.stderr.write('Preview failed: '+(error instanceof SyntaxError ? 'Invalid JSON or arguments' : error.code ? 'Unable to read input file' : error.message)+'\n');
    process.exitCode = 1;
  }
}
