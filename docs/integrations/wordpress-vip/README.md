# WordPress VIP integration prototype

Status: **offline policy preview, not VIP-certified or live-validated**. No network calls or apply command. This developer tool lives under `docs/`, which `build.sh` excludes from distributed plugin ZIPs. It adds no WordPress request overhead.

This prototype converts an explicitly selected list of crawler User-Agent tokens into a proposed VIP edge restriction configuration. It does not fetch a WebDecoy policy feed, ingest VIP logs, verify agent identities, or install the WordPress plugin. Each is a separate integration capability.

## Preview a synthetic example

Requires Node.js22+. From the repository root:

```sh
node --test docs/integrations/wordpress-vip/plan.test.mjs
# Make a fresh copy of the synthetic snapshot; do not misdate real snapshots.
node --input-type=module -e 'import fs from "node:fs"; const p="docs/integrations/wordpress-vip/examples/snapshot.json";const s=JSON.parse(fs.readFileSync(p));s.capturedAt=new Date().toISOString();fs.writeFileSync("/tmp/webdecoy-vip-example.json",JSON.stringify(s));'
node docs/integrations/wordpress-vip/plan.mjs \
  --snapshot /tmp/webdecoy-vip-example.json \
  --policy docs/integrations/wordpress-vip/examples/policy.json \
  > /tmp/webdecoy-vip-plan.json
```

The sample environment42, UUIDs and `WebDecoy-VIP-Test/1.0` token are synthetic. This is not a recommended production blocklist. A stale example intentionally fails unless you create a fresh synthetic copy.

## Inputs and output

For a real preview, an authorized VIP operator must capture the **complete** current restriction list for the specific environment and map it to the snapshot format. A missing or partial response must never become `groups: []`. Existing groups require their real IDs. Optional API timestamps are stripped from mutation inputs. Unsupported fields/operators fail rather than being silently discarded. The snapshot timestamp is supplied by the operator; it is not proof of completeness or authenticity.

Choose specific crawler tokens using the publisher's policy, WebDecoy evidence and recent HTTP request logs. UA tokens are case-insensitive substring rules: a claimed name does not verify identity, intent or harm. There is no automatic recommendation to block all AI traffic. Add actual monitoring/support/browser UAs to `protectedUserAgents`; built-in examples only catch obvious mistakes and cannot guarantee zero false positives.

Keep a stable UUID `managedGroupId` for WebDecoy's group. Repeated runs update that ID, preserving unrelated groups. Group ID/note collisions are rejected. The planner enforces the default25 total rule entries across all groups; it does not assume VIP has granted a higher limit.

The JSON plan contains `before`, `after`, a baseline fingerprint, and GraphQL request bodies for the proposed change and rollback. **Neither request is sent.** Store plans privately: they expose environment policy even though they contain no API credentials.

## Operator validation before any write

1. Obtain a VIP nonproduction environment and an authorized operator. This prototype needs no credentials; never put credentials in a policy file or commit.
2. Capture the full configuration and verify environment identity. Preview the policy. Inspect every preserved rule and every proposed token.
3. Compare proposed rules against recent actual HTTP logs and all required VIP/support services. VIP restrictions are global: cached/uncached pages, logged-in traffic, assets and API endpoints can be affected.
4. Immediately before a manual mutation, recapture the list and compare the normalized groups to `before`. If changed, regenerate and re-review. The hash is an offline comparison aid, **not an atomic concurrency lock**. Coordinate with other administrators to avoid concurrent writes.
5. If separately approved, an authorized operator submits the reviewed GraphQL request through VIP's supported API tooling. Observe propagation and test the selected test UA and ordinary browser/service UAs. Record response codes and preserve the before-state.
6. Rollback also replaces the complete list. Re-read and reconcile any intervening third-party edits before submitting a rollback; blindly replaying an old snapshot can erase other administrators' changes.

No cron workflow, network client or live deployment is included. Do not describe the prototype as an approved Integration Center integration. An end-to-end VIP pilot and partner review remain required.

## Coverage architecture

- **WordPress plugin:** only PHP-reaching requests. Full-page edge cache hits and edge rejections do not execute plugin code.
- **VIP edge restriction plan:** control of declared User-Agent names, including cached requests. No analytics delivered by this planner.
- **Future observability connector:** evaluate VIP HTTP request log export/Log Shipping with VIP. Confirm eligible sources, coverage, delivery format and data handling before claiming complete edge visibility.

## Official references (checked November15,2026)

- [VIP user-agent restrictions: scope, rule limit, services and propagation](https://docs.wpvip.com/security-controls/user-agent-restrictions/)
- [VIP update mutation](https://docs.wpvip.com/vip-api/reference/security/operations/mutations/update-user-agent-access-restrictions)
- [Group input schema](https://docs.wpvip.com/vip-api/reference/common/types/inputs/edge-config-update-user-agent-group-input)
- [VIP service user agents](https://docs.wpvip.com/infrastructure/vip-user-agents/)
- [Plugin evaluation](https://docs.wpvip.com/plugins/third-party-plugins/)
- [Git-based plugin installation](https://docs.wpvip.com/plugins/installing-plugins/)
- [Log Shipping](https://docs.wpvip.com/logs/log-shipping/)
- [Technology partner intake](https://wpvip.com/partners/technology-partners/become-a-partner/)

## Runtime standards follow-up

See [remediation](remediation.md) for code changes, reproducible scan commands, reviewed exceptions, and remaining VIP pilot requirements. The original baseline is preserved. A passing static check is not VIP certification.
