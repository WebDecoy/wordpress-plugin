const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const scanner = fs.readFileSync(path.join(__dirname, '../public/js/webdecoy-scanner.js'), 'utf8');
const init = '  init();\n})();';
assert.ok(scanner.includes(init));
const fixture = scanner.replace(init, '  window.submitReport = submitScannerReport;\n})();');
const origin = 'https://fixture.example';
const report = 'webdecoy_client_detection';
const refresh = 'webdecoy_scanner_nonce';
const expired = { status: 403, json: async () => ({ data: { code: 'invalid_scanner_nonce' } }) };
const renewed = { ok: true, json: async () => ({ success: true, data: { nonce: 'current' } }) };

function start(responses, ajaxUrl = origin + '/wp-admin/admin-ajax.php', requestClass = Request) {
    const requests = [];
    const window = {
        location: { origin, href: origin + '/cached-page/' },
        fetch: async (url, options) => {
            assert.equal(url, ajaxUrl);
            assert.equal(options.mode, 'same-origin');
            assert.equal(options.redirect, 'error');
            assert.equal(options.keepalive, true);
            const body = new URLSearchParams(options.body);
            requests.push(body);
            const response = responses[requests.length - 1];
            if (response instanceof Error) throw response;
            return response;
        }
    };
    vm.runInNewContext(fixture, {
        window, URL, FormData, Request: requestClass,
        webdecoyScanner: { enabled: true, ajaxUrl, nonce: 'cached' },
        navigator: { sendBeacon: (url, body) => {
            assert.equal(url, ajaxUrl);
            requests.push(body);
        } }
    });
    return { send: () => window.submitReport({ s: 25 }), requests };
}

test('reloads the nonce once and retries the original report', async () => {
    const { send, requests } = start([expired, renewed, expired]);
    await send();
    assert.deepEqual(requests.map(body => body.get('action')), [report, refresh, report]);
    assert.deepEqual(requests.map(body => body.get('nonce')), ['cached', null, 'current']);
    assert.equal(requests[0].get('detection'), requests[2].get('detection'));
});

test('leaves acknowledged, unrelated, rate-limited, and ambiguous failures alone', async () => {
    for (const outcome of [
        { status: 200 },
        { status: 403, json: async () => ({ data: { code: 'different_error' } }) },
        { status: 429 },
        new Error('connection closed')
    ]) {
        const { send, requests } = start([outcome]);
        await send();
        assert.deepEqual(requests.map(body => body.get('action')), [report]);
    }
});

test('requires a successful renewal before retrying', async () => {
    const { send, requests } = start([expired, { ok: false, status: 403 }]);
    await send();
    assert.deepEqual(requests.map(body => body.get('action')), [report, refresh]);
});

test('keeps the existing beacon submission for a separate admin origin', async () => {
    const { send, requests } = start([], 'https://admin.fixture.example/wp-admin/admin-ajax.php');
    await send();
    assert.deepEqual(requests.map(body => body.get('action')), [report]);
    assert.equal(requests[0].get('nonce'), 'cached');
});

test('keeps beacon delivery when fetch has no keepalive support', async () => {
    const { send, requests } = start([], origin + '/wp-admin/admin-ajax.php', function LegacyRequest() {});
    await send();
    assert.deepEqual(requests.map(body => body.get('action')), [report]);
});
