/**
 * WebDecoy Challenge Page script
 *
 * Solves a SHA-256 proof-of-work puzzle in a Web Worker, then verifies the
 * solution server-side before allowing access. Loaded on the standalone
 * challenge interstitial via wp_register_script() + wp_print_scripts();
 * configuration and translated strings arrive in the webdecoyChallengeConfig
 * global attached with wp_add_inline_script().
 *
 * @package WebDecoy
 */
(function() {
    'use strict';

    var config = window.webdecoyChallengeConfig;
    if (!config) {
        return;
    }

    var challenge = config.challenge;
    var ajaxUrl = config.ajaxUrl;
    var wpNonce = config.nonce;
    var redirectUrl = config.redirectUrl;
    var i18n = config.i18n;

    var box = document.getElementById('challengeBox');
    var statusEl = document.getElementById('statusText');
    var retryBtn = document.getElementById('retryBtn');
    var solving = false;

    // Behavioral tracking
    var mouseEvents = 0;
    var firstInteraction = null;
    var pageLoadTime = Date.now();
    document.addEventListener('mousemove', function() {
        mouseEvents++;
        if (!firstInteraction) firstInteraction = Date.now();
    });
    document.addEventListener('keydown', function() {
        if (!firstInteraction) firstInteraction = Date.now();
    });
    document.addEventListener('touchstart', function() {
        if (!firstInteraction) firstInteraction = Date.now();
    });

    // Pure-JS SHA-256 (inlined for Web Worker)
    var workerCode = [
        'self.onmessage = function(e) {',
        '  var prefix = e.data.prefix, d = e.data.difficulty;',
        '  var target = "";',
        '  for (var i = 0; i < d; i++) target += "0";',
        '  for (var n = 0; n < 100000000; n++) {',
        '    var hash = sha256(prefix + n);',
        '    if (hash.substr(0, d) === target) {',
        '      self.postMessage({ found: true, nonce: n, hash: hash });',
        '      return;',
        '    }',
        '    if (n % 100000 === 0) self.postMessage({ progress: n });',
        '  }',
        '  self.postMessage({ found: false });',
        '};',
        'function sha256(str) {',
        '  var H = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];',
        '  var K = [0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,',
        '    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,',
        '    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,',
        '    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,',
        '    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,',
        '    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,',
        '    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,',
        '    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];',
        '  var bytes = [];',
        '  for (var i = 0; i < str.length; i++) {',
        '    var c = str.charCodeAt(i);',
        '    if (c < 128) bytes.push(c);',
        '    else if (c < 2048) { bytes.push(192 | (c >> 6)); bytes.push(128 | (c & 63)); }',
        '    else { bytes.push(224 | (c >> 12)); bytes.push(128 | ((c >> 6) & 63)); bytes.push(128 | (c & 63)); }',
        '  }',
        '  var len = bytes.length;',
        '  bytes.push(0x80);',
        '  while ((bytes.length % 64) !== 56) bytes.push(0);',
        '  var bitLen = len * 8;',
        '  for (var i = 7; i >= 0; i--) bytes.push((bitLen >>> (i * 8)) & 255);',
        '  var h0=H[0],h1=H[1],h2=H[2],h3=H[3],h4=H[4],h5=H[5],h6=H[6],h7=H[7];',
        '  for (var chunk = 0; chunk < bytes.length; chunk += 64) {',
        '    var w = [];',
        '    for (var i = 0; i < 16; i++) w[i] = (bytes[chunk+i*4]<<24)|(bytes[chunk+i*4+1]<<16)|(bytes[chunk+i*4+2]<<8)|bytes[chunk+i*4+3];',
        '    for (var i = 16; i < 64; i++) {',
        '      var s0 = rr(w[i-15],7)^rr(w[i-15],18)^(w[i-15]>>>3);',
        '      var s1 = rr(w[i-2],17)^rr(w[i-2],19)^(w[i-2]>>>10);',
        '      w[i] = (w[i-16]+s0+w[i-7]+s1)|0;',
        '    }',
        '    var a=h0,b=h1,c=h2,d=h3,e=h4,f=h5,g=h6,hh=h7;',
        '    for (var i = 0; i < 64; i++) {',
        '      var S1=rr(e,6)^rr(e,11)^rr(e,25);',
        '      var ch=(e&f)^(~e&g);',
        '      var t1=(hh+S1+ch+K[i]+w[i])|0;',
        '      var S0=rr(a,2)^rr(a,13)^rr(a,22);',
        '      var maj=(a&b)^(a&c)^(b&c);',
        '      var t2=(S0+maj)|0;',
        '      hh=g;g=f;f=e;e=(d+t1)|0;d=c;c=b;b=a;a=(t1+t2)|0;',
        '    }',
        '    h0=(h0+a)|0;h1=(h1+b)|0;h2=(h2+c)|0;h3=(h3+d)|0;',
        '    h4=(h4+e)|0;h5=(h5+f)|0;h6=(h6+g)|0;h7=(h7+hh)|0;',
        '  }',
        '  return hex(h0)+hex(h1)+hex(h2)+hex(h3)+hex(h4)+hex(h5)+hex(h6)+hex(h7);',
        '}',
        'function rr(n,b) { return (n>>>b)|(n<<(32-b)); }',
        'function hex(n) { var s=""; for(var i=7;i>=0;i--) s+="0123456789abcdef".charAt((n>>>(i*4))&15); return s; }'
    ].join('\n');

    function startChallenge() {
        if (solving) return;
        solving = true;
        box.className = 'challenge-checkbox solving';
        statusEl.textContent = i18n.solving;
        retryBtn.style.display = 'none';

        try {
            var blob = new Blob([workerCode], { type: 'application/javascript' });
            var workerUrl = URL.createObjectURL(blob);
            var worker = new Worker(workerUrl);

            worker.onmessage = function(e) {
                if (e.data.found) {
                    worker.terminate();
                    URL.revokeObjectURL(workerUrl);
                    verifySolution(e.data.nonce, e.data.hash);
                } else if (e.data.progress !== undefined) {
                    statusEl.textContent = i18n.working + ' (' + Math.floor(e.data.progress / 1000) + 'K)';
                } else if (e.data.found === false) {
                    worker.terminate();
                    URL.revokeObjectURL(workerUrl);
                    handleFailure(i18n.unsolvable);
                }
            };

            worker.onerror = function() {
                worker.terminate();
                URL.revokeObjectURL(workerUrl);
                handleFailure(i18n.browserError);
            };

            worker.postMessage({
                prefix: challenge.prefix,
                difficulty: challenge.difficulty
            });
        } catch (e) {
            handleFailure(i18n.noWorkers);
        }
    }

    function verifySolution(powNonce, powHash) {
        statusEl.textContent = i18n.verifying;

        var formData = new FormData();
        formData.append('action', 'webdecoy_pow_verify');
        formData.append('_wpnonce', wpNonce);
        formData.append('challenge', JSON.stringify(challenge));
        formData.append('pow_nonce', powNonce);
        formData.append('pow_hash', powHash);
        formData.append('behavioral', JSON.stringify({
            mouseEvents: mouseEvents,
            timeToInteraction: firstInteraction ? firstInteraction - pageLoadTime : null,
            sessionDuration: Date.now() - pageLoadTime
        }));

        fetch(ajaxUrl, {
            method: 'POST',
            body: formData,
            credentials: 'same-origin'
        })
        .then(function(r) { return r.json(); })
        .then(function(data) {
            if (data.success) {
                box.className = 'challenge-checkbox success';
                statusEl.textContent = i18n.verified;
                setTimeout(function() {
                    window.location.href = redirectUrl;
                }, 1000);
            } else {
                var msg = (data.data && data.data.message) ? data.data.message : i18n.failed;
                handleFailure(msg);
            }
        })
        .catch(function() {
            handleFailure(i18n.networkError);
        });
    }

    function handleFailure(msg) {
        solving = false;
        box.className = 'challenge-checkbox failed';
        statusEl.textContent = msg;
        retryBtn.style.display = 'inline-block';
    }

    box.addEventListener('click', startChallenge);
    box.addEventListener('keydown', function(e) {
        if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            startChallenge();
        }
    });

    retryBtn.addEventListener('click', function() {
        var formData = new FormData();
        formData.append('action', 'webdecoy_pow_challenge');
        formData.append('_wpnonce', wpNonce);

        fetch(ajaxUrl, {
            method: 'POST',
            body: formData,
            credentials: 'same-origin'
        })
        .then(function(r) { return r.json(); })
        .then(function(data) {
            if (data.success && data.data) {
                challenge = data.data;
                box.className = 'challenge-checkbox';
                statusEl.textContent = '';
                retryBtn.style.display = 'none';
            }
        })
        .catch(function() {
            statusEl.textContent = i18n.refreshFailed;
        });
    });
})();
