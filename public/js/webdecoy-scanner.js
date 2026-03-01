/**
 * WebDecoy Bot Scanner for WordPress
 * Client-side bot detection with server-side forwarding to WebDecoy ingest
 *
 * @package WebDecoy
 */

(function() {
  'use strict';

  // Configuration injected by WordPress (via wp_localize_script)
  if (typeof webdecoyScanner === 'undefined') {
    console.warn('[WebDecoy] Scanner configuration not found');
    return;
  }

  const config = webdecoyScanner;

  if (!config.enabled) {
    return;
  }

  /**
   * Detects if browser is running under webdriver protocol
   */
  function detectWebdriver() {
    try {
      return navigator.webdriver === true;
    } catch (e) {
      return false;
    }
  }

  /**
   * Detects headless browser indicators
   */
  function detectHeadless() {
    const headlessIndicators = [
      // Chrome/Chromium headless
      /HeadlessChrome/.test(navigator.userAgent),

      // Firefox headless
      /firefox/.test(navigator.userAgent.toLowerCase()) &&
      !window.mozInnerScreenX && !window.mozInnerScreenY,

      // Missing chrome object in headless mode (only check for Chrome user agents)
      /chrome/i.test(navigator.userAgent) && !(window.chrome && window.chrome.webstore),

      // Phantom JS
      /PhantomJS/.test(navigator.userAgent),

      // Check for headless-specific navigator properties
      navigator.vendor === '' && navigator.userAgent.includes('Headless'),
    ];

    return headlessIndicators.some(function(indicator) { return indicator === true; });
  }

  /**
   * Detects Chrome object inconsistencies that stealth plugins often miss
   * Updated to remove deprecated chrome.csi() and chrome.loadTimes() checks
   */
  function detectChromeInconsistency() {
    try {
      if (!/Chrome/.test(navigator.userAgent)) {
        return { detected: false, signals: [] };
      }

      var signals = [];

      // Check for missing chrome object entirely
      if (!window.chrome) {
        signals.push('no_chrome_object');
      } else {
        // chrome.runtime is required in real Chrome (except in some iframes)
        if (!window.chrome.runtime && window === window.top) {
          signals.push('missing_chrome_runtime');
        }

        // chrome.app check - should exist in Chrome
        if (window.chrome.app && typeof window.chrome.app.isInstalled !== 'undefined') {
          if (typeof window.chrome.app.isInstalled !== 'boolean') {
            signals.push('invalid_chrome_app');
          }
        }

        // Check chrome.webstore existence (removed in Chrome 88+ from normal pages,
        // but presence in headless mode is suspicious)
        // Note: We only flag if it exists AND has unusual properties
      }

      // Check error stack trace format - Chrome has specific format
      try {
        throw new Error('test');
      } catch (e) {
        if (e.stack && !/at .+:\d+:\d+/.test(e.stack)) {
          signals.push('non_chrome_stack_trace');
        }
      }

      // Check Performance API - modern and reliable
      if (window.performance && window.performance.memory) {
        // Chrome exposes performance.memory
        if (typeof window.performance.memory.jsHeapSizeLimit !== 'number') {
          signals.push('invalid_performance_memory');
        }
      } else if (/Chrome/.test(navigator.userAgent) && !navigator.userAgent.includes('Edge')) {
        // Chrome should have performance.memory (except some contexts)
        // Only flag in main window context
        if (window === window.top) {
          signals.push('missing_performance_memory');
        }
      }

      // Check navigator.permissions API behavior
      if (navigator.permissions && typeof navigator.permissions.query === 'function') {
        // Headless browsers may have broken permissions API
        try {
          var permissionDescriptor = Object.getOwnPropertyDescriptor(navigator, 'permissions');
          if (permissionDescriptor && permissionDescriptor.get &&
              permissionDescriptor.get.toString().includes('native code') === false) {
            signals.push('modified_permissions_api');
          }
        } catch (e) {}
      }

      // Check for Puppeteer/Playwright specific properties
      if (window.cdc_adoQpoasnfa76pfcZLmcfl_Array ||
          window.cdc_adoQpoasnfa76pfcZLmcfl_Promise ||
          window.cdc_adoQpoasnfa76pfcZLmcfl_Symbol) {
        signals.push('chrome_devtools_protocol');
      }

      // Check navigator.languages consistency
      if (navigator.languages && navigator.languages.length === 0) {
        signals.push('empty_languages_array');
      }

      // Check for overridden native functions
      try {
        if (navigator.plugins.toString() !== '[object PluginArray]') {
          signals.push('modified_plugins_array');
        }
      } catch (e) {}

      return {
        detected: signals.length > 0,
        signals: signals
      };
    } catch (e) {
      return { detected: false, signals: [] };
    }
  }

  /**
   * Detects Permission API inconsistencies
   */
  function detectPermissionInconsistency() {
    return new Promise(function(resolve) {
      try {
        if (!navigator.permissions || typeof navigator.permissions.query !== 'function') {
          resolve({ detected: false, signals: [] });
          return;
        }

        var signals = [];

        navigator.permissions.query({ name: 'notifications' })
          .then(function(result) {
            if (result.state === 'denied' && typeof Notification !== 'undefined') {
              if (Notification.permission !== 'denied') {
                signals.push('permission_notification_mismatch');
              }
            }

            if (result.state === 'prompt') {
              try {
                if (typeof Notification !== 'undefined' && Notification.permission === 'denied') {
                  signals.push('notification_permission_inconsistent');
                }
              } catch (e) {}
            }

            resolve({
              detected: signals.length > 0,
              signals: signals
            });
          })
          .catch(function() {
            signals.push('permissions_api_failed');
            resolve({
              detected: signals.length > 0,
              signals: signals
            });
          });
      } catch (e) {
        resolve({ detected: false, signals: [] });
      }
    });
  }

  /**
   * Detects iframe anomalies
   */
  function detectIframeAnomaly() {
    try {
      if (!/Chrome/.test(navigator.userAgent)) {
        return { detected: false, signals: [] };
      }

      var signals = [];
      var iframe = document.createElement('iframe');
      iframe.style.display = 'none';
      document.body.appendChild(iframe);

      try {
        var iframeWindow = iframe.contentWindow;

        if (!iframeWindow.chrome) {
          signals.push('iframe_no_chrome');
        } else if (iframeWindow.chrome && Object.keys(iframeWindow.chrome).length === 0) {
          signals.push('iframe_empty_chrome');
        }

        if (iframeWindow.navigator && iframeWindow.navigator.webdriver !== navigator.webdriver) {
          signals.push('iframe_webdriver_mismatch');
        }

        if (iframeWindow.navigator && iframeWindow.navigator.plugins) {
          if (iframeWindow.navigator.plugins.length !== navigator.plugins.length) {
            signals.push('iframe_plugins_mismatch');
          }
        }
      } finally {
        document.body.removeChild(iframe);
      }

      return {
        detected: signals.length > 0,
        signals: signals
      };
    } catch (e) {
      return { detected: false, signals: [] };
    }
  }

  /**
   * Detects unrealistically fast API timing (headless browsers)
   */
  function detectAPITiming() {
    try {
      var signals = [];

      // Test 1: DOM manipulation timing
      var start1 = performance.now();
      var div = document.createElement('div');
      div.style.width = '100px';
      div.style.height = '100px';
      div.style.position = 'absolute';
      div.style.left = '-9999px';
      document.body.appendChild(div);

      void div.getBoundingClientRect();
      void div.offsetHeight;

      document.body.removeChild(div);
      var duration1 = performance.now() - start1;

      if (duration1 < 0.01) {
        signals.push('dom_timing_too_fast');
      }

      // Test 2: Canvas rendering timing
      var start2 = performance.now();
      var canvas = document.createElement('canvas');
      canvas.width = 200;
      canvas.height = 200;
      var ctx = canvas.getContext('2d');
      if (ctx) {
        ctx.fillStyle = '#ff0000';
        ctx.fillRect(0, 0, 200, 200);
        ctx.fillStyle = '#00ff00';
        for (var i = 0; i < 50; i++) {
          ctx.fillRect(i * 4, i * 4, 10, 10);
        }
        void canvas.toDataURL();
      }
      var duration2 = performance.now() - start2;

      if (duration2 < 0.1) {
        signals.push('canvas_timing_too_fast');
      }

      // Test 3: Performance.now() precision
      var times = [];
      for (var j = 0; j < 100; j++) {
        times.push(performance.now());
      }

      var uniqueTimes = [];
      times.forEach(function(t) {
        var mod = t % 1;
        if (uniqueTimes.indexOf(mod) === -1) {
          uniqueTimes.push(mod);
        }
      });
      if (uniqueTimes.length > 90) {
        signals.push('timing_precision_suspicious');
      }

      return {
        detected: signals.length > 0,
        signals: signals,
        timing: {
          domOperation: duration1,
          canvasOperation: duration2
        }
      };
    } catch (e) {
      return { detected: false, signals: [] };
    }
  }

  /**
   * Detects automation frameworks
   */
  function detectAutomationFramework() {
    var frameworks = {
      puppeteer: function() { return navigator.webdriver || '__puppeteer' in window || navigator.userAgent.indexOf('Headless') !== -1; },
      playwright: function() { return '__playwright' in window || navigator.userAgent.indexOf('Playwright') !== -1; },
      selenium: function() { return '__webdriver_evaluate' in window || '__driver_evaluate' in window || '__webdrivereval' in window; },
      nightmare: function() { return '__nightmare' in window; },
      phantom: function() { return /PhantomJS/.test(navigator.userAgent); },
      watir: function() { return '__watir' in window; },
      chromedp: function() { return navigator.userAgent.indexOf('ChromeHeadless') !== -1; },
      cypress: function() { return '__cypress' in window || window.cy !== undefined; },
      protractor: function() { return '__protractor' in window; },
      jsdom: function() { return navigator.userAgent.indexOf('jsdom') !== -1; },
      testcafe: function() { return '__testcafe' in window || navigator.userAgent.indexOf('TestCafe') !== -1; },
      casperjs: function() { return /CasperJS/.test(navigator.userAgent); },
      zombie: function() { return navigator.userAgent.indexOf('Zombie') !== -1; }
    };

    for (var framework in frameworks) {
      try {
        if (frameworks[framework]()) {
          return framework;
        }
      } catch (e) {}
    }

    return null;
  }

  /**
   * Detects missing browser headers
   */
  function detectMissingHeaders() {
    var missing = [];

    try {
      // Note: navigator.plugins is deprecated in modern browsers and returns empty array
      // So we no longer check for no_plugins - it creates false positives
      if (!navigator.language && !navigator.userLanguage) {
        missing.push('no_language');
      }
      if (!navigator.userAgent) {
        missing.push('no_user_agent');
      }
    } catch (e) {}

    return missing;
  }

  /**
   * Detects AI/ML crawlers and known bots
   */
  function detectAICrawler() {
    var userAgent = navigator.userAgent.toLowerCase();

    var crawlers = {
      'GPTBot': /gptbot/i,
      'ClaudeBot': /claudebot/i,
      'PerplexityBot': /perplexitybot/i,
      'CCBot': /ccbot/i,
      'OAI-SearchBot': /oai-searchbot/i,
      'anthropic-ai': /anthropic-ai/i,
      'Googlebot': /googlebot/i,
      'Bingbot': /bingbot/i,
      'Slurp': /slurp/i,
      'DuckDuckBot': /duckduckbot/i,
      'Baiduspider': /baiduspider/i,
      'YandexBot': /yandexbot/i,
      'AppleBot': /applebot/i,
      'Facebookexternalhit': /facebookexternalhit/i,
      'Twitterbot': /twitterbot/i,
      'LinkedInBot': /linkedinbot/i,
      'WhatsApp': /whatsapp/i,
      'Slack': /slackbot|slack-imgproxy/i,
      'Telegram': /telegrambot/i,
      'Semrush': /semrushbot|semrush/i,
      'Ahrefs': /ahrefs|ahrefsbot/i,
      'MJ12bot': /mj12bot/i,
      'Scrapy': /scrapy/i,
      'Curl': /curl/i,
      'Wget': /wget/i,
      'Python-Requests': /python-requests/i
    };

    for (var crawler in crawlers) {
      if (crawlers[crawler].test(userAgent)) {
        return crawler;
      }
    }

    return null;
  }

  /**
   * Detects WebRTC IP leak - can reveal real IP even when using VPN
   * Returns a promise that resolves with the detected IPs
   */
  function detectWebRTCIP() {
    return new Promise(function(resolve) {
      try {
        // Check if WebRTC is available
        var RTCPeerConnection = window.RTCPeerConnection ||
                                 window.webkitRTCPeerConnection ||
                                 window.mozRTCPeerConnection;

        if (!RTCPeerConnection) {
          resolve({ available: false, ips: [] });
          return;
        }

        var ips = [];
        var ipRegex = /([0-9]{1,3}(\.[0-9]{1,3}){3}|[a-f0-9]{1,4}(:[a-f0-9]{1,4}){7})/gi;

        // Create a peer connection with STUN servers
        var pc = new RTCPeerConnection({
          iceServers: [
            { urls: 'stun:stun.l.google.com:19302' },
            { urls: 'stun:stun1.l.google.com:19302' }
          ]
        });

        // Create a data channel to trigger ICE gathering
        pc.createDataChannel('');

        // Listen for ICE candidates
        pc.onicecandidate = function(event) {
          if (!event || !event.candidate || !event.candidate.candidate) {
            return;
          }

          var candidate = event.candidate.candidate;
          var matches = candidate.match(ipRegex);

          if (matches) {
            for (var i = 0; i < matches.length; i++) {
              var ip = matches[i];
              // Skip local/private IPs for VPN detection
              if (!isPrivateIP(ip) && ips.indexOf(ip) === -1) {
                ips.push(ip);
              }
            }
          }
        };

        // Create offer to start ICE gathering
        pc.createOffer()
          .then(function(offer) {
            return pc.setLocalDescription(offer);
          })
          .catch(function() {
            // Silently fail
          });

        // Wait for ICE gathering to complete (with timeout)
        setTimeout(function() {
          pc.close();
          resolve({
            available: true,
            ips: ips,
            // Return the first public IP found (most likely the real IP)
            publicIP: ips.length > 0 ? ips[0] : null
          });
        }, 1000); // 1 second timeout for ICE gathering

      } catch (e) {
        resolve({ available: false, ips: [], error: e.message });
      }
    });
  }

  /**
   * Checks if an IP is private/local
   */
  function isPrivateIP(ip) {
    // IPv4 private ranges
    if (/^10\./.test(ip)) return true;
    if (/^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(ip)) return true;
    if (/^192\.168\./.test(ip)) return true;
    if (/^127\./.test(ip)) return true;
    if (/^169\.254\./.test(ip)) return true;
    if (/^0\./.test(ip)) return true;

    // IPv6 private/local
    if (/^::1$/.test(ip)) return true;
    if (/^fe80:/i.test(ip)) return true;
    if (/^fc00:/i.test(ip)) return true;
    if (/^fd00:/i.test(ip)) return true;

    return false;
  }

  /**
   * Collects browser fingerprint data
   */
  function collectFingerprint() {
    var fp = {
      userAgent: navigator.userAgent,
      language: navigator.language,
      languages: navigator.languages ? Array.prototype.slice.call(navigator.languages) : [navigator.language],
      platform: navigator.platform,
      hardwareConcurrency: navigator.hardwareConcurrency,
      deviceMemory: navigator.deviceMemory,
      maxTouchPoints: navigator.maxTouchPoints,
      vendor: navigator.vendor,
      plugins: navigator.plugins ? Array.prototype.slice.call(navigator.plugins).map(function(p) { return p.name; }) : [],
      doNotTrack: navigator.doNotTrack,
      cookieEnabled: navigator.cookieEnabled,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      screenResolution: {
        width: window.screen.width,
        height: window.screen.height,
        colorDepth: window.screen.colorDepth,
        pixelDepth: window.screen.pixelDepth
      },
      webGL: (function() {
        try {
          var canvas = document.createElement('canvas');
          var gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
          return gl ? gl.getParameter(gl.VERSION) : null;
        } catch (e) {
          return null;
        }
      })(),
      canvas: (function() {
        try {
          var canvas = document.createElement('canvas');
          return canvas.toDataURL() !== 'data:,';
        } catch (e) {
          return false;
        }
      })(),
      localStorage: (function() {
        try {
          var test = '__test__';
          localStorage.setItem(test, test);
          localStorage.removeItem(test);
          return true;
        } catch (e) {
          return false;
        }
      })(),
      sessionStorage: (function() {
        try {
          var test = '__test__';
          sessionStorage.setItem(test, test);
          sessionStorage.removeItem(test);
          return true;
        } catch (e) {
          return false;
        }
      })(),
      indexedDB: typeof indexedDB !== 'undefined',
      openDatabase: typeof openDatabase !== 'undefined'
    };

    return fp;
  }

  /**
   * Calculates client-side threat score (0-100)
   */
  function calculateScore(signals) {
    var score = 0;

    if (signals.webdriver) score += 40;
    if (signals.headless) score += 25;
    if (signals.automationFramework) score += 35;
    if (signals.aiBot) score += 50;
    if (signals.missingHeaders.length > 0) {
      score += Math.min(signals.missingHeaders.length * 2, 10);
    }
    if (signals.honeypotTriggered) score += 60;

    if (signals.chromeInconsistency && signals.chromeInconsistency.detected) {
      score += Math.min(signals.chromeInconsistency.signals.length * 10, 30);
    }
    if (signals.permissionInconsistency && signals.permissionInconsistency.detected) {
      score += 20;
    }
    if (signals.iframeAnomaly && signals.iframeAnomaly.detected) {
      score += 25;
    }
    if (signals.apiTiming && signals.apiTiming.detected) {
      score += Math.min(signals.apiTiming.signals.length * 15, 30);
    }

    // Behavioral analysis scoring
    if (signals.behavioral && signals.behavioral.detected) {
      var behavioralSignals = signals.behavioral.signals;
      for (var i = 0; i < behavioralSignals.length; i++) {
        var sig = behavioralSignals[i];
        switch (sig) {
          case 'instant_interaction':
            score += 15;
            break;
          case 'clicks_without_mouse_movement':
            score += 20;
            break;
          case 'robotic_mouse_movement':
            score += 25;
            break;
          case 'rapid_clicking':
            score += 20;
            break;
          case 'robotic_scrolling':
            score += 20;
            break;
          case 'instant_page_load':
            score += 10;
            break;
          case 'suspicious_direct_navigation':
            score += 10;
            break;
          case 'no_interaction_5s':
            // This alone isn't highly suspicious, but combined with other signals
            score += 5;
            break;
          default:
            score += 10;
        }
      }
    }

    return Math.min(score, 100);
  }

  /**
   * Checks for honeypot field triggers
   */
  function checkHoneypot() {
    // Check for WordPress honeypot fields injected by WebDecoy
    var honeypotSelectors = [
      'input.webdecoy-hp-wrap input',
      'input[name^="webdecoy_hp_"]',
      'input[style*="display: none"]',
      'input[style*="visibility: hidden"]',
      '.webdecoy-hp-wrap input'
    ];

    for (var i = 0; i < honeypotSelectors.length; i++) {
      var fields = document.querySelectorAll(honeypotSelectors[i]);
      for (var j = 0; j < fields.length; j++) {
        if (fields[j].value && fields[j].value.trim() !== '') {
          return fields[j].value;
        }
      }
    }

    return '';
  }

  var detectionSent = false;

  /**
   * Behavioral analysis state
   */
  var behavioralState = {
    pageLoadTime: Date.now(),
    firstInteractionTime: null,
    mouseMovements: [],
    scrollEvents: [],
    keyPresses: 0,
    clicks: 0,
    focusChanges: 0,
    touchEvents: 0,
    rapidClicks: [],
    lastMousePos: null,
    straightLineMovements: 0,
    totalMouseMovements: 0
  };

  /**
   * Tracks mouse movements for behavioral analysis
   */
  function trackMouseMovement(e) {
    var now = Date.now();
    if (!behavioralState.firstInteractionTime) {
      behavioralState.firstInteractionTime = now;
    }

    var pos = { x: e.clientX, y: e.clientY, t: now };

    // Check for straight-line movements (bot behavior)
    if (behavioralState.lastMousePos && behavioralState.mouseMovements.length > 2) {
      var prev = behavioralState.lastMousePos;
      var prevPrev = behavioralState.mouseMovements[behavioralState.mouseMovements.length - 2];

      if (prevPrev) {
        // Calculate angle consistency (bots often move in perfectly straight lines)
        var angle1 = Math.atan2(prev.y - prevPrev.y, prev.x - prevPrev.x);
        var angle2 = Math.atan2(pos.y - prev.y, pos.x - prev.x);
        var angleDiff = Math.abs(angle1 - angle2);

        if (angleDiff < 0.01 && angleDiff !== 0) {
          behavioralState.straightLineMovements++;
        }
      }
    }

    behavioralState.lastMousePos = pos;
    behavioralState.totalMouseMovements++;

    // Store limited history
    if (behavioralState.mouseMovements.length < 100) {
      behavioralState.mouseMovements.push(pos);
    }
  }

  /**
   * Tracks scroll events
   */
  function trackScroll() {
    var now = Date.now();
    if (!behavioralState.firstInteractionTime) {
      behavioralState.firstInteractionTime = now;
    }

    behavioralState.scrollEvents.push({
      y: window.scrollY,
      t: now
    });

    // Keep limited history
    if (behavioralState.scrollEvents.length > 50) {
      behavioralState.scrollEvents.shift();
    }
  }

  /**
   * Tracks click events
   */
  function trackClick(e) {
    var now = Date.now();
    if (!behavioralState.firstInteractionTime) {
      behavioralState.firstInteractionTime = now;
    }

    behavioralState.clicks++;
    behavioralState.rapidClicks.push(now);

    // Keep only recent clicks (last 5 seconds)
    behavioralState.rapidClicks = behavioralState.rapidClicks.filter(function(t) {
      return now - t < 5000;
    });
  }

  /**
   * Tracks keyboard events
   */
  function trackKeyPress() {
    if (!behavioralState.firstInteractionTime) {
      behavioralState.firstInteractionTime = Date.now();
    }
    behavioralState.keyPresses++;
  }

  /**
   * Tracks focus changes
   */
  function trackFocusChange() {
    behavioralState.focusChanges++;
  }

  /**
   * Tracks touch events (mobile)
   */
  function trackTouch() {
    if (!behavioralState.firstInteractionTime) {
      behavioralState.firstInteractionTime = Date.now();
    }
    behavioralState.touchEvents++;
  }

  /**
   * Analyzes behavioral patterns for bot signals
   */
  function analyzeBehavior() {
    var signals = [];
    var now = Date.now();
    var timeOnPage = now - behavioralState.pageLoadTime;

    // 1. No interaction after sufficient time on page (suspicious for non-bots)
    if (timeOnPage > 5000 && !behavioralState.firstInteractionTime) {
      signals.push('no_interaction_5s');
    }

    // 2. Instant interaction (bots often interact immediately)
    if (behavioralState.firstInteractionTime) {
      var timeToFirstInteraction = behavioralState.firstInteractionTime - behavioralState.pageLoadTime;
      if (timeToFirstInteraction < 100) {
        signals.push('instant_interaction');
      }
    }

    // 3. No mouse movements at all (suspicious for desktop with clicks)
    if (behavioralState.clicks > 0 && behavioralState.totalMouseMovements === 0) {
      if (navigator.maxTouchPoints === 0) { // Not a touch device
        signals.push('clicks_without_mouse_movement');
      }
    }

    // 4. Too many straight-line mouse movements (bot behavior)
    if (behavioralState.totalMouseMovements > 20) {
      var straightLineRatio = behavioralState.straightLineMovements / behavioralState.totalMouseMovements;
      if (straightLineRatio > 0.5) {
        signals.push('robotic_mouse_movement');
      }
    }

    // 5. Rapid clicking (click spam)
    if (behavioralState.rapidClicks.length >= 10) {
      // 10+ clicks in 5 seconds
      signals.push('rapid_clicking');
    }

    // 6. Inhuman scroll patterns
    if (behavioralState.scrollEvents.length >= 3) {
      var scrollDeltas = [];
      for (var i = 1; i < behavioralState.scrollEvents.length; i++) {
        var delta = behavioralState.scrollEvents[i].y - behavioralState.scrollEvents[i - 1].y;
        var timeDelta = behavioralState.scrollEvents[i].t - behavioralState.scrollEvents[i - 1].t;
        if (timeDelta > 0) {
          scrollDeltas.push(Math.abs(delta / timeDelta)); // Scroll velocity
        }
      }

      // Check for perfectly consistent scroll velocity (bot behavior)
      if (scrollDeltas.length >= 3) {
        var avgVelocity = scrollDeltas.reduce(function(a, b) { return a + b; }, 0) / scrollDeltas.length;
        var variance = scrollDeltas.reduce(function(sum, v) {
          return sum + Math.pow(v - avgVelocity, 2);
        }, 0) / scrollDeltas.length;

        if (variance < 0.001 && avgVelocity > 0) {
          signals.push('robotic_scrolling');
        }
      }
    }

    // 7. Form filling too fast
    // This is tracked separately by form timing

    // 8. Navigation timing anomalies
    if (window.performance && window.performance.timing) {
      var timing = window.performance.timing;
      var pageLoadDuration = timing.loadEventEnd - timing.navigationStart;

      // Suspiciously fast page load (might be cached bot)
      if (pageLoadDuration > 0 && pageLoadDuration < 50) {
        signals.push('instant_page_load');
      }

      // Check if page was loaded via back/forward (bots rarely use history)
      if (window.performance.navigation) {
        var navType = window.performance.navigation.type;
        // type 2 = back/forward - not suspicious
        // type 1 = reload - slightly suspicious if rapid
        // type 0 = direct navigation - normal
      }
    }

    // 9. Missing referrer with direct navigation (suspicious for non-bookmarks)
    if (!document.referrer && document.visibilityState === 'visible') {
      // Only flag if it looks like an automated direct hit
      if (behavioralState.firstInteractionTime &&
          (behavioralState.firstInteractionTime - behavioralState.pageLoadTime) < 200) {
        signals.push('suspicious_direct_navigation');
      }
    }

    // 10. Check for copy-paste behavior patterns
    // High key presses but only in bursts (paste behavior)

    return {
      detected: signals.length > 0,
      signals: signals,
      metrics: {
        timeOnPage: timeOnPage,
        timeToFirstInteraction: behavioralState.firstInteractionTime ?
          behavioralState.firstInteractionTime - behavioralState.pageLoadTime : null,
        mouseMovements: behavioralState.totalMouseMovements,
        straightLineRatio: behavioralState.totalMouseMovements > 0 ?
          behavioralState.straightLineMovements / behavioralState.totalMouseMovements : 0,
        clicks: behavioralState.clicks,
        scrollEvents: behavioralState.scrollEvents.length,
        keyPresses: behavioralState.keyPresses
      }
    };
  }

  /**
   * Initialize behavioral tracking
   */
  function initBehavioralTracking() {
    // Mouse tracking (throttled)
    var mouseThrottleTimer = null;
    document.addEventListener('mousemove', function(e) {
      if (!mouseThrottleTimer) {
        mouseThrottleTimer = setTimeout(function() {
          trackMouseMovement(e);
          mouseThrottleTimer = null;
        }, 50);
      }
    }, { passive: true });

    // Scroll tracking (throttled)
    var scrollThrottleTimer = null;
    window.addEventListener('scroll', function() {
      if (!scrollThrottleTimer) {
        scrollThrottleTimer = setTimeout(function() {
          trackScroll();
          scrollThrottleTimer = null;
        }, 100);
      }
    }, { passive: true });

    // Click tracking
    document.addEventListener('click', trackClick, { passive: true });

    // Keyboard tracking
    document.addEventListener('keydown', trackKeyPress, { passive: true });

    // Focus tracking
    window.addEventListener('focus', trackFocusChange);
    window.addEventListener('blur', trackFocusChange);

    // Touch tracking (mobile)
    document.addEventListener('touchstart', trackTouch, { passive: true });
  }

  /**
   * Runs all detection checks
   */
  function runDetectionAsync() {
    return new Promise(function(resolve) {
      try {
        var signals = {
          webdriver: detectWebdriver(),
          headless: detectHeadless(),
          automationFramework: detectAutomationFramework(),
          aiBot: detectAICrawler(),
          missingHeaders: detectMissingHeaders(),
          honeypotTriggered: false,
          chromeInconsistency: detectChromeInconsistency(),
          iframeAnomaly: detectIframeAnomaly(),
          apiTiming: detectAPITiming(),
          permissionInconsistency: null,
          webrtcIP: null,
          behavioral: analyzeBehavior()
        };

        var honeypotValue = checkHoneypot();
        if (honeypotValue) {
          signals.honeypotTriggered = true;
        }
        signals.honeypotValue = honeypotValue;

        // Run async checks in parallel with timeout
        var permissionPromise = detectPermissionInconsistency();
        var webrtcPromise = detectWebRTCIP();

        var timeoutPromise = new Promise(function(res) {
          setTimeout(function() {
            res({ timeout: true });
          }, 1500); // 1.5s timeout for async checks (WebRTC needs more time)
        });

        // Run both async checks in parallel
        Promise.all([
          Promise.race([permissionPromise, timeoutPromise]),
          Promise.race([webrtcPromise, timeoutPromise])
        ])
          .then(function(results) {
            var permResult = results[0];
            var webrtcResult = results[1];

            // Set permission result if not timed out
            if (!permResult.timeout) {
              signals.permissionInconsistency = permResult;
            } else {
              signals.permissionInconsistency = { detected: false, signals: [] };
            }

            // Set WebRTC result if not timed out
            if (!webrtcResult.timeout) {
              signals.webrtcIP = webrtcResult;
            }

            var clientScore = calculateScore(signals);

            // Only send if score meets threshold
            if (clientScore < config.minScore) {
              resolve(null);
              return;
            }

            // Collect fingerprint and add WebRTC IP data
            var fingerprint = collectFingerprint();

            // Add WebRTC IP to fingerprint for geo consistency check on server
            if (signals.webrtcIP && signals.webrtcIP.publicIP) {
              fingerprint.webrtcIP = signals.webrtcIP.publicIP;
              fingerprint.webrtcIPs = signals.webrtcIP.ips;
            }

            resolve({
              signals: signals,
              fingerprint: fingerprint,
              score: clientScore
            });
          })
          .catch(function() {
            var clientScore = calculateScore(signals);
            if (clientScore < config.minScore) {
              resolve(null);
              return;
            }

            var fingerprint = collectFingerprint();
            resolve({
              signals: signals,
              fingerprint: fingerprint,
              score: clientScore
            });
          });
      } catch (error) {
        resolve(null);
      }
    });
  }

  /**
   * Submits detection to WordPress endpoint (which forwards to ingest)
   */
  function submitDetection(signals, fingerprint) {
    try {
      var flags = [];
      if (signals.webdriver) flags.push('webdriver');
      if (signals.headless) flags.push('headless');
      if (signals.automationFramework) flags.push(signals.automationFramework);
      if (signals.missingHeaders.length > 0) {
        for (var i = 0; i < signals.missingHeaders.length; i++) {
          flags.push(signals.missingHeaders[i]);
        }
      }
      if (signals.honeypotTriggered) flags.push('honeypot');

      if (signals.chromeInconsistency && signals.chromeInconsistency.detected) {
        for (var j = 0; j < signals.chromeInconsistency.signals.length; j++) {
          flags.push(signals.chromeInconsistency.signals[j]);
        }
      }
      if (signals.permissionInconsistency && signals.permissionInconsistency.detected) {
        for (var k = 0; k < signals.permissionInconsistency.signals.length; k++) {
          flags.push(signals.permissionInconsistency.signals[k]);
        }
      }
      if (signals.iframeAnomaly && signals.iframeAnomaly.detected) {
        for (var l = 0; l < signals.iframeAnomaly.signals.length; l++) {
          flags.push(signals.iframeAnomaly.signals[l]);
        }
      }
      if (signals.apiTiming && signals.apiTiming.detected) {
        for (var m = 0; m < signals.apiTiming.signals.length; m++) {
          flags.push(signals.apiTiming.signals[m]);
        }
      }
      if (signals.behavioral && signals.behavioral.detected) {
        for (var n = 0; n < signals.behavioral.signals.length; n++) {
          flags.push('behavior_' + signals.behavioral.signals[n]);
        }
      }

      var clientScore = calculateScore(signals);

      // Build payload for WordPress AJAX endpoint
      var payload = {
        action: 'webdecoy_client_detection',
        nonce: config.nonce,
        detection: {
          v: 1,
          s: clientScore,
          f: flags,
          fp: fingerprint,
          url: window.location.href,
          ref: document.referrer,
          ts: Date.now(),
          ai: signals.aiBot || '',
          hp: signals.honeypotValue || '',
          timing: signals.apiTiming ? signals.apiTiming.timing : null,
          behavior: signals.behavioral ? signals.behavioral.metrics : null
        }
      };

      // Send to WordPress AJAX endpoint
      if (navigator.sendBeacon) {
        var formData = new FormData();
        formData.append('action', 'webdecoy_client_detection');
        formData.append('nonce', config.nonce);
        formData.append('detection', JSON.stringify(payload.detection));
        navigator.sendBeacon(config.ajaxUrl, formData);
      } else {
        // Fallback for older browsers
        var xhr = new XMLHttpRequest();
        xhr.open('POST', config.ajaxUrl, true);
        xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
        var params = 'action=webdecoy_client_detection&nonce=' + encodeURIComponent(config.nonce) +
                     '&detection=' + encodeURIComponent(JSON.stringify(payload.detection));
        xhr.send(params);
      }
    } catch (error) {
      // Silently fail
    }
  }

  /**
   * Main detection function
   */
  function sendDetection() {
    if (detectionSent) {
      return;
    }

    runDetectionAsync().then(function(result) {
      if (result && !detectionSent) {
        detectionSent = true;
        submitDetection(result.signals, result.fingerprint);
      }
    }).catch(function() {});
  }

  /**
   * Initialize
   */
  function init() {
    // Start behavioral tracking immediately
    initBehavioralTracking();

    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', sendDetection);
      window.addEventListener('load', sendDetection);
    } else {
      sendDetection();
    }

    window.addEventListener('beforeunload', sendDetection);

    // Also run detection after some time on page to capture behavioral signals
    setTimeout(function() {
      if (!detectionSent) {
        sendDetection();
      }
    }, 5000);
  }

  init();
})();
