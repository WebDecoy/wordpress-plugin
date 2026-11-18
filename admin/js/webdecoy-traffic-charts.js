/** WebDecoy local traffic visualizations. Existing protection charts stay independent. */
(function () {
    'use strict';
    if (typeof Chart === 'undefined' || !window.webdecoyChartData || !window.webdecoyChartData.traffic) return;
    var d = window.webdecoyChartData.traffic;
    var palette = ['#f90289', '#7565db', '#239d98'];
    var reduced = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    var labels = d.labels.map(function (date) { return date.slice(5).replace('-', '/'); });
    var names = d.names;
    var totals = ['ai', 'search', 'other'].map(function (key) { return (d.groups && d.groups[key]) || 0; });
    function options() {
        return {
            responsive: true, maintainAspectRatio: false,
            animation: reduced ? false : { duration: 350 },
            interaction: { mode: 'index', intersect: false },
            plugins: { legend: { display: false }, tooltip: { backgroundColor: '#171923', padding: 12, cornerRadius: 8 } },
            scales: {
                x: { grid: { display: false }, border: { display: false }, ticks: { color: '#73717d', maxTicksLimit: 8, maxRotation: 0, font: { size: 11 } } },
                y: { beginAtZero: true, border: { display: false }, grid: { color: '#eeedf1' }, ticks: { color: '#73717d', precision: 0, maxTicksLimit: 5, font: { size: 11 } } }
            }
        };
    }
    var crawler = document.getElementById('wdCrawlerChart');
    if (crawler && d.crawlerReady) {
        var o = options();
        o.scales.y.stacked = true;
        o.scales.x.stacked = true;
        new Chart(crawler, { type: 'line', data: { labels: labels, datasets: ['ai', 'search', 'other'].map(function (key, i) {
            return { label: names[i], data: d.series[key], borderColor: palette[i], backgroundColor: palette[i] + '24', borderWidth: 2, pointRadius: 0, pointHoverRadius: 4, fill: i === 0 ? 'origin' : '-1', tension: 0.25 };
        }) }, options: o });
    }
    var mix = document.getElementById('wdBotMixChart');
    if (mix && d.crawlerReady) {
        new Chart(mix, { type: 'doughnut', data: { labels: names.slice(0, 3), datasets: [{ data: totals, backgroundColor: palette, borderColor: '#fff', borderWidth: 4, hoverOffset: reduced ? 0 : 4 }] }, options: { responsive: true, maintainAspectRatio: false, cutout: '76%', animation: reduced ? false : { duration: 350 }, plugins: { legend: { display: false }, tooltip: { backgroundColor: '#171923', padding: 12 } } } });
    }
    var agents = document.getElementById('wdTopAgentsChart');
    if (agents && d.crawlerReady) {
        var rank = options();
        rank.indexAxis = 'y';
        rank.interaction = { mode: 'nearest', intersect: true };
        rank.scales.y.grid.display = false;
        rank.scales.x.grid = { color: '#eeedf1' };
        rank.scales.x.beginAtZero = true;
        rank.scales.x.ticks.precision = 0;
        rank.scales.y.ticks.color = '#34323c';
        rank.scales.y.ticks.autoSkip = false;
        new Chart(agents, { type: 'bar', data: { labels: d.agents.map(function (a) { return a.name; }), datasets: [{ label: names[4], data: d.agents.map(function (a) { return a.hits; }), backgroundColor: d.agents.map(function (a) { return palette[a.group === 'ai' ? 0 : (a.group === 'search' ? 1 : 2)]; }), borderRadius: 4, maxBarThickness: 18 }] }, options: rank });
    }
    var referrals = document.getElementById('wdReferralChart');
    if (referrals && d.referralReady) {
        new Chart(referrals, { type: 'line', data: { labels: labels, datasets: [{ label: names[3], data: d.series.referrals, borderColor: '#239d98', backgroundColor: '#239d981c', borderWidth: 2, pointRadius: 0, pointHoverRadius: 4, fill: true, tension: 0.25 }] }, options: options() });
    }
})();
