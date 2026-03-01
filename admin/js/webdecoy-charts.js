/**
 * WebDecoy Statistics Charts
 *
 * @package WebDecoy
 */
(function() {
    'use strict';

    if (typeof Chart === 'undefined' || !window.webdecoyChartData) {
        return;
    }

    var data = window.webdecoyChartData;

    // Color palette
    var colors = {
        primary: '#2271b1',
        primaryLight: 'rgba(34, 113, 177, 0.1)',
        danger: '#dc3232',
        warning: '#f0b849',
        success: '#46b450',
        minimal: '#4caf50',
        low: '#ff9800',
        medium: '#ffc107',
        high: '#f44336',
        critical: '#b71c1c'
    };

    var threatColors = {
        'MINIMAL': colors.minimal,
        'LOW': colors.low,
        'MEDIUM': colors.medium,
        'HIGH': colors.high,
        'CRITICAL': colors.critical
    };

    // Chart.js defaults
    Chart.defaults.font.family = '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif';
    Chart.defaults.font.size = 12;

    // Detection Trend (Bar Chart)
    var trendCtx = document.getElementById('webdecoyTrendChart');
    if (trendCtx) {
        new Chart(trendCtx.getContext('2d'), {
            type: 'bar',
            data: {
                labels: data.trend.labels.map(function(d) {
                    var parts = d.split('-');
                    return parts[1] + '/' + parts[2];
                }),
                datasets: [{
                    label: 'Detections',
                    data: data.trend.data,
                    backgroundColor: colors.primary,
                    borderColor: colors.primary,
                    borderWidth: 1,
                    borderRadius: 3
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: { precision: 0 }
                    },
                    x: {
                        grid: { display: false }
                    }
                }
            }
        });
    }

    // Threat Distribution (Donut Chart)
    var threatCtx = document.getElementById('webdecoyThreatChart');
    if (threatCtx && data.threats.labels.length > 0) {
        new Chart(threatCtx.getContext('2d'), {
            type: 'doughnut',
            data: {
                labels: data.threats.labels,
                datasets: [{
                    data: data.threats.data,
                    backgroundColor: data.threats.labels.map(function(l) {
                        return threatColors[l] || '#999';
                    }),
                    borderWidth: 2,
                    borderColor: '#fff'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { padding: 16 }
                    }
                }
            }
        });
    }

    // Top Signals (Horizontal Bar Chart)
    var signalsCtx = document.getElementById('webdecoySignalsChart');
    if (signalsCtx && data.signals.labels.length > 0) {
        new Chart(signalsCtx.getContext('2d'), {
            type: 'bar',
            data: {
                labels: data.signals.labels.map(function(l) {
                    return l.replace(/_/g, ' ');
                }),
                datasets: [{
                    label: 'Count',
                    data: data.signals.data,
                    backgroundColor: colors.warning,
                    borderColor: colors.warning,
                    borderWidth: 1,
                    borderRadius: 3
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: {
                        beginAtZero: true,
                        ticks: { precision: 0 }
                    }
                }
            }
        });
    }
})();
