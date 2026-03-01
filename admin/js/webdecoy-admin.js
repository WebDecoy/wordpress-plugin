/**
 * WebDecoy Admin JavaScript
 *
 * @package WebDecoy
 */

(function($) {
    'use strict';

    /**
     * WebDecoy Admin Module
     */
    var WebDecoyAdmin = {
        /**
         * Initialize
         */
        init: function() {
            this.bindEvents();
            this.initTabs();
            this.initPasswordToggle();
        },

        /**
         * Bind event handlers
         */
        bindEvents: function() {
            // Connection test
            $(document).on('click', '#webdecoy-test-connection', this.testConnection);

            // Quick block from detections page
            $(document).on('click', '.webdecoy-quick-block', this.quickBlock);

            // Unblock confirmation
            $(document).on('click', '.webdecoy-unblock', this.confirmUnblock);

            // Tab navigation
            $(document).on('click', '.webdecoy-settings-wrap .nav-tab', this.switchTab);

            // Password visibility toggle
            $(document).on('click', '.webdecoy-toggle-visibility', this.togglePasswordVisibility);

            // Select all good bots in category
            $(document).on('change', '.webdecoy-category-toggle', this.toggleCategory);
        },

        /**
         * Initialize tabs on page load
         */
        initTabs: function() {
            // Check URL hash for active tab
            var hash = window.location.hash;
            if (hash && $(hash + '-tab').length) {
                this.activateTab(hash.substring(1));
            }
        },

        /**
         * Initialize password toggle buttons
         */
        initPasswordToggle: function() {
            // Wrap API key inputs with toggle button
            $('input[name*="api_key"]').each(function() {
                var $input = $(this);
                if (!$input.parent().hasClass('webdecoy-api-key-field')) {
                    $input.wrap('<span class="webdecoy-api-key-field"></span>');
                    $input.after(
                        '<button type="button" class="webdecoy-toggle-visibility" aria-label="' +
                        webdecoyAdmin.strings.toggleVisibility + '">' +
                        '<span class="dashicons dashicons-visibility"></span></button>'
                    );
                }
            });
        },

        /**
         * Test API connection
         */
        testConnection: function(e) {
            e.preventDefault();

            var $button = $(this);
            var $result = $('#webdecoy-connection-status');

            // Get API key from form
            var apiKey = $('#webdecoy_api_key').val();

            // Disable button and show loading
            $button.prop('disabled', true);
            $result.removeClass('success error').html(
                '<span class="spinner is-active" style="float:none;margin:0 5px 0 0;"></span>' +
                webdecoyAdmin.strings.testing
            ).show();

            // Make AJAX request
            $.ajax({
                url: webdecoyAdmin.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'webdecoy_test_connection',
                    nonce: webdecoyAdmin.nonce,
                    api_key: apiKey
                },
                success: function(response) {
                    if (response.success) {
                        var msg = $('<span>').text(response.data.message);
                        $result.addClass('success').html('<span class="dashicons dashicons-yes-alt"></span> ').append(msg);
                    } else {
                        var errMsg = $('<span>').text(response.data.message);
                        $result.addClass('error').html('<span class="dashicons dashicons-warning"></span> ').append(errMsg);
                    }
                },
                error: function(xhr, status, error) {
                    $result.addClass('error').html(
                        '<span class="dashicons dashicons-warning"></span> ' +
                        webdecoyAdmin.strings.connectionFailed + ': ' + error
                    );
                },
                complete: function() {
                    $button.prop('disabled', false);
                }
            });
        },

        /**
         * Quick block IP from detections page
         */
        quickBlock: function(e) {
            var ip = $(this).data('ip');
            if (!confirm(webdecoyAdmin.strings.confirmBlock.replace('%s', ip))) {
                e.preventDefault();
                return false;
            }
        },

        /**
         * Confirm unblock action
         */
        confirmUnblock: function(e) {
            if (!confirm(webdecoyAdmin.strings.confirmUnblock)) {
                e.preventDefault();
                return false;
            }
        },

        /**
         * Switch between tabs
         */
        switchTab: function(e) {
            e.preventDefault();

            var tabId = $(this).attr('href').substring(1);
            WebDecoyAdmin.activateTab(tabId);

            // Update URL hash
            window.location.hash = tabId;
        },

        /**
         * Activate a specific tab
         */
        activateTab: function(tabId) {
            // Update tab buttons
            $('.webdecoy-settings-wrap .nav-tab').removeClass('nav-tab-active');
            $('.webdecoy-settings-wrap .nav-tab[href="#' + tabId + '"]').addClass('nav-tab-active');

            // Update tab content
            $('.webdecoy-tab-content').removeClass('active');
            $('#' + tabId + '-tab').addClass('active');
        },

        /**
         * Toggle password visibility
         */
        togglePasswordVisibility: function(e) {
            e.preventDefault();

            var $button = $(this);
            var $input = $button.siblings('input');
            var $icon = $button.find('.dashicons');

            if ($input.attr('type') === 'password') {
                $input.attr('type', 'text');
                $icon.removeClass('dashicons-visibility').addClass('dashicons-hidden');
            } else {
                $input.attr('type', 'password');
                $icon.removeClass('dashicons-hidden').addClass('dashicons-visibility');
            }
        },

        /**
         * Toggle all checkboxes in a category
         */
        toggleCategory: function() {
            var $toggle = $(this);
            var category = $toggle.data('category');
            var isChecked = $toggle.is(':checked');

            $('input[data-bot-category="' + category + '"]').prop('checked', isChecked);
        }
    };

    /**
     * Stats refresh module
     */
    var WebDecoyStats = {
        refreshInterval: null,

        /**
         * Initialize auto-refresh for stats
         */
        init: function() {
            // Only on dashboard widget or main pages
            if ($('.webdecoy-widget, .webdecoy-detection-stats').length) {
                this.startAutoRefresh();
            }
        },

        /**
         * Start auto-refresh timer
         */
        startAutoRefresh: function() {
            var self = this;

            // Refresh every 60 seconds
            this.refreshInterval = setInterval(function() {
                self.refreshStats();
            }, 60000);
        },

        /**
         * Refresh stats via AJAX
         */
        refreshStats: function() {
            $.ajax({
                url: webdecoyAdmin.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'webdecoy_get_stats',
                    nonce: webdecoyAdmin.nonce
                },
                success: function(response) {
                    if (response.success && response.data) {
                        WebDecoyStats.updateStatsDisplay(response.data);
                    }
                }
            });
        },

        /**
         * Update stats display with new data
         */
        updateStatsDisplay: function(data) {
            // Update detection stats
            if (data.detections) {
                $('.webdecoy-stat-total').text(data.detections.total);
                $('.webdecoy-stat-high-risk').text(data.detections.high_risk);
            }

            // Update blocked stats
            if (data.blocked) {
                $('.webdecoy-stat-blocked').text(data.blocked.active);
            }
        }
    };

    /**
     * Detections page module
     */
    var WebDecoyDetections = {
        /**
         * Initialize
         */
        init: function() {
            this.initFilters();
            this.initBulkActions();
            this.initExpandableRows();
        },

        /**
         * Initialize filter handling
         */
        initFilters: function() {
            // Auto-submit on filter change (optional UX enhancement)
            $('.webdecoy-filters select').on('change', function() {
                // Uncomment to auto-submit:
                // $(this).closest('form').submit();
            });
        },

        /**
         * Initialize bulk actions
         */
        initBulkActions: function() {
            // Select all checkbox
            $('#webdecoy-select-all').on('change', function() {
                var isChecked = $(this).is(':checked');
                $('.webdecoy-select-ip').prop('checked', isChecked);
                WebDecoyDetections.updateBulkButton();
            });

            // Individual checkbox change
            $(document).on('change', '.webdecoy-select-ip', function() {
                WebDecoyDetections.updateBulkButton();
            });

            // Bulk block action
            $('#webdecoy-bulk-block').on('click', function(e) {
                e.preventDefault();

                var selectedIPs = [];
                $('.webdecoy-select-ip:checked').each(function() {
                    selectedIPs.push($(this).val());
                });

                if (selectedIPs.length === 0) {
                    alert(webdecoyAdmin.strings.selectIPs);
                    return;
                }

                if (!confirm(webdecoyAdmin.strings.confirmBulkBlock.replace('%d', selectedIPs.length))) {
                    return;
                }

                WebDecoyDetections.bulkBlock(selectedIPs);
            });
        },

        /**
         * Update the bulk block button visibility and count
         */
        updateBulkButton: function() {
            var count = $('.webdecoy-select-ip:checked').length;
            var $btn = $('#webdecoy-bulk-block');
            var $count = $('#webdecoy-selected-count');

            if (count > 0) {
                $btn.show();
                $count.text(count);
            } else {
                $btn.hide();
                $count.text('0');
            }
        },

        /**
         * Initialize expandable detail rows
         */
        initExpandableRows: function() {
            $(document).on('click', '.webdecoy-expandable-row td:not(.check-column)', function() {
                var $row = $(this).closest('tr');
                var $detailRow = $row.next('.webdecoy-detail-row');
                $detailRow.toggle();
                $row.toggleClass('webdecoy-row-expanded');
            });
        },

        /**
         * Perform bulk block action
         */
        bulkBlock: function(ips) {
            $.ajax({
                url: webdecoyAdmin.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'webdecoy_bulk_block',
                    nonce: webdecoyAdmin.nonce,
                    ips: ips
                },
                success: function(response) {
                    if (response.success) {
                        alert(response.data.message);
                        location.reload();
                    } else {
                        alert(response.data.message || webdecoyAdmin.strings.error);
                    }
                },
                error: function() {
                    alert(webdecoyAdmin.strings.error);
                }
            });
        }
    };

    /**
     * Initialize on document ready
     */
    $(document).ready(function() {
        WebDecoyAdmin.init();
        WebDecoyStats.init();
        WebDecoyDetections.init();
    });

})(jQuery);
