# Checkout IP history before the proxy-resolution fix

Before the fix for WebDecoy/app#878, WooCommerce checkout attempts used a
collector without the plugin's configured trusted proxies. On proxied stores,
those records can contain the proxy address instead of the shopper address.

Treat IP-based checkout velocity and card-testing history from versions without
this fix as unreliable on those stores. The affected rows do not retain enough
forwarding evidence to reconstruct the original shopper IP safely, so no
automatic backfill is performed. Do not interpret a shared proxy address as one
shopper or use it to justify a sitewide block.

Record the site's plugin upgrade time when deploying this fix; only subsequent
checkout attempts use the same configured resolver as the rest of the plugin.
