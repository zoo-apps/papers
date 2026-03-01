# Cloudflare Configuration for papers.zoo.ngo

## Current Issues

The site is experiencing Cloudflare-related console errors:

1. **Cloudflare Beacon Script Errors**:
   - CORS policy blocking beacon.min.js
   - Subresource Integrity (SRI) hash mismatch

2. **Root Cause**: Cloudflare automatically injects tracking/analytics scripts when certain features are enabled.

## Recommended Cloudflare Settings

To eliminate console errors and improve performance, configure the following in your Cloudflare dashboard for `papers.zoo.ngo`:

### 1. Disable Automatic Script Injection

Navigate to: **Speed** → **Optimization**

- ✅ **Rocket Loader**: OFF (can break inline scripts)
- ✅ **Auto Minify**: Use only CSS and HTML (disable JavaScript)

Navigate to: **Security** → **Bots**

- ✅ **Browser Integrity Check**: Optional (can be ON)
- ⚠️ **Bot Fight Mode**: OFF (injects challenge scripts)

Navigate to: **Analytics** → **Web Analytics**

- ✅ **Browser Insights**: OFF (injects beacon.min.js)
- Alternative: Use server-side analytics instead

### 2. Caching Configuration

Navigate to: **Caching** → **Configuration**

- ✅ **Caching Level**: Standard
- ✅ **Browser Cache TTL**: Respect Existing Headers
- ✅ **Always Online**: ON (good for static sites)

### 3. Page Rules (Optional Performance Boost)

Create a page rule for `papers.zoo.ngo/*`:

- ✅ **Cache Level**: Cache Everything
- ✅ **Edge Cache TTL**: 1 month (2592000 seconds)
- ✅ **Browser Cache TTL**: 1 day (86400 seconds)

### 4. SSL/TLS Settings

Navigate to: **SSL/TLS** → **Overview**

- ✅ **SSL/TLS encryption mode**: Full (strict)
- ✅ **Always Use HTTPS**: ON
- ✅ **Minimum TLS Version**: TLS 1.2

### 5. DNS Settings

Ensure DNS record for `papers.zoo.ngo`:

- ✅ **Type**: CNAME or A record
- ✅ **Proxied**: Orange cloud (proxied through Cloudflare)
- ✅ **TTL**: Auto

## Testing After Changes

1. Clear Cloudflare cache: **Caching** → **Configuration** → **Purge Everything**
2. Hard refresh browser: `Cmd+Shift+R` (Mac) or `Ctrl+Shift+R` (Windows/Linux)
3. Open DevTools console and verify no errors

## Alternative: Disable Cloudflare Proxy (Not Recommended)

If you want to completely avoid Cloudflare script injection:

1. In DNS settings, click the orange cloud to make it gray (DNS only)
2. This disables all Cloudflare features (caching, security, etc.)
3. **Not recommended** - you lose CDN benefits

## Current Site Status

✅ **Jekyll theme disabled** - Prevents `scale.fix.js` loading errors
✅ **Static HTML generation** - No external dependencies
✅ **Minimal external resources** - Only favicon and PDFs
⚠️ **Cloudflare scripts** - Need dashboard configuration (see above)

## Support

For Cloudflare-specific issues:
- [Cloudflare Support](https://support.cloudflare.com/)
- [Cloudflare Community](https://community.cloudflare.com/)

For site code issues:
- [GitHub Repository](https://github.com/zooai/papers)
- [GitHub Issues](https://github.com/zooai/papers/issues)
