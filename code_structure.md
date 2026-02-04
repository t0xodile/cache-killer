# Cache Killer - Technical Documentation

## Table of Contents

1. [Scan Types - Detailed Breakdown](#scan-types---detailed-breakdown)
2. [Best Practices](#best-practices)

---

## Scan Types - Detailed Breakdown

### Delimiter Finder Scan

**Purpose:** Identifies characters that act as path delimiters at the origin or (optionally) in the cache key.

#### Dialog Options

**Payload List:**
- **Select from file**: Custom delimiter list from user-provided file
- **ASCII - Extended**: Characters 0x00-0xFF (256 characters)
- **ASCII (with encoded) - Extended**: ASCII chars + URL-encoded variants (512 payloads)

**Scan Options:**
- **Full Sitemap Scan**: Scan all requests in Burp sitemap for the target host(s)
- **Detect sub hosts delimiters**: Include subdomains in scan (e.g., api.example.com when scanning example.com)
- **Detect Key delimiters**: Also detect delimiters used by cache (requires cached requests)

#### Requirements

✅ **Origin Delimiter Detection:**
- Valid HTTP response (status code 200-399)
- Dynamic (non-cached) requests available
- Origin must return different status codes for valid vs invalid paths

✅ **Key Delimiter Detection:**
- At least one cached (static) request
- Cache must provide detectable cache-hit indicators (Age header, X-Cache: hit, etc.)
- Request path without query string

---

### Normalization Probe Scan

**Purpose:** Detects how origin / cache normalize request paths / cache keys. 

#### Dialog Options

**Scan Options:**
- **Full Sitemap Scan**: Scan all requests in Burp sitemap
- **Detect sub hosts normalization**: Include subdomains
- **Detect Key normalization**: Test cache key normalization (requires cached requests)

#### Requirements

✅ **Origin Normalization:**
- Path with 2+ characters
- Valid response (status code 200-399)
- Origin returns different status for valid vs invalid paths

✅ **Key Normalization:**
- Cached request available
- Detectable cache-hit indicators
- Path with 2+ characters

#### 10 Normalization Techniques Tested

| Index | Name | Test Path | Expected Normalized | Description |
|-------|------|-----------|---------------------|-------------|
| 0 | SINGLE_DOT | `/.` + path | path | Single dot handling |
| 1 | DOT_SEGMENT | `/aaa/..` + path | path | Dot-segment removal |
| 2 | BACKSLASH_DOT_SEGMENT | `/aaa\..` + path | path | Backslash dot-segment |
| 3 | MULTI_SLASH | `///` + path | path | Multiple slash removal |
| 4 | BACK_SLASH | Replace `/` with `\` | original | Backslash to slash conversion |
| 5 | ENCODED_SLASH | Replace `/` with `%2f` | original | Encoded slash handling |
| 6 | ENCODED_BACKSLASH | Replace `/` with `%5c` | original | Encoded backslash handling |
| 7 | ENCODED_SEGMENT | `/aaa%2f..` + path | path | Encoded slash in dot-segment |
| 8 | ENCODED_BACK_SEGMENT | `/aaa%5c..` + path | path | Encoded backslash in dot-segment |
| 9 | PATH_DECODING | URL-encode entire path | original | Full path URL decoding |
| 10* | IS_QUERY_KEYED | Add cache buster param | N/A | Query string in cache key (cache-only) |

*Index 10 only applies to key normalization detection

---

### Web Cache Deception Scan

**Purpose:** Exploits cache behavior to serve cached sensitive responses to unauthorized users, causing victim data to be accessible via a cacheable static path.

#### Three Exploitation Techniques

**1. Static Extension Rule Exploitation**
- Delimiter at origin server allows appending fake extension: `/account/.js`
- Cache treats as static file, caches response
- Attacker fetches cached victim data

**2. Cache Key Normalization Exploitation**
- Cache normalizes path: `/account;/../static/file.js` → `/static/file.js`
- Origin doesn't normalize and has valid delimiter, returns `/account` data
- Attacker fetches cached victim data

**3. Origin Normalization Exploitation**
- Origin normalizes: `/static/../account` → `/account`
- Cache doesn't normalize, and caches anything in `/static/...` 
- Attacker fetches cached victim data

#### Dialog Options

**Delimiters List:**
- Select from file 
- ASCII - Extended 
- ASCII (with encoded) - Extended

**Static Extension List:**
- **Select from file**: Custom extension list
- **simple list (js, ico, exe)**: 5 common static extensions
- **extended list (css, js, ico, exe, png)**: 38 extensions from SecLists

**Static Directories List:**
- **Select from file**: Custom directory list
- **Use classic static directories**: `/static`, `/resources`, `/public`, `/assets`, `/wp-content`, `/media`, `images`
- **Detect static directories (slow)**: Auto-detect from sitemap static requests

**Scan Options:**
- **Full Sitemap Scan**: Scan all sitemap requests
- **Detect sub hosts delimiters**: Include subdomains
- **Report detection results**: Create Burp issues for delimiter/normalization detections even if cache deception was not found

#### Requirements

✅ **All Techniques:**
- Dynamic (non-cached) request available
- Valid response from dynamic request

✅ **Extension Rule:**
- Origin delimiters detected
- No key delimiters that matches the origin delimiter 

✅ **Normalization Exploits:**
- Cache or origin normalization detected
- Static directories accessible
- Either cache key or origin normalization enabled

---

### Web Cache Poisoning Scan

**Purpose:** Exploits normalization and delimiter discrepancies to poison cache entries, causing the cache to serve incorrect content to all users.

#### Two Exploitation Vectors

**Vector 1: Normalizing Cache Key (Origin Delimiter + Cache Key Normalization)**

Attack Flow:
1. Cache normalizes path: `/static/file.js<delim>/../random` → `/static/random`
2. Origin doesn't normalize, sees delimiter: `/static/file.js`
3. Attacker requests: `/static/file.js;/../malicious`
4. Response from `/static/file.js` cached under key `/static/malicious`
5. Victim requests: `/static/malicious` → gets poisoned `/static/file.js` content

**Vector 2: Normalizing Origin (Key Delimiter + Origin Normalization)**

Attack Flow:
1. Origin normalizes: `/random<delim>/..` + path → path
2. Cache doesn't normalize: keys as `/random<delim>/..` + path
3. Attacker requests: `/malicious;/../static/file.js`
4. Origin returns `/static/file.js`, cached under `/malicious;/..` + path
5. Victim requests: `/malicious` → gets `/static/file.js` content

#### Dialog Options

**Delimiters List:**
- Select from file 
- ASCII - Extended
- ASCII (with encoded) - Extended

**Scan Options:**
- **Full Sitemap Scan**: Scan all sitemap requests
- **Detect sub hosts**: Include subdomains

#### Requirements

✅ **Both Vectors:**
- Delimiter detection successful (origin and key)
- At least one cached static request
- Normalization detection successful

✅ **Vector 1:**
- Origin delimiter exists that's NOT a key delimiter
- Cache performs DOT_SEGMENT normalization

✅ **Vector 2:**
- Key delimiter exists that's NOT an origin delimiter
- Origin performs DOT_SEGMENT normalization

---

## Best Practices

### When to Use Full Sitemap Scan

✅ **Enable Full Sitemap Scan when:**
- Testing a new target for the first time (comprehensive discovery)
- Selected requests don't include static resources
- You need to find all vulnerable endpoints
- Time is not critical (it will take a while to finish)

❌ **Skip Full Sitemap Scan when:**
- Quickly testing a specific endpoint
- Sitemap is very large - use filtered selection
- You know the selected requests are sufficient

---

### When to Detect Sub Hosts

✅ **Enable Sub Hosts Detection when:**
- Application uses microservices architecture (`api.example.com`, `auth.example.com`)
- CDN serves multiple subdomains (`cdn1.example.com`, `cdn2.example.com`)
- Sitemap contains multiple subdomain entries
- Shared cache infrastructure across subdomains is likely

❌ **Disable Sub Hosts Detection when:**
- Testing single subdomain in isolation
- Subdomains use completely different infrastructure
- You know subdomains have different cache configurations
- Performance is critical (reduces request count)

**Example Decision:**

```
Sitemap shows:
  www.example.com (10 requests)
  api.example.com (50 requests)
  cdn.example.com (200 requests)

Server headers show:
  All three: Via: 1.1 cloudflare

Decision: Enable sub hosts detection
Reason: Shared Cloudflare cache likely has shared behavior
```
---

### Caching Issues

**Problem: "No cached requests found"**

This is the most common issue preventing key delimiter and key normalization detection.

**Troubleshooting Steps:**

1. **Verify cache headers in Burp HTTP history:**
   - Look for: Age, X-Cache, CF-Cache-Status, Server-Timing

2. **Try browsing static resources:**
   - Visit `/favicon.ico`, `/robots.txt`, CSS files
   - Add these to Burp sitemap
   - Rerun scan with those requests selected

3. **Check cache warming:**
   - Some caches require 2-3 requests before caching
   - The extension attempts this automatically
   - Try manually requesting static files multiple times

4. **Use Full Sitemap Scan:**
   - Increases chance of finding cached resources
   - Extension probes fallback paths automatically

5. **Populate the sitemap with more data:**
   - Check you are not filtering out static files
