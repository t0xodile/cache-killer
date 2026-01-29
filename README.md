<h1>Gotta Cache Em All: Bending the rules of web cache exploitation</h1>

Welcome to the repo. This repository contains all the materials for my talk "Gotta Cache Em All: Bending the rules of web cache exploitation".

You can read about this research at:

https://portswigger.net/research/gotta-cache-em-all

CacheKiller contains a tool to discover URL parsing discrepancies and the different arbitrary cache poisoning and deception described in my BlackHat and DEF CON talk.

We've created a Web Security Academy topic to learn the web cache deception attacks and to try out your new skills.

## Documentation

### Building

Requires Java 21.

```bash
./gradlew build
```

The built JAR is output to `build/libs/` and can be loaded into Burp Suite via **Extensions > Installed > Add**.

### Scans

The extension adds four scans, accessible by right-clicking any request in Burp or via the command pallet.

#### Delimiters Finder

Finds characters that are interpreted differently by the origin server and the cache. This is useful as a first step before running the other scans.

**Options:**
- **Payload list** - The set of characters to test. Choose from ASCII Extended, ASCII with encoded variants, or a custom file.
- **Full Sitemap Scan** - When enabled, tests all requests in the sitemap for the target host instead of just the selected request.
- **Detect sub hosts delimiters** - Also test subdomains of selected request's host.
- **Detect Key delimiters** - Check whether discovered delimiters affect the cache key.

#### Normalization Probe

Checks how the origin and cache each handle path normalization, such as dot-segments, backslashes, double slashes, and encoded characters.

**Options:**
- **Full Sitemap Scan** - Test all sitemap requests for the host.
- **Detect sub hosts normalization** - Also test subdomains of selected requests's host.
- **Detect Key normalization** - Check normalization behaviour at the cache level.

#### Web Cache Deception Scan

Tests whether an attacker could trick the cache into storing sensitive responses under an attacker-controlled URL.

**Options:**
- **Delimiters list** - Characters to use as delimiters. Choose a built-in list or import from a file.
- **Static extension list** - File extensions to append (e.g. `.js`, `.css`). Choose a simple list, an extended list, or import from a file.
- **Static directories list** - Directory prefixes to try (e.g. `/static/`, `/assets/`). Choose classic directories, auto-detect from the sitemap, or import from a file.
- **Full Sitemap Scan** - Test all sitemap requests for the host.
- **Detect sub hosts delimiters** - Also test subdomains of selected request's host.

#### Web Cache Poisoning Scan

Tests whether normalization differences between the origin and cache allow an attacker to poison shared cache entries.

**Options:**
- **Delimiters list** - Characters to use as delimiters. Choose a built-in list or import from a file.
- **Full Sitemap Scan** - Test all sitemap requests for the host.
- **Detect sub hosts** - Also test subdomains of selected request's host.

### Custom Payload Files

All scans support importing custom lists from a file. The expected format is one item per line, UTF-8 encoded.
