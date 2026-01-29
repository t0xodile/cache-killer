package extensions.cachekiller.Workers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import extensions.cachekiller.Utils.Server;

import java.util.*;
import java.util.concurrent.TimeUnit;

import static extensions.cachekiller.Utils.Server.sendHTTP1Request;

public class CacheDeceptionScanWorker extends ScanWorker {

    private final List<String> testDelimitersList;
    private final List<String> extensions;
    private List<String> staticDirs;
    public static final List<Character> BROWSER_ENCODED = new ArrayList<>(Arrays.asList('"', '^', '{', '}', '`','|','<','>','#','?','\\'));


    public CacheDeceptionScanWorker(MontoyaApi api, List<HttpRequestResponse> requestResponse, List<String> testDelimitersList, boolean fullSiteMap, boolean subHosts, List<String> extensions, List<String> staticDirs){
        super(api, requestResponse, fullSiteMap, subHosts);
        this.extensions = new ArrayList<>(extensions);
        if (staticDirs == null) this.staticDirs = null;
        else this.staticDirs = new ArrayList<>(staticDirs);
        this.testDelimitersList = new ArrayList<>(testDelimitersList);
    }

    public void scan(){
        api.logging().logToOutput("[CacheDeceptionScan] Scan started");
        HashMap<String, Server> servers = getServers();
        api.logging().logToOutput("[CacheDeceptionScan] Found " + servers.size() + " server group(s) to test");
        if (servers.isEmpty()) {
            api.logging().logToOutput("[CacheDeceptionScan] No servers found. Ensure the selected request returns a valid response.");
            return;
        }
        for (Server serv : servers.values()){
            api.logging().logToOutput("[CacheDeceptionScan] Detecting origin delimiters...");
            serv.detectOriginDelimiters(testDelimitersList);
            api.logging().logToOutput("[CacheDeceptionScan] Detecting key delimiters...");
            serv.detectKeyDelimiters(testDelimitersList);
            api.logging().logToOutput("[CacheDeceptionScan] Detecting origin normalization...");
            serv.detectOriginNormalization();
            api.logging().logToOutput("[CacheDeceptionScan] Detecting key normalization...");
            serv.detectKeyNormalization();
            if (serv.getOriginDelimiters() == null && serv.getKeyDelimiters() == null && serv.getOriginNormalization() == null && serv.getKeyNormalization() == null) {
                api.logging().logToOutput("[CacheDeceptionScan] Skipping server: no detection results.");
                continue;
            }
            api.logging().logToOutput("[CacheDeceptionScan] Detection results (originDelimiters=" + (serv.getOriginDelimiters() != null) + ", keyDelimiters=" + (serv.getKeyDelimiters() != null) + ", originNorm=" + (serv.getOriginNormalization() != null) + ", keyNorm=" + (serv.getKeyNormalization() != null) + ").");

            //Delimiter Scan
            if (serv.getOriginDelimiters() != null && serv.getKeyDelimiters() != null) {
                List<String> discrepancyOriginDelimiters = new ArrayList<>();
                for (String delim : serv.getOriginDelimiters()) {
                    if (isSentByBrowser(delim) && !serv.getKeyDelimiters().contains(delim))
                        discrepancyOriginDelimiters.add(delim);
                }
                List<HttpRequestResponse[]> vulnerableExtension;
                for (String delim : discrepancyOriginDelimiters) {
                    vulnerableExtension = testExtensionRule(serv, delim, this.extensions);
                    for (HttpRequestResponse[] vuln : vulnerableExtension) {
                        reportIssue("Web Cache Deception Detected", "The target appears to be vulnerable to Web Cache Deception using the Delimiter: '" + ScanWorker.printableStr(delim) + "' and the Static Extensions rule<br><br>If the response contains sensitive information this could be used to hijack victim's data.", AuditIssueSeverity.HIGH, vuln[0], vuln[1]);
                    }
                }
            }
            if (this.staticDirs == null) {
                this.staticDirs = new ArrayList<>(detectStaticDirectories(serv));
            }
            for (String fallback : List.of("/robots.txt", "/favicon.ico", "/index.html", "/home", "/resources")) {
                if (!this.staticDirs.contains(fallback)) {
                    this.staticDirs.add(fallback);
                }
            }

            //Cache key normalization scan
            if (serv.getKeyNormalization() != null && serv.getKeyNormalization()[Server.ENCODED_SEGMENT] && serv.getOriginDelimiters() != null){
                for (HttpRequestResponse reqResp : serv.getDynamicRequest()) {
                    if (reqResp.request().pathWithoutQuery().length()<2) continue;
                    for (String delimiter : serv.getOriginDelimiters()) {
                        if (!isSentByBrowser(delimiter)) continue;
                        for (String dir : this.staticDirs) {
                            StringBuilder sb = new StringBuilder();
                            sb.append(reqResp.request().pathWithoutQuery());
                            sb.append(delimiter);
                            sb.append("%2F");
                            for (String s : Server.splitPathSegments(reqResp.request().pathWithoutQuery())) {
                                sb.append("..%2F");
                            }
                            sb.append(dir.startsWith("/") ? dir.substring(1) : dir);
                            HttpRequestResponse testReq = sendHTTP1Request(reqResp.request().withPath(sb.toString()));
                            HttpRequestResponse cachedResp = detectCacheDeception(testReq, reqResp);
                            if (cachedResp != null){
                                reportIssue("Web Cache Deception Detected", "The target appears to be vulnerable to Web Cache Deception with Cache Key Normalization.<br>The path : '"+dir+"' appears to be a Static Directory.<br>The Origin Delimiter used is: '"+ScanWorker.printableStr(delimiter)+"'.", AuditIssueSeverity.HIGH, testReq, cachedResp);
                            }
                        }
                    }
                }
            }

            //Cache key normalization scan (backslash)
            if (serv.getKeyNormalization() != null && serv.getKeyNormalization()[Server.ENCODED_BACK_SEGMENT] && serv.getOriginDelimiters() != null){
                for (HttpRequestResponse reqResp : serv.getDynamicRequest()) {
                    if (reqResp.request().pathWithoutQuery().length()<2) continue;
                    for (String delimiter : serv.getOriginDelimiters()) {
                        if (!isSentByBrowser(delimiter)) continue;
                        for (String dir : this.staticDirs) {
                            StringBuilder sb = new StringBuilder();
                            sb.append(reqResp.request().pathWithoutQuery());
                            sb.append(delimiter);
                            sb.append("%5C");
                            for (String s : Server.splitPathSegments(reqResp.request().pathWithoutQuery())) {
                                sb.append("..%5C");
                            }
                            sb.append(dir.startsWith("/") ? dir.substring(1) : dir);
                            HttpRequestResponse testReq = sendHTTP1Request(reqResp.request().withPath(sb.toString()));
                            HttpRequestResponse cachedResp = detectCacheDeception(testReq, reqResp);
                            if (cachedResp != null){
                                reportIssue("Web Cache Deception Detected", "The target appears to be vulnerable to Web Cache Deception with Cache Key Backslash Normalization.<br>The path : '"+dir+"' appears to be a Static Directory.<br>The Origin Delimiter used is: '"+ScanWorker.printableStr(delimiter)+"'.", AuditIssueSeverity.HIGH, testReq, cachedResp);
                            }
                        }
                    }
                }
            }

            //Origin normalizaiton scan
            if (serv.getOriginNormalization() != null && serv.getOriginNormalization()[Server.ENCODED_SEGMENT]){
                for (HttpRequestResponse reqResp : serv.getDynamicRequest()) {
                    if (reqResp.request().pathWithoutQuery().length()<2) continue;
                    for (String dir : this.staticDirs) {
                        StringBuilder sb = new StringBuilder();
                        sb.append(dir);
                        if (!dir.endsWith("/")) sb.append("/");
                        for (String s : Server.splitPathSegments(dir)) {
                            sb.append("..%2F");
                        }
                        sb.append(reqResp.request().path().substring(1));
                        HttpRequestResponse testReq = sendHTTP1Request(reqResp.request().withPath(sb.toString()));
                        HttpRequestResponse cachedResp = detectCacheDeception(testReq, reqResp);
                        if (cachedResp != null){
                            reportIssue("Web Cache Deception Detected", "The target appears to be vulnerable to Web Cache Deception with Origin Server Normalization.<br>The path : '"+dir+"' appears to be a Static Directory.", AuditIssueSeverity.HIGH, testReq, cachedResp);
                        }
                    }
                }
            }

            //Origin normalization Scan
            if (serv.getOriginNormalization() != null && serv.getOriginNormalization()[Server.ENCODED_BACK_SEGMENT]){
                for (HttpRequestResponse reqResp : serv.getDynamicRequest()) {
                    if (reqResp.request().pathWithoutQuery().length()<2) continue;
                    for (String dir : this.staticDirs) {
                        StringBuilder sb = new StringBuilder();
                        sb.append(dir);
                        if (!dir.endsWith("/")) sb.append("/");
                        for (String s : Server.splitPathSegments(dir)) {
                            sb.append("..%5C");
                        }
                        sb.append(reqResp.request().path().substring(1));
                        HttpRequestResponse testReq = sendHTTP1Request(reqResp.request().withPath(sb.toString()));
                        HttpRequestResponse cachedResp = detectCacheDeception(testReq, reqResp);
                        if (cachedResp != null){
                            reportIssue("Web Cache Deception Detected", "The target appears to be vulnerable to Web Cache Deception with Origin Server Backslash Normalization.<br>The path : '"+dir+"' appears to be a Static Directory.", AuditIssueSeverity.HIGH, testReq, cachedResp);
                        }
                    }
                }
            }

        }
    }


    public List<HttpRequestResponse[]> testExtensionRule(Server server, String delimiter, List<String> extensions){
        List<HttpRequestResponse[]> out = new ArrayList<>();
        for (HttpRequestResponse reqResp : server.getDynamicRequest()) {
            HttpRequestResponse testReq = sendHTTP1Request(setPathSuffix(reqResp.request(), delimiter+(delimiter.equals(".") ? ".": "")+"aaaaa"));
            if (testReq.hasResponse() && testReq.response().statusCode() != 0 && compareResp(testReq.response(), reqResp.response())) {
                for (String ext : extensions) {
                    HttpRequestResponse initialReq = sendHTTP1Request(setPathSuffix(reqResp.request(), delimiter + (delimiter.equals(".") ? "" : ".") + ext));
                    boolean cached = triggerCache(initialReq.request());
                    HttpRequestResponse cachedReq = sendHTTP1Request(initialReq.request());
                    if (cached || !containSameCacheHeaders(cachedReq, reqResp)) {
                        out.add(new HttpRequestResponse[]{initialReq, cachedReq});
                    }
                }
            }
        }
        return out;
    }

    public HttpRequestResponse detectCacheDeception(HttpRequestResponse testReq, HttpRequestResponse baseReqResp){
        if (testReq.hasResponse() && testReq.response().statusCode() != 0 && compareResp(testReq.response(), baseReqResp.response())) {
            boolean cached = triggerCache(testReq.request());
            HttpRequestResponse cachedResp = sendHTTP1Request(testReq.request());
            if (cached || !containSameCacheHeaders(cachedResp, baseReqResp)) {
                return cachedResp;
            }
        }
        return null;
    }


    public boolean triggerCache(HttpRequest request){
        boolean done = false;
        HttpRequestResponse testGet = sendHTTP1Request(request);
        if (testGet.hasResponse() && hasCacheHit(testGet.response())) done = true;
        if (!done) {
            try {
                TimeUnit.SECONDS.sleep(1);
            } catch (InterruptedException ignored) {
            }
            testGet = sendHTTP1Request(testGet.request());
            if (testGet.hasResponse() && hasCacheHit(testGet.response())) done = true;
        }
        if (!done) {
            try {
                TimeUnit.SECONDS.sleep(1);
            } catch (InterruptedException ignored) {
            }
            testGet = sendHTTP1Request(testGet.request());
            if (testGet.hasResponse() && hasCacheHit(testGet.response())) done = true;
        }
        int retries = 0;
        while (!(testGet.hasResponse() && testGet.response().statusCode() != 0) && retries < 5){
            try {
                TimeUnit.SECONDS.sleep(2);
            } catch (InterruptedException ignored) {
            }
            testGet = sendHTTP1Request(testGet.request());
            if (testGet.hasResponse() && hasCacheHit(testGet.response())) done = true;
            retries++;
        }
        return done;
    }

    public static boolean hasCacheHit(HttpResponse cacheableResponse) {

        for (HttpHeader hdr : cacheableResponse.headers()) {
            String name = hdr.name().toLowerCase();
            String value = hdr.value().toLowerCase();
            if ((name.contains("-cache-") || name.startsWith("cache-") || name.endsWith("-cache") || name.contains("server-timing")) && (value.toLowerCase().contains("hit") || value.toLowerCase().contains("served"))) {
                return true;
            }
        }

        return cacheableResponse.hasHeader("Age");
    }


    public Map<String, String> getCacheHeaders(HttpResponse cacheableResponse){
        Map<String, String> headers = new HashMap<>();
        for (HttpHeader hdr : cacheableResponse.headers()) {
            String name = hdr.name().toLowerCase();
            String value = hdr.value().toLowerCase();
            if ((name.contains("-cache-") || name.startsWith("cache-") || name.endsWith("-cache")) && (value.toLowerCase().contains("hit"))) {
                headers.put(hdr.name(), hdr.value());
            }
        }
        return headers;
    }

    public boolean containSameCacheHeaders(HttpRequestResponse r1, HttpRequestResponse r2){
        Map<String, String> h1, h2;
        h1 = getCacheHeaders(r1.response());
        h2 = getCacheHeaders(r2.response());
        if (h1.size() != h2.size()) return false;
        for (String name : h1.keySet()){
            if (!h2.containsKey(name)) return false;
            if (!h1.get(name).equals(h2.get(name))) return false;
        }
        return true;
    }

    public static boolean compareResp(HttpResponse r1, HttpResponse r2){
        return  (r1 != null && r2 != null && r1.statusCode() != 0 && r1.statusCode() == r2.statusCode() && (Math.abs(r1.body().length()-r2.body().length())<20) && compareHeader(r1, r2, "content-type") && compareHeader(r1, r2, "server") && compareHeader(r1, r2, "vary"));
    }

    public static boolean compareHeader(HttpResponse r1, HttpResponse r2, String header){
        if (r1 != null && r2 != null){
            if (r1.hasHeader(header) && r2.hasHeader(header)){
                return r1.header(header).value().equals(r2.header(header).value());
            }
            else return (r1.hasHeader(header) == r2.hasHeader(header));
        }
        else return (r1 == r2);
    }
    public static HttpRequest setPathSuffix(HttpRequest base, String suffix){
        if (!base.path().contains("?")) return base.withPath(base.path()+suffix);
        return base.withPath(base.path().substring(0, base.path().indexOf("?"))+suffix+base.path().substring(base.path().indexOf("?")));
    }

    public static boolean isSentByBrowser(String delimiter){
        for (char c : delimiter.toCharArray()){
            if (BROWSER_ENCODED.contains(c)) return false;
            if (c<32 || c>126) return false;
        }
        return true;
    }

    public List<String> detectStaticDirectories(Server server){
        Set<String> seen = new HashSet<>();
        List<String> out = new ArrayList<>();
        for (String path : server.getStaticRequestURLs()){
            ArrayList<String> segments = Server.splitPathSegments(path);
            if (!segments.isEmpty()) {
                String dir = "/" + segments.get(0);
                if (seen.add(dir)) out.add(dir);
            }
        }
        return out;
    }

}