package extensions.cachekiller.Workers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import extensions.cachekiller.Utils.Server;

import java.util.*;
import java.util.concurrent.TimeUnit;

import static extensions.cachekiller.Utils.Server.*;

public class CacheDeceptionScanWorker extends ScanWorker {

    record DetectionResult(HttpRequestResponse initialRequest, HttpRequestResponse cachedResponse,
                           boolean isFallback, String headerDiff) {}

    private final List<String> testDelimitersList;
    private final List<String> extensions;
    private List<String> staticDirs;
    private final boolean reportDetectionResults;
    private final HttpMode mode;
    public static final List<Character> BROWSER_ENCODED = new ArrayList<>(Arrays.asList('"', '^', '{', '}', '`','|','<','>','#','\\'));


    public CacheDeceptionScanWorker(MontoyaApi api, List<HttpRequestResponse> requestResponse, List<String> testDelimitersList, boolean fullSiteMap, boolean subHosts, List<String> extensions, List<String> staticDirs, boolean reportDetectionResults, boolean useHTTP2){
        super(api, requestResponse, fullSiteMap, subHosts);
        this.extensions = new ArrayList<>(extensions);
        if (staticDirs == null) this.staticDirs = null;
        else this.staticDirs = new ArrayList<>(staticDirs);
        this.testDelimitersList = new ArrayList<>(testDelimitersList);
        this.reportDetectionResults = reportDetectionResults;
        this.mode = useHTTP2 ? HttpMode.HTTP_2 : HttpMode.HTTP_1;
    }

    public void scan(){
        HashMap<String, Server> servers = getServers();
        if (servers.isEmpty()) {
            api.logging().logToOutput("[CacheDeceptionScan] No servers found. Ensure the selected request returns a valid response.");
            return;
        }
        for (Server serv : servers.values()){
            checkCancelled();
            if (serv.getDynamicRequest().isEmpty()) {
                api.logging().logToOutput("[CacheDeceptionScan] Skipping server group: no dynamic (non-cached) requests found. All selected requests appear to already be cached.");
                continue;
            }
            HttpRequestResponse originDelimReportReq = serv.detectOriginDelimiters(testDelimitersList, mode);
            HttpRequestResponse keyDelimReportReq = serv.detectKeyDelimiters(testDelimitersList, mode);
            HttpRequestResponse originNormReportReq = serv.detectOriginNormalization();
            HttpRequestResponse keyNormReportReq = serv.detectKeyNormalization();

            String host = serv.getDynamicRequest().getFirst().httpService().host();

            if (serv.getOriginDelimiters() == null && serv.getKeyDelimiters() == null && serv.getOriginNormalization() == null && serv.getKeyNormalization() == null) {
                api.logging().logToOutput("[CacheDeceptionScan] ["+host+"] Skipping server: no detection results.");
                continue;
            }

            //TODO this is dupe code for sure... clean up
            if (reportDetectionResults) {
                if (serv.getOriginDelimiters() != null && !serv.getOriginDelimiters().isEmpty()) {
                    StringBuilder sb = new StringBuilder();
                    for (String del : serv.getOriginDelimiters()) {
                        sb.append(printableStr(del));
                        sb.append("<br>");
                    }
                    reportIssue("Origin Delimiters", "The following characters where detected as Origin Delimiters:<br>"+sb.toString()+"<br><br>The following paths appear to share the same network components and should be affected:<br>"+serv.requestsToString(), AuditIssueSeverity.INFORMATION, originDelimReportReq);
                }
                if (serv.getKeyDelimiters() != null && !serv.getKeyDelimiters().isEmpty()) {
                    StringBuilder sb = new StringBuilder();
                    for (String del : serv.getKeyDelimiters()) {
                        sb.append(printableStr(del));
                        sb.append("<br>");
                    }
                    reportIssue("Key Delimiters", "The following characters where detected as Cache Delimiters:<br>"+sb.toString()+"<br><br>The following paths appear to share the same network components and should be affected:<br>"+serv.requestsToString(), AuditIssueSeverity.INFORMATION, keyDelimReportReq);
                } else if (keyDelimReportReq != null) {
                    reportIssue("Key Delimiters", "None of the tested characters are used as Key Delimiters for the following paths that share the same network components.<br>"+serv.requestsToString(), AuditIssueSeverity.INFORMATION, keyDelimReportReq);
                }
                if (serv.getOriginNormalization() != null) {
                    boolean[] normalizations = serv.getOriginNormalization();
                    StringBuilder sb = new StringBuilder();
                    sb.append("The following Normalization behaviour was detected at the origin server:<br>");
                    sb.append("Single dot normalized: ").append(normalizations[Server.SINGLE_DOT] ? "YES - /a/./b == /a/b" : "NO").append("<br>");
                    sb.append("Dot-segment normalized: ").append(normalizations[Server.DOT_SEGMENT] ? "YES - /a/../b == /b" : "NO").append("<br>");
                    sb.append("Backslash normalized: ").append(normalizations[Server.BACK_SLASH] ? "YES - /a\\b == /a/b" : "NO").append("<br>");
                    sb.append("Backslash dot-segment normalized: ").append(normalizations[Server.BACKSLASH_DOT_SEGMENT] ? "YES - /a/..\\b == /b" : "NO").append("<br>");
                    sb.append("Multi-slash removed: ").append(normalizations[Server.MULTI_SLASH] ? "YES - /a////b == /b" : "NO").append("<br>");
                    sb.append("Encoded slash normalized: ").append(normalizations[Server.ENCODED_SLASH] ? "YES - /a%2Fb == /a/b" : "NO").append("<br>");
                    sb.append("Encoded backslash normalized: ").append(normalizations[Server.ENCODED_BACKSLASH] ? "YES - /a%5Cb == /a/b" : "NO").append("<br>");
                    sb.append("Encoded dot-segment normalized: ").append(normalizations[Server.ENCODED_SEGMENT] ? "YES - /a/..%2Fb == /b" : "NO").append("<br>");
                    sb.append("Encoded backslash dot-segment normalized: ").append(normalizations[Server.ENCODED_BACK_SEGMENT] ? "YES - /a/..%5Cb == /b" : "NO").append("<br>");
                    sb.append("Path is URL decoded: ").append(normalizations[Server.PATH_DECODING] ? "YES - /%68%65%6c%6c%6f == /hello" : "NO").append("<br>");
                    sb.append("<br>The following paths appear to share the same network components and should be affected:<br>").append(serv.requestsToString());
                    reportIssue("Origin Normalization", sb.toString(), AuditIssueSeverity.INFORMATION, originNormReportReq);
                }
                if (serv.getKeyNormalization() != null) {
                    boolean[] normalizations = serv.getKeyNormalization();
                    StringBuilder sb = new StringBuilder();
                    sb.append("The following Normalization behaviour was detected at the cache proxy:<br>");
                    sb.append("Single dot normalized: ").append(normalizations[Server.SINGLE_DOT] ? "YES - /a/./b == /a/b" : "NO").append("<br>");
                    sb.append("Dot-segment normalized: ").append(normalizations[Server.DOT_SEGMENT] ? "YES - /a/../b == /b" : "NO").append("<br>");
                    sb.append("Backslash normalized: ").append(normalizations[Server.BACK_SLASH] ? "YES - /a\\b == /a/b" : "NO").append("<br>");
                    sb.append("Backslash dot-segment normalized: ").append(normalizations[Server.BACKSLASH_DOT_SEGMENT] ? "YES - /a/..\\b == /b" : "NO").append("<br>");
                    sb.append("Multi-slash removed: ").append(normalizations[Server.MULTI_SLASH] ? "YES - /a////b == /b" : "NO").append("<br>");
                    sb.append("Encoded slash normalized: ").append(normalizations[Server.ENCODED_SLASH] ? "YES - /a%2Fb == /a/b" : "NO").append("<br>");
                    sb.append("Encoded backslash normalized: ").append(normalizations[Server.ENCODED_BACKSLASH] ? "YES - /a%5Cb == /a/b" : "NO").append("<br>");
                    sb.append("Encoded dot-segment normalized: ").append(normalizations[Server.ENCODED_SEGMENT] ? "YES - /a/..%2Fb == /b" : "NO").append("<br>");
                    sb.append("Encoded backslash dot-segment normalized: ").append(normalizations[Server.ENCODED_BACK_SEGMENT] ? "YES - /a/..%5Cb == /b" : "NO").append("<br>");
                    sb.append("Path is URL decoded: ").append(normalizations[Server.PATH_DECODING] ? "YES - /%68%65%6c%6c%6f == /hello" : "NO").append("<br>");
                    sb.append("Query string is part of cache key: ").append(normalizations[Server.IS_QUERY_KEYED] ? "NO - key(/hello?abc) == key(/hello)" : "YES").append("<br>");
                    sb.append("<br>The following paths appear to share the same network components and should be affected:<br>").append(serv.requestsToString());
                    reportIssue("Key Normalization", sb.toString(), AuditIssueSeverity.INFORMATION, keyNormReportReq);
                }
            }

            //Delimiter Scan
            if (serv.getOriginDelimiters() != null) {
                List<String> discrepancyOriginDelimiters = new ArrayList<>();
                for (String delim : serv.getOriginDelimiters()) {
                    if (serv.getKeyDelimiters() == null) {
                        if (isSentByBrowser(delim)) {
                            discrepancyOriginDelimiters.add(delim);
                        }
                    } else if (isSentByBrowser(delim) && !serv.getKeyDelimiters().contains(delim)) { //if the cache uses the same delimiter, it'll break the poc
                        discrepancyOriginDelimiters.add(delim);
                    }
                }
                for (String delim : discrepancyOriginDelimiters) {
                    List<DetectionResult> vulnerableExtension = testExtensionRule(serv, delim, this.extensions);
                    for (DetectionResult vuln : vulnerableExtension) {
                        String desc = "The target appears to be vulnerable to Web Cache Deception using the Delimiter: '" + ScanWorker.printableStr(delim) + "' and the Static Extensions rule<br><br>If the response contains sensitive information this could be used to hijack victim's data.";
                        AuditIssueConfidence confidence = AuditIssueConfidence.CERTAIN;
                        if (vuln.isFallback()) {
                            desc += vuln.headerDiff();
                            confidence = AuditIssueConfidence.TENTATIVE;
                        }
                        reportIssue("Web Cache Deception", desc, AuditIssueSeverity.HIGH, confidence, vuln.initialRequest(), vuln.cachedResponse());
                    }
                }
            }

            //TODO evaulate if this is even needed....
//            if (this.staticDirs == null) {
//                this.staticDirs = new ArrayList<>(detectStaticDirectories(serv));
//            }
//            for (String fallback : FALLBACK_STATIC_PATHS) {
//                if (!this.staticDirs.contains(fallback)) {
//                    this.staticDirs.add(fallback);
//                }
//            }

            //Cache key normalization scan
            if (serv.getKeyNormalization() != null && serv.getKeyNormalization()[Server.ENCODED_SEGMENT] && serv.getOriginDelimiters() != null) {
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
                            HttpRequestResponse testReq = sendRequest(withRawPath(reqResp.request(), sb.toString()), mode);
                            DetectionResult result = detectCacheDeception(testReq, reqResp);
                            if (result != null){
                                String desc = "The target appears to be vulnerable to Web Cache Deception with Cache Key Normalization.<br>The path : '"+dir+"' appears to be a Static Directory.<br>The Origin Delimiter used is: '"+ScanWorker.printableStr(delimiter)+"'.";
                                AuditIssueConfidence confidence = AuditIssueConfidence.CERTAIN;
                                if (result.isFallback()) {
                                    desc += result.headerDiff();
                                    confidence = AuditIssueConfidence.TENTATIVE;
                                }
                                reportIssue("Web Cache Deception", desc, AuditIssueSeverity.HIGH, confidence, testReq, result.cachedResponse());
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
                            HttpRequestResponse testReq = sendRequest(withRawPath(reqResp.request(), sb.toString()), mode);
                            DetectionResult result = detectCacheDeception(testReq, reqResp);
                            if (result != null){
                                String desc = "The target appears to be vulnerable to Web Cache Deception with Cache Key Backslash Normalization.<br>The path : '"+dir+"' appears to be a Static Directory.<br>The Origin Delimiter used is: '"+ScanWorker.printableStr(delimiter)+"'.";
                                AuditIssueConfidence confidence = AuditIssueConfidence.CERTAIN;
                                if (result.isFallback()) {
                                    desc += result.headerDiff();
                                    confidence = AuditIssueConfidence.TENTATIVE;
                                }
                                reportIssue("Web Cache Deception", desc, AuditIssueSeverity.HIGH, confidence, testReq, result.cachedResponse());
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
                        HttpRequestResponse testReq = sendRequest(reqResp.request().withPath(sb.toString()), mode);
                        DetectionResult result = detectCacheDeception(testReq, reqResp);
                        if (result != null){
                            String desc = "The target appears to be vulnerable to Web Cache Deception with Origin Server Normalization.<br>The path : '"+dir+"' appears to be a Static Directory.";
                            AuditIssueConfidence confidence = AuditIssueConfidence.CERTAIN;
                            if (result.isFallback()) {
                                desc += result.headerDiff();
                                confidence = AuditIssueConfidence.TENTATIVE;
                            }
                            reportIssue("Web Cache Deception", desc, AuditIssueSeverity.HIGH, confidence, testReq, result.cachedResponse());
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
                        HttpRequestResponse testReq = sendRequest(reqResp.request().withPath(sb.toString()), mode);
                        DetectionResult result = detectCacheDeception(testReq, reqResp);
                        if (result != null){
                            String desc = "The target appears to be vulnerable to Web Cache Deception with Origin Server Backslash Normalization.<br>The path : '"+dir+"' appears to be a Static Directory.";
                            AuditIssueConfidence confidence = AuditIssueConfidence.CERTAIN;
                            if (result.isFallback()) {
                                desc += result.headerDiff();
                                confidence = AuditIssueConfidence.TENTATIVE;
                            }
                            reportIssue("Web Cache Deception", desc, AuditIssueSeverity.HIGH, confidence, testReq, result.cachedResponse());
                        }
                    }
                }
            }

        }
    }


    public List<DetectionResult> testExtensionRule(Server server, String delimiter, List<String> extensions){
        List<DetectionResult> out = new ArrayList<>();
        for (HttpRequestResponse reqResp : server.getDynamicRequest()) {
            HttpRequestResponse testReq = sendRequest(setRawPathSuffix(reqResp.request(), delimiter+(delimiter.equals(".") ? ".": "")+"aaaaa"), mode);
            if (testReq.hasResponse() && testReq.response().statusCode() != 0 && compareResp(testReq.response(), reqResp.response())) {
                for (String ext : extensions) {
                    HttpRequestResponse initialReq = sendRequest(setRawPathSuffix(reqResp.request(), delimiter + (delimiter.equals(".") ? "" : ".") + ext), mode);
                    boolean cached = triggerCache(initialReq.request());
                    HttpRequestResponse cachedReq = sendRequest(initialReq.request(), mode);
                    if (cached) {
                        out.add(new DetectionResult(initialReq, cachedReq, false, null));
                    } else if (!containSameCacheHeaders(cachedReq, reqResp)) {
                        out.add(new DetectionResult(initialReq, cachedReq, true, buildCacheHeaderDiff(cachedReq, reqResp)));
                    }
                }
            }
        }
        return out;
    }

    public DetectionResult detectCacheDeception(HttpRequestResponse testReq, HttpRequestResponse baseReqResp){
        if (testReq.hasResponse() && testReq.response().statusCode() != 0 && compareResp(testReq.response(), baseReqResp.response())) {
            boolean cached = triggerCache(testReq.request());
            HttpRequestResponse cachedResp = sendRequest(testReq.request(), mode);
            if (cached) {
                return new DetectionResult(null, cachedResp, false, null);
            }
            if (!containSameCacheHeaders(cachedResp, baseReqResp)) {
                return new DetectionResult(null, cachedResp, true, buildCacheHeaderDiff(cachedResp, baseReqResp));
            }
        }
        return null;
    }


    public boolean triggerCache(HttpRequest request){
        boolean done = false;
        HttpRequestResponse testGet = sendRequest(request, mode);
        if (testGet.hasResponse() && hasCacheHit(testGet.response())) done = true;
        if (!done) {
            try {
                TimeUnit.SECONDS.sleep(1);
            } catch (InterruptedException ignored) {
            }
            testGet = sendRequest(testGet.request(), mode);
            if (testGet.hasResponse() && hasCacheHit(testGet.response())) done = true;
        }
        if (!done) {
            try {
                TimeUnit.SECONDS.sleep(1);
            } catch (InterruptedException ignored) {
            }
            testGet = sendRequest(testGet.request(), mode);
            if (testGet.hasResponse() && hasCacheHit(testGet.response())) done = true;
        }
        int retries = 0;
        while (!(testGet.hasResponse() && testGet.response().statusCode() != 0) && retries < 5){
            try {
                TimeUnit.SECONDS.sleep(2);
            } catch (InterruptedException ignored) {
            }
            testGet = sendRequest(testGet.request(), mode);
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

        //return cacheableResponse.hasHeader("Age"); //This produces FP.... having age with a value 0 is bad

        if (cacheableResponse.hasHeader("Age")) {
            if (!cacheableResponse.headerValue("Age").equals("0")) {
                return true;
            } else {
                return false;
            }
        } else {
            return false;
        }
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

    private String buildCacheHeaderDiff(HttpRequestResponse testResponse, HttpRequestResponse baseResponse) {
        Map<String, String> testHeaders = getCacheHeaders(testResponse.response());
        Map<String, String> baseHeaders = getCacheHeaders(baseResponse.response());

        Set<String> allKeys = new LinkedHashSet<>();
        allKeys.addAll(testHeaders.keySet());
        allKeys.addAll(baseHeaders.keySet());

        StringBuilder sb = new StringBuilder();
        sb.append("<br><br><b>Cache header differences (tentative detection):</b><br>");
        sb.append("<table><tr><th>Header</th><th>Test Response</th><th>Baseline Response</th></tr>");
        for (String key : allKeys) {
            String testVal = testHeaders.getOrDefault(key, "(absent)");
            String baseVal = baseHeaders.getOrDefault(key, "(absent)");
            if (!testVal.equals(baseVal)) {
                sb.append("<tr><td>").append(escapeHtml(key)).append("</td>");
                sb.append("<td>").append(escapeHtml(testVal)).append("</td>");
                sb.append("<td>").append(escapeHtml(baseVal)).append("</td></tr>");
            }
        }
        sb.append("</table>");
        return sb.toString();
    }

    private static String escapeHtml(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
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
    public static HttpRequest setRawPathSuffix(HttpRequest base, String suffix){
        if (!base.path().contains("?")) return withRawPath(base, base.path()+suffix);
        return withRawPath(base, base.path().substring(0, base.path().indexOf("?"))+suffix+base.path().substring(base.path().indexOf("?")));
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