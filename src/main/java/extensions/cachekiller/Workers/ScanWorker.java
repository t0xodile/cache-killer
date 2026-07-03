package extensions.cachekiller.Workers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import extensions.cachekiller.Utils.Server;

import javax.swing.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

import static burp.api.montoya.scanner.audit.issues.AuditIssue.auditIssue;
import static extensions.cachekiller.Utils.Server.isCachedResponse;
import static extensions.cachekiller.Utils.Server.sendHTTP1Request;

public abstract class ScanWorker extends SwingWorker<Void, Void> {

    protected List<HttpRequestResponse> requestResponses;
    protected final MontoyaApi api;
    protected final boolean fullSiteMap;
    protected final boolean subHosts;
    protected boolean probeStaticPaths = true;
    private Runnable onComplete;

    public ScanWorker(MontoyaApi api, List<HttpRequestResponse> requestResponses, boolean fullSiteMap, boolean subHosts){
        this.api = api;
        this.requestResponses = new ArrayList<>(requestResponses);
        this.fullSiteMap = fullSiteMap;
        this.subHosts = subHosts;
    }

    public void setOnComplete(Runnable onComplete) {
        this.onComplete = onComplete;
    }

    @Override
    protected Void doInBackground() {
        try {
            scan();
        } catch (CancellationException e) {
            api.logging().logToOutput("[ScanWorker] Scan cancelled.");
        } catch (Throwable e) {
            api.logging().logToOutput("[ScanWorker] ERROR: Scan failed - " + e.getClass().getName() + ": " + e.getMessage());
            java.io.StringWriter sw = new java.io.StringWriter();
            e.printStackTrace(new java.io.PrintWriter(sw));
            api.logging().logToError(sw.toString());
        } finally {
            if (onComplete != null) {
                onComplete.run();
            }
        }
        return null;
    }

    /**
     * Throws CancellationException if this worker has been cancelled.
     * Call this at key points in scan loops to support clean shutdown.
     */
    protected void checkCancelled() {
        if (isCancelled()) {
            throw new CancellationException("Worker cancelled");
        }
    }

    public HashMap<String, Server> getServers(){
        HashMap<String, Server> servers = new HashMap<>();
        Set<String> hosts = new LinkedHashSet<>();
        for (HttpRequestResponse rr : requestResponses) {
            hosts.add(rr.httpService().host());
        }
        if (fullSiteMap){
            for (HttpRequestResponse rr : requestResponses) {
                sendHTTP1Request(Server.addRequestCacheBuster(rr.request()));
            }
            for (HttpRequestResponse reqResp : api.siteMap().requestResponses()){
                checkCancelled();
                String reqHost = reqResp.httpService().host();
                boolean matches = false;
                for (String host : hosts) {
                    if (reqHost.equals(host) || (subHosts && reqHost.endsWith("." + host))) {
                        matches = true;
                        break;
                    }
                }
                if (!matches) continue;
                HttpRequestResponse testReqResp = sendHTTP1Request(Server.addRequestCacheBuster(reqResp.request()));
                if (!testReqResp.hasResponse() || testReqResp.response().statusCode() == 0) continue;
                String serverHash = Server.getNetworkHash(testReqResp);
                if (servers.containsKey(serverHash)){
                    if (!(servers.get(serverHash).containsRequest(reqResp.request()))) servers.get(serverHash).addRequestResponse(reqResp);
                }
                else{
                    servers.put(serverHash, new Server(serverHash, api));
                    servers.get(serverHash).addRequestResponse(reqResp);
                }
            }
        }
        else {
            // Note: requests are classified as static/dynamic by addRequestResponse().
            // Scan workers must handle the case where dynamicReqs is empty (all requests were cached).
            Set<String> probedServerHashes = new HashSet<>();
            for (HttpRequestResponse rr : requestResponses) {
                checkCancelled();
                HttpRequestResponse testReqResp = sendHTTP1Request(Server.addRequestCacheBuster(rr.request()));
                if (testReqResp.hasResponse() && testReqResp.response().statusCode() != 0) {
                    String serverHash = Server.getNetworkHash(testReqResp);
                    if (!servers.containsKey(serverHash)) {
                        servers.put(serverHash, new Server(serverHash, api));
                    }
                    servers.get(serverHash).addRequestResponse(rr);

                    // Probe fallback static paths once per server hash (only needed for key detection)
                    if (probeStaticPaths && probedServerHashes.add(serverHash)) {
                        for (String path : Server.FALLBACK_STATIC_PATHS) {
                            checkCancelled();
                            HttpRequestResponse fallbackResp = sendHTTP1Request(rr.request().withPath(path));
                            if (fallbackResp.hasResponse() && fallbackResp.response().statusCode() > 0) {
                                if (isCachedResponse(fallbackResp) != 0) {
                                    servers.get(serverHash).addStaticRequest(fallbackResp);
                                }
                            }
                        }
                    }
                }
            }
        }
        return servers;
    }

    public void reportIssue(String title, String description, AuditIssueSeverity severity, HttpRequestResponse... requestResponses) {
        reportIssue(title, description, severity, AuditIssueConfidence.CERTAIN, requestResponses);
    }

    public void reportIssue(String title, String description, AuditIssueSeverity severity, AuditIssueConfidence confidence, HttpRequestResponse... requestResponses) {
        AuditIssue issue = auditIssue(
                title,
                description,
                null,
                requestResponses[0].request().url(),
                severity,
                confidence,
                null,
                null,
                AuditIssueSeverity.INFORMATION,
                requestResponses
        );
        api.siteMap().add(issue);
    }

    public static String strToHex(String input){
        StringBuilder hexString = new StringBuilder("0x");

        for (char ch : input.toCharArray()) {
            hexString.append(String.format("%02x", (int) ch));
        }

        return hexString.toString();
    }

    public static String printableStr(String str) {
        // Check if the character is a control character
        for (char ch : str.toCharArray()) {
            if (Character.isISOControl(ch)) {
                return strToHex(str);
            }

            // Check if the character is whitespace
            if (Character.isWhitespace(ch)) {
                continue;
            }

            // Check if the character is within the printable ASCII range
            if (ch >= 32 && ch <= 126) {
                continue;
            }

            // For Unicode characters, check general category
            int type = Character.getType(ch);
            if (!(type != Character.UNASSIGNED && type != Character.CONTROL && type != Character.FORMAT && type != Character.PRIVATE_USE && type != Character.SURROGATE && type != Character.LINE_SEPARATOR && type != Character.PARAGRAPH_SEPARATOR && type != Character.SPACE_SEPARATOR)) return strToHex(str);
        }
        return str;
    }

    abstract void scan();

    /**
     * Unchecked exception used for cancellation flow control.
     */
    public static class CancellationException extends RuntimeException {
        public CancellationException(String message) {
            super(message);
        }
    }
}
