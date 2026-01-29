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
import java.util.HashMap;
import java.util.List;

import static burp.api.montoya.scanner.audit.issues.AuditIssue.auditIssue;
import static extensions.cachekiller.Utils.Server.sendHTTP1Request;

public abstract class ScanWorker extends SwingWorker<Void, Void> {

    protected HttpRequestResponse requestResponse;
    protected final MontoyaApi api;
    protected final boolean fullSiteMap;
    protected final boolean subHosts;

    public ScanWorker(MontoyaApi api, List<HttpRequestResponse> requestResponse, boolean fullSiteMap, boolean subHosts){
        this.api = api;
        this.requestResponse = requestResponse.get(0);
        this.fullSiteMap = fullSiteMap;
        this.subHosts = subHosts;
    }

    @Override
    protected Void doInBackground() {
        try {
            scan();
        } catch (Throwable e) {
            api.logging().logToOutput("[ScanWorker] ERROR: Scan failed - " + e.getClass().getName() + ": " + e.getMessage());
            java.io.StringWriter sw = new java.io.StringWriter();
            e.printStackTrace(new java.io.PrintWriter(sw));
            api.logging().logToError(sw.toString());
        }
        return null;
    }

    public HashMap<String, Server> getServers(){
        HashMap<String, Server> servers = new HashMap<>();
        api.logging().logToOutput("[ScanWorker] Discovering servers for host: " + requestResponse.httpService().host() + " (fullSiteMap=" + fullSiteMap + ")");
        sendHTTP1Request(Server.addRequestCacheBuster(this.requestResponse.request()));
        String host = requestResponse.httpService().host();
        if (fullSiteMap){
            for (HttpRequestResponse reqResp : api.siteMap().requestResponses()){
                if (!(reqResp.httpService().host().equals(host) || (subHosts && reqResp.httpService().host().endsWith("."+host)))) continue;
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
        else{
            HttpRequestResponse testReqResp = sendHTTP1Request(Server.addRequestCacheBuster(this.requestResponse.request()));
            if (testReqResp.hasResponse() && testReqResp.response().statusCode() != 0) {
                String serverHash = Server.getNetworkHash(testReqResp);
                servers.put(serverHash, new Server(serverHash, api));
                servers.get(serverHash).addRequestResponse(this.requestResponse);
            }
        }
        return servers;
    }

    public void reportIssue(String title, String description, AuditIssueSeverity severity, HttpRequestResponse... requestResponses) {
        AuditIssue issue = auditIssue(
                title,
                description,
                null,
                requestResponses[0].request().url(),
                severity,
                AuditIssueConfidence.CERTAIN,
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
}
