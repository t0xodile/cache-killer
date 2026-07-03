package extensions.cachekiller.Workers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import extensions.cachekiller.Utils.Server;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

public class DelimiterScanWorker extends ScanWorker {

    private final List<String> testDelimitersList;
    private final boolean testKey;
    private final boolean useHTTP2;

    public DelimiterScanWorker(MontoyaApi api, List<HttpRequestResponse> requestResponse, List<String> testDelimitersList, boolean fullSiteMap, boolean subHosts, boolean testKey, boolean useHTTP2){
        super(api, requestResponse, fullSiteMap, subHosts);
        this.testDelimitersList = new ArrayList<>(testDelimitersList);
        this.testKey = testKey;
        this.useHTTP2 = useHTTP2;
        this.probeStaticPaths = testKey;
    }

    public void scan(){
        HashMap<String, Server> servers = getServers();
        if (servers.isEmpty()) {
            api.logging().logToOutput("[DelimiterScan] No servers found. Ensure the selected request returns a valid response.");
            return;
        }
        for (Server serv : servers.values()){
            if (useHTTP2) {
                scanServer(serv, HttpMode.HTTP_1, " (HTTP/1)");
                scanServer(serv, HttpMode.HTTP_2, " (HTTP/2)");
            } else {
                scanServer(serv, HttpMode.HTTP_1, "");
            }
        }
    }

    private void scanServer(Server serv, HttpMode mode, String suffix){
        checkCancelled();
        HttpRequestResponse reportReq = serv.detectOriginDelimiters(testDelimitersList, mode);
        if (serv.getOriginDelimiters() != null && !serv.getOriginDelimiters().isEmpty()) {
            StringBuilder sb = new StringBuilder();
            for (String del : serv.getOriginDelimiters()){
                sb.append(printableStr(del));
                sb.append("<br>");
            }
            reportIssue("Origin Delimiters" + suffix, "The following characters where detected as Origin Delimiters:<br>"+sb.toString()+"<br><br>The following paths appear to share the same network components and should be affected:<br>"+serv.requestsToString(), AuditIssueSeverity.INFORMATION, reportReq);
        }
        if (testKey) {
            reportReq = serv.detectKeyDelimiters(testDelimitersList, mode);
            if (serv.getKeyDelimiters() != null && !serv.getKeyDelimiters().isEmpty()) {
                StringBuilder sb = new StringBuilder();
                for (String del : serv.getKeyDelimiters()) {
                    sb.append(printableStr(del));
                    sb.append("<br>");
                }
                reportIssue("Key Delimiters" + suffix, "The following characters where detected as Cache Delimiters:<br>"+sb.toString()+"<br><br>The following paths appear to share the same network components and should be affected:<br>"+serv.requestsToString(), AuditIssueSeverity.INFORMATION, reportReq);
            }
            else if (reportReq != null) {
                reportIssue("Key Delimiters" + suffix, "None of the tested characters are used as Key Delimiters for the following paths that share the same network components.<br>"+serv.requestsToString(), AuditIssueSeverity.INFORMATION, reportReq);
            }
            else {
                api.logging().logToOutput("Key delimiter detection skipped: no suitable cached request found for this server.");
            }
        }
    }
}
