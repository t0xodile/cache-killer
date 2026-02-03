package extensions.cachekiller.Workers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import extensions.cachekiller.Utils.Server;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

public class DelimiterScanWorker extends ScanWorker {

    private final List<String> testDelimitersList;
    private final boolean testKey;

    public DelimiterScanWorker(MontoyaApi api, List<HttpRequestResponse> requestResponse, List<String> testDelimitersList, boolean fullSiteMap, boolean subHosts, boolean testKey){
        super(api, requestResponse, fullSiteMap, subHosts);
        this.testDelimitersList = new ArrayList<>(testDelimitersList);
        this.testKey = testKey;
        this.probeStaticPaths = testKey;
    }

    public void scan(){
        HashMap<String, Server> servers = getServers();
        if (servers.isEmpty()) {
            api.logging().logToOutput("[DelimiterScan] No servers found. Ensure the selected request returns a valid response.");
            return;
        }
        HttpRequestResponse reportReq;
        for (Server serv : servers.values()){
            checkCancelled();
            reportReq = serv.detectOriginDelimiters(testDelimitersList);
            if (serv.getOriginDelimiters() != null && !serv.getOriginDelimiters().isEmpty()) {
                StringBuilder sb = new StringBuilder();
                for (String del : serv.getOriginDelimiters()){
                    sb.append(printableStr(del));
                    sb.append("<br>");
                }
                reportIssue("Origin Delimiters Detected", "The following characters where detected as Origin Delimiters:<br>"+sb.toString()+"<br><br>The following paths appear to share the same network components and should be affected:<br>"+serv.requestsToString(), AuditIssueSeverity.INFORMATION, reportReq);
            }
            if (testKey) {
                reportReq = serv.detectKeyDelimiters(testDelimitersList);
                if (serv.getKeyDelimiters() != null && !serv.getKeyDelimiters().isEmpty()) {
                    StringBuilder sb = new StringBuilder();
                    for (String del : serv.getKeyDelimiters()) {
                        sb.append(printableStr(del));
                        sb.append("<br>");
                    }
                    reportIssue("Key Delimiters Detected", "The following characters where detected as Cache Delimiters:<br>"+sb.toString()+"<br><br>The following paths appear to share the same network components and should be affected:<br>"+serv.requestsToString(), AuditIssueSeverity.INFORMATION, reportReq);
                }
                else if (reportReq != null) {
                    reportIssue("Key Delimiters", "None of the tested characters are used as Key Delimiters for the following paths that share the same network components.<br>"+serv.requestsToString(), AuditIssueSeverity.INFORMATION, reportReq);
                }
                else {
                    api.logging().logToOutput("Key delimiter detection skipped: no suitable cached request found for this server.");
                }
            }
        }
    }
}
