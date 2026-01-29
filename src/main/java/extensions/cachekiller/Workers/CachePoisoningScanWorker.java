package extensions.cachekiller.Workers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import extensions.cachekiller.Utils.Server;

import java.util.*;

import static extensions.cachekiller.Utils.Server.sendHTTP1Request;

public class CachePoisoningScanWorker extends ScanWorker {

    private final List<String> testDelimitersList;

    public CachePoisoningScanWorker(MontoyaApi api, List<HttpRequestResponse> requestResponse, List<String> testDelimitersList, boolean fullSiteMap, boolean subHosts){
        super(api, requestResponse, fullSiteMap, subHosts);
        this.testDelimitersList = new ArrayList<>(testDelimitersList);
    }

    public void scan(){
        api.logging().logToOutput("[CachePoisoningScan] Scan started");
        HashMap<String, Server> servers = getServers();
        api.logging().logToOutput("[CachePoisoningScan] Found " + servers.size() + " server group(s) to test");
        if (servers.isEmpty()) {
            api.logging().logToOutput("[CachePoisoningScan] No servers found. Ensure the selected request returns a valid response.");
            return;
        }
        for (Server serv : servers.values()){
            api.logging().logToOutput("[CachePoisoningScan] Detecting origin delimiters...");
            serv.detectOriginDelimiters(testDelimitersList);
            api.logging().logToOutput("[CachePoisoningScan] Detecting key delimiters...");
            serv.detectKeyDelimiters(testDelimitersList);
            api.logging().logToOutput("[CachePoisoningScan] Detecting origin normalization...");
            serv.detectOriginNormalization();
            api.logging().logToOutput("[CachePoisoningScan] Detecting key normalization...");
            serv.detectKeyNormalization();
            if (serv.getOriginDelimiters() == null || serv.getKeyDelimiters() == null || serv.getOriginNormalization() == null || serv.getKeyNormalization() == null) {
                api.logging().logToOutput("[CachePoisoningScan] Skipping server: insufficient detection results (originDelimiters=" + (serv.getOriginDelimiters() != null) + ", keyDelimiters=" + (serv.getKeyDelimiters() != null) + ", originNorm=" + (serv.getOriginNormalization() != null) + ", keyNorm=" + (serv.getKeyNormalization() != null) + ").");
                continue;
            }
            List<String> discrepancyOriginDelimiters = new ArrayList<>();
            List<String> discrepancyKeyDelimiters =  new ArrayList<>();
            for (String delim : serv.getOriginDelimiters()){
                if (!serv.getKeyDelimiters().contains(delim)) discrepancyOriginDelimiters.add(delim);
            }
            for (String delim : serv.getKeyDelimiters()){
                if (!serv.getOriginDelimiters().contains(delim)) discrepancyKeyDelimiters.add(delim);
            }
            if (serv.getKeyNormalization()[Server.DOT_SEGMENT]){
                for (String delim : discrepancyOriginDelimiters){
                    for (HttpRequestResponse reqResp : serv.getStaticRequest()){
                        String random = Server.randomNonce(5);
                        sendHTTP1Request(setPathSuffix(reqResp.request(), delim+"/../"+random));
                        sendHTTP1Request(setPathSuffix(reqResp.request(), delim+"/../"+random));
                        HttpRequestResponse testResp = sendHTTP1Request(reqResp.request().withPath(Server.removeLastSegment(reqResp.request().path())+"/"+random));
                        if (compareResp(testResp.response(), reqResp.response())){
                            reportIssue("Web Cache Poisoning Detected", "The target appears to be normalizing the cache keys and its vulnerable to Web Cache Poisoning using the origin delimiter: '"+ScanWorker.printableStr(delim)+"'.", AuditIssueSeverity.HIGH, testResp);
                        }
                    }
                }
            }

            if (serv.getOriginNormalization()[Server.DOT_SEGMENT]){
                for (String delim : discrepancyKeyDelimiters){
                    for (HttpRequestResponse reqResp : serv.getStaticRequest()){
                        String random = Server.randomNonce(5);
                        sendHTTP1Request(reqResp.request().withPath("/"+random+delim+"/.."+reqResp.request().path()));
                        sendHTTP1Request(reqResp.request().withPath("/"+random+delim+"/.."+reqResp.request().path()));
                        HttpRequestResponse testResp = sendHTTP1Request(reqResp.request().withPath("/"+random));
                        if (compareResp(testResp.response(), reqResp.response())){
                            reportIssue("Web Cache Poisoning Detected", "The target appears to be normalizing the path at the origin and its vulnerable to Web Cache Poisoning using the key delimiter: '"+ScanWorker.printableStr(delim)+"'.", AuditIssueSeverity.HIGH, testResp);
                        }
                    }
                }
            }
        }
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

}