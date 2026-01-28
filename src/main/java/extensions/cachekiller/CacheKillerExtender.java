package extensions.cachekiller;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.hotkey.HotKey;
import extensions.cachekiller.Utils.Server;

import javax.swing.*;
import java.util.ArrayList;
import java.util.List;

public class CacheKillerExtender implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("CacheKiller");
        Server.setApi(api);
        CacheKiller cacheKiller = new CacheKiller(api);
        api.userInterface().registerContextMenuItemsProvider(cacheKiller);
        api.extension().registerUnloadingHandler(cacheKiller::onUnload);

        api.userInterface().registerHotKeyHandler(
                HotKey.hotKey("Delimiters finder", "Ctrl+Shift+1"),
                event -> {
                    List<HttpRequestResponse> requests = getRequestsFromEvent(event);
                    if (!requests.isEmpty()) {
                        SwingUtilities.invokeLater(() -> cacheKiller.showDelimiterDialog(requests));
                    }
                }
        );

        api.userInterface().registerHotKeyHandler(
                HotKey.hotKey("Normalization prove", "Ctrl+Shift+2"),
                event -> {
                    List<HttpRequestResponse> requests = getRequestsFromEvent(event);
                    if (!requests.isEmpty()) {
                        SwingUtilities.invokeLater(() -> cacheKiller.showNormalizationDialog(requests));
                    }
                }
        );

        api.userInterface().registerHotKeyHandler(
                HotKey.hotKey("Web Cache Deception scan", "Ctrl+Shift+3"),
                event -> {
                    List<HttpRequestResponse> requests = getRequestsFromEvent(event);
                    if (!requests.isEmpty()) {
                        SwingUtilities.invokeLater(() -> cacheKiller.showCacheDeceptionDialog(requests));
                    }
                }
        );

        api.userInterface().registerHotKeyHandler(
                HotKey.hotKey("Web Cache Poisoning scan", "Ctrl+Shift+4"),
                event -> {
                    List<HttpRequestResponse> requests = getRequestsFromEvent(event);
                    if (!requests.isEmpty()) {
                        SwingUtilities.invokeLater(() -> cacheKiller.showCachePoisoningDialog(requests));
                    }
                }
        );
    }

    private List<HttpRequestResponse> getRequestsFromEvent(burp.api.montoya.ui.hotkey.HotKeyEvent event) {
        List<HttpRequestResponse> requests = new ArrayList<>(event.selectedRequestResponses());
        if (requests.isEmpty() && event.messageEditorRequestResponse().isPresent()) {
            requests.add(event.messageEditorRequestResponse().get().requestResponse());
        }
        return requests;
    }
}