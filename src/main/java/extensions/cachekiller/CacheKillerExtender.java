package extensions.cachekiller;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import extensions.cachekiller.Utils.Server;


public class CacheKillerExtender implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("CacheKiller");
        Server.setApi(api);
        CacheKiller cacheKiller = new CacheKiller(api);
        api.userInterface().registerContextMenuItemsProvider(cacheKiller);
        api.extension().registerUnloadingHandler(cacheKiller::onUnload);
    }
}