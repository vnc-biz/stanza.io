var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { NS_ALT_CONNECTIONS_WEBSOCKET, NS_ALT_CONNECTIONS_XBOSH } from '../Namespaces';
export default function (client) {
    client.discoverBindings = (server) => __awaiter(this, void 0, void 0, function* () {
        const bosh = new Set();
        const websocket = new Set();
        const discoverHostMeta = client.resolver
            .getHostMeta(server)
            .then(xrd => {
            var _a;
            for (const link of (_a = xrd.links) !== null && _a !== void 0 ? _a : []) {
                if (link.href && link.rel === NS_ALT_CONNECTIONS_WEBSOCKET) {
                    websocket.add(link.href);
                }
                if (link.href && link.rel === NS_ALT_CONNECTIONS_XBOSH) {
                    bosh.add(link.href);
                }
            }
        })
            .catch(err => console.error(err));
        const discoverDNS = !client.config.allowAlternateDNSDiscovery
            ? Promise.resolve()
            : client.resolver
                .resolveTXT(`_xmppconnect.${server}`)
                .then(txtRecords => {
                for (const group of txtRecords) {
                    for (const value of group) {
                        if (value.startsWith('_xmpp-client-websocket=')) {
                            const url = value.substring(value.indexOf('=') + 1);
                            if (url) {
                                websocket.add(url);
                            }
                        }
                        if (value.startsWith('_xmpp-client-xbosh=')) {
                            const url = value.substring(value.indexOf('=') + 1);
                            if (url) {
                                bosh.add(url);
                            }
                        }
                    }
                }
            })
                .catch(err => console.error(err));
        yield Promise.all([discoverHostMeta, discoverDNS]).catch(err => console.error(err));
        return {
            bosh: [...bosh].filter(url => url.startsWith('https://')),
            websocket: [...websocket].filter(url => url.startsWith('wss://'))
        };
    });
}
