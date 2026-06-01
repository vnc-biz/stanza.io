var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import Disco from '../helpers/DiscoManager';
import * as JID from '../JID';
import { NS_DISCO_INFO, NS_DISCO_ITEMS } from '../Namespaces';
export default function (client) {
    client.disco = new Disco();
    client.disco.addFeature(NS_DISCO_INFO);
    client.disco.addFeature(NS_DISCO_ITEMS);
    client.disco.addIdentity({
        category: 'client',
        type: 'web'
    });
    client.registerFeature('caps', 100, (features, done) => {
        const domain = JID.getDomain(client.jid) || client.config.server;
        client.emit('disco:caps', {
            caps: features.legacyCapabilities || [],
            jid: domain
        });
        client.features.negotiated.caps = true;
        done();
    });
    client.getDiscoInfo = (jid, node) => __awaiter(this, void 0, void 0, function* () {
        const resp = yield client.sendIQ({
            disco: {
                node,
                type: 'info'
            },
            to: jid,
            type: 'get'
        });
        return Object.assign({ extensions: [], features: [], identities: [] }, resp.disco);
    });
    client.getDiscoItems = (jid, node) => __awaiter(this, void 0, void 0, function* () {
        const resp = yield client.sendIQ({
            disco: {
                node,
                type: 'items'
            },
            to: jid,
            type: 'get'
        });
        return Object.assign({ items: [] }, resp.disco);
    });
    client.updateCaps = () => {
        const node = client.config.capsNode || 'https://stanzajs.org';
        return client.disco.updateCaps(node);
    };
    client.getCurrentCaps = () => {
        const caps = client.disco.getCaps();
        if (!caps) {
            return;
        }
        const node = `${caps[0].node}#${caps[0].value}`;
        return {
            info: client.disco.getNodeInfo(node),
            legacyCapabilities: caps
        };
    };
    client.on('presence', pres => {
        if (pres.legacyCapabilities) {
            client.emit('disco:caps', {
                caps: pres.legacyCapabilities,
                jid: pres.from
            });
        }
    });
    client.on('iq:get:disco', iq => {
        const { type, node } = iq.disco;
        if (type === 'info') {
            client.sendIQResult(iq, {
                disco: Object.assign(Object.assign({}, client.disco.getNodeInfo(node || '')), { node, type: 'info' })
            });
        }
        if (type === 'items') {
            client.sendIQResult(iq, {
                disco: {
                    items: client.disco.items.get(node || '') || [],
                    type: 'items'
                }
            });
        }
    });
}
