var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { VERSION } from '../Constants';
import { NS_DATAFORM, NS_DATAFORM_LAYOUT, NS_DATAFORM_MEDIA, NS_DATAFORM_VALIDATION, NS_DELAY, NS_EME_0, NS_FORWARD_0, NS_HASH_NAME, NS_HASHES_1, NS_HASHES_2, NS_IDLE_1, NS_JSON_0, NS_OOB, NS_PSA, NS_REFERENCE_0, NS_SHIM, NS_TIME, NS_VERSION } from '../Namespaces';
import * as hashes from '../platform';
export default function (client) {
    client.disco.addFeature('jid\\20escaping');
    client.disco.addFeature(NS_DELAY);
    client.disco.addFeature(NS_EME_0);
    client.disco.addFeature(NS_FORWARD_0);
    client.disco.addFeature(NS_HASHES_2);
    client.disco.addFeature(NS_HASHES_1);
    client.disco.addFeature(NS_IDLE_1);
    client.disco.addFeature(NS_JSON_0);
    client.disco.addFeature(NS_OOB);
    client.disco.addFeature(NS_PSA);
    client.disco.addFeature(NS_REFERENCE_0);
    client.disco.addFeature(NS_SHIM);
    client.disco.addFeature(NS_DATAFORM);
    client.disco.addFeature(NS_DATAFORM_MEDIA);
    client.disco.addFeature(NS_DATAFORM_VALIDATION);
    client.disco.addFeature(NS_DATAFORM_LAYOUT);
    const names = hashes.getHashes();
    for (const name of names) {
        client.disco.addFeature(NS_HASH_NAME(name));
    }
    client.disco.addFeature(NS_TIME);
    client.disco.addFeature(NS_VERSION);
    client.on('iq:get:softwareVersion', iq => {
        return client.sendIQResult(iq, {
            softwareVersion: client.config.softwareVersion || {
                name: 'stanzajs.org',
                version: VERSION
            }
        });
    });
    client.on('iq:get:time', (iq) => {
        const time = new Date();
        client.sendIQResult(iq, {
            time: {
                tzo: time.getTimezoneOffset(),
                utc: time
            }
        });
    });
    client.getSoftwareVersion = (jid) => __awaiter(this, void 0, void 0, function* () {
        const resp = yield client.sendIQ({
            softwareVersion: {},
            to: jid,
            type: 'get'
        });
        return resp.softwareVersion;
    });
    client.getTime = (jid) => __awaiter(this, void 0, void 0, function* () {
        const resp = yield client.sendIQ({
            time: {},
            to: jid,
            type: 'get'
        });
        return resp.time;
    });
    client.getLastActivity = (jid) => __awaiter(this, void 0, void 0, function* () {
        const resp = yield client.sendIQ({
            lastActivity: {},
            to: jid,
            type: 'get'
        });
        return resp.lastActivity;
    });
}
