var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import * as JID from '../JID';
import { NS_BOB, NS_HTTP_UPLOAD_0 } from '../Namespaces';
export default function (client) {
    client.disco.addFeature(NS_BOB);
    client.getBits = (jid, cid) => __awaiter(this, void 0, void 0, function* () {
        const result = yield client.sendIQ({
            bits: {
                cid
            },
            to: jid,
            type: 'get'
        });
        return result.bits;
    });
    function getUploadParameters(jid) {
        return __awaiter(this, void 0, void 0, function* () {
            const disco = yield client.getDiscoInfo(jid);
            if (!disco.features || !disco.features.includes(NS_HTTP_UPLOAD_0)) {
                return;
            }
            let maxSize;
            for (const form of disco.extensions || []) {
                const fields = form.fields || [];
                if (fields.some(field => field.name === 'FORM_TYPE' && field.value === NS_HTTP_UPLOAD_0)) {
                    const sizeField = fields.find(field => field.name === 'max-file-size');
                    if (sizeField) {
                        maxSize = parseInt(sizeField.value, 10);
                    }
                    return {
                        jid,
                        maxSize
                    };
                }
            }
        });
    }
    client.getUploadService = (...args_1) => __awaiter(this, [...args_1], void 0, function* (domain = JID.getDomain(client.jid)) {
        const domainParameters = yield getUploadParameters(domain);
        if (domainParameters) {
            return domainParameters;
        }
        const disco = yield client.getDiscoItems(domain);
        for (const item of disco.items || []) {
            if (!item.jid) {
                continue;
            }
            const itemParameters = yield getUploadParameters(item.jid);
            if (itemParameters) {
                return itemParameters;
            }
        }
        throw new Error('No upload service discovered on: ' + domain);
    });
    client.getUploadSlot = (uploadService, uploadRequest) => __awaiter(this, void 0, void 0, function* () {
        const resp = yield client.sendIQ({
            httpUpload: Object.assign({ type: 'request' }, uploadRequest),
            to: uploadService,
            type: 'get'
        });
        return resp.httpUpload;
    });
}
