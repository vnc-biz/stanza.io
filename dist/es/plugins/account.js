var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { NS_VCARD_TEMP } from '../Namespaces';
export default function (client) {
    client.getAccountInfo = (jid) => __awaiter(this, void 0, void 0, function* () {
        const resp = yield client.sendIQ({
            account: {},
            to: jid,
            type: 'get'
        });
        return resp.account;
    });
    client.updateAccount = (jid, data) => {
        return client.sendIQ({
            account: data,
            to: jid,
            type: 'set'
        });
    };
    client.deleteAccount = (jid) => {
        return client.sendIQ({
            account: {
                remove: true
            },
            to: jid,
            type: 'set'
        });
    };
    client.getPrivateData = (key) => __awaiter(this, void 0, void 0, function* () {
        const res = yield client.sendIQ({
            privateStorage: {
                [key]: {}
            },
            type: 'get'
        });
        return res.privateStorage[key];
    });
    client.setPrivateData = (key, value) => __awaiter(this, void 0, void 0, function* () {
        return client.sendIQ({
            privateStorage: {
                [key]: value
            },
            type: 'set'
        });
    });
    client.getVCard = (jid) => __awaiter(this, void 0, void 0, function* () {
        const resp = yield client.sendIQ({
            to: jid,
            type: 'get',
            vcard: {
                format: NS_VCARD_TEMP
            }
        });
        return resp.vcard;
    });
    client.publishVCard = (vcard) => __awaiter(this, void 0, void 0, function* () {
        yield client.sendIQ({
            type: 'set',
            vcard
        });
    });
    client.enableNotifications = (jid, node, fieldList = []) => {
        return client.sendIQ({
            push: {
                action: 'enable',
                form: {
                    fields: [
                        {
                            name: 'FORM_TYPE',
                            type: 'hidden',
                            value: 'http://jabber.org/protocol/pubsub#publish-options'
                        },
                        ...fieldList
                    ],
                    type: 'submit'
                },
                jid,
                node
            },
            type: 'set'
        });
    };
    client.disableNotifications = (jid, node) => {
        return client.sendIQ({
            push: {
                action: 'disable',
                jid,
                node
            },
            type: 'set'
        });
    };
}
