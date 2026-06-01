var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { mergeFields } from '../helpers/DataForms';
import * as JID from '../JID';
import { NS_MAM_2 } from '../Namespaces';
export default function (client) {
    client.getHistorySearchForm = (jid_1, ...args_1) => __awaiter(this, [jid_1, ...args_1], void 0, function* (jid, opts = {}) {
        const res = yield client.sendIQ({
            archive: {
                type: 'query',
                version: opts.version
            },
            to: jid,
            type: 'get'
        });
        return res.archive.form;
    });
    client.searchHistory = (jidOrOpts_1, ...args_1) => __awaiter(this, [jidOrOpts_1, ...args_1], void 0, function* (jidOrOpts, opts = {}) {
        const queryid = client.nextId();
        let jid = '';
        if (typeof jidOrOpts === 'string') {
            jid = jidOrOpts;
        }
        else {
            jid = jidOrOpts.to || '';
            opts = jidOrOpts;
        }
        opts.queryId = queryid;
        const form = opts.form || {};
        form.type = 'submit';
        const fields = form.fields || [];
        const defaultFields = [
            {
                name: 'FORM_TYPE',
                type: 'hidden',
                value: NS_MAM_2
            }
        ];
        if (opts.with) {
            defaultFields.push({
                name: 'with',
                type: 'text-single',
                value: opts.with
            });
        }
        if (opts.start) {
            defaultFields.push({
                name: 'start',
                type: 'text-single',
                value: opts.start.toISOString()
            });
        }
        if (opts.end) {
            defaultFields.push({
                name: 'end',
                type: 'text-single',
                value: opts.end.toISOString()
            });
        }
        form.fields = mergeFields(defaultFields, fields);
        opts.form = form;
        const allowed = JID.allowedResponders(client.jid, jid);
        const results = [];
        const collector = (msg) => {
            if (allowed.has(msg.from) && msg.archive && msg.archive.queryId === queryid) {
                results.push(msg.archive);
            }
        };
        client.on('mam:item', collector);
        try {
            const resp = yield client.sendIQ({
                archive: opts,
                id: queryid,
                to: jid,
                type: 'set'
            });
            return Object.assign(Object.assign({}, resp.archive), { results });
        }
        finally {
            client.off('mam:item', collector);
        }
    });
    client.getHistoryPreferences = () => __awaiter(this, void 0, void 0, function* () {
        const resp = yield client.sendIQ({
            archive: {
                type: 'preferences'
            },
            type: 'get'
        });
        return resp.archive;
    });
    client.setHistoryPreferences = (opts) => {
        return client.sendIQ({
            archive: Object.assign({ type: 'preferences' }, opts),
            type: 'set'
        });
    };
    client.on('message', msg => {
        if (msg.archive) {
            client.emit('mam:item', msg);
        }
    });
}
