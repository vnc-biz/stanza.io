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
import { NS_SHIM } from '../Namespaces';
function isPubsubMessage(msg) {
    return !!msg.pubsub;
}
function isPubsubPublish(msg) {
    return !!msg.pubsub.items && !!msg.pubsub.items.published;
}
function isPubsubRetract(msg) {
    return !!msg.pubsub.items && !!msg.pubsub.items.retracted;
}
function isPubsubPurge(msg) {
    return msg.pubsub.eventType === 'purge';
}
function isPubsubDelete(msg) {
    return msg.pubsub.eventType === 'delete';
}
function isPubsubSubscription(msg) {
    return msg.pubsub.eventType === 'subscription';
}
function isPubsubConfiguration(msg) {
    return msg.pubsub.eventType === 'configuration';
}
function isPubsubAffiliation(msg) {
    if (!msg.pubsub) {
        return false;
    }
    return (!msg.pubsub.context || msg.pubsub.context === 'user') && !!msg.pubsub.affiliations;
}
export default function (client) {
    client.disco.addFeature(`${NS_SHIM}#SubID`, NS_SHIM);
    client.on('message', msg => {
        if (isPubsubAffiliation(msg)) {
            client.emit('pubsub:affiliations', msg);
            return;
        }
        if (!isPubsubMessage(msg)) {
            return;
        }
        client.emit('pubsub:event', msg);
        if (isPubsubPublish(msg)) {
            client.emit('pubsub:published', msg);
            return;
        }
        if (isPubsubRetract(msg)) {
            client.emit('pubsub:retracted', msg);
            return;
        }
        if (isPubsubPurge(msg)) {
            client.emit('pubsub:purged', msg);
            return;
        }
        if (isPubsubDelete(msg)) {
            client.emit('pubsub:deleted', msg);
            return;
        }
        if (isPubsubSubscription(msg)) {
            client.emit('pubsub:subscription', msg);
            return;
        }
        if (isPubsubConfiguration(msg)) {
            client.emit('pubsub:config', msg);
            return;
        }
    });
    client.subscribeToNode = (jid, opts) => __awaiter(this, void 0, void 0, function* () {
        const subscribe = {};
        let form;
        if (typeof opts === 'string') {
            subscribe.node = opts;
            subscribe.jid = JID.toBare(client.jid);
        }
        else {
            subscribe.node = opts.node;
            subscribe.jid = opts.jid || (opts.useBareJID ? JID.toBare(client.jid) : client.jid);
            form = opts.options;
        }
        const resp = yield client.sendIQ({
            pubsub: {
                context: 'user',
                subscribe,
                subscriptionOptions: form ? { form } : undefined
            },
            to: jid,
            type: 'set'
        });
        const sub = resp.pubsub.subscription || {};
        if (resp.pubsub.subscriptionOptions) {
            sub.options = resp.pubsub.subscriptionOptions.form;
        }
        return sub;
    });
    client.unsubscribeFromNode = (jid, opts) => __awaiter(this, void 0, void 0, function* () {
        const unsubscribe = {};
        if (typeof opts === 'string') {
            unsubscribe.node = opts;
            unsubscribe.jid = JID.toBare(client.jid);
        }
        else {
            unsubscribe.node = opts.node;
            unsubscribe.subid = opts.subid;
            unsubscribe.jid = opts.jid || (opts.useBareJID ? JID.toBare(client.jid) : client.jid);
        }
        const resp = yield client.sendIQ({
            pubsub: {
                context: 'user',
                unsubscribe
            },
            to: jid,
            type: 'set'
        });
        if (!resp.pubsub || !resp.pubsub.subscription) {
            return Object.assign(Object.assign({}, unsubscribe), { state: 'none' });
        }
        return resp.pubsub.subscription;
    });
    client.publish = (jid, node, item, id) => {
        return client.sendIQ({
            pubsub: {
                context: 'user',
                publish: {
                    item: {
                        content: item,
                        id
                    },
                    node
                }
            },
            to: jid,
            type: 'set'
        });
    };
    client.getItem = (jid, node, id) => __awaiter(this, void 0, void 0, function* () {
        const resp = yield client.sendIQ({
            pubsub: {
                context: 'user',
                fetch: {
                    items: [{ id }],
                    node
                }
            },
            to: jid,
            type: 'get'
        });
        return resp.pubsub.fetch.items[0];
    });
    client.getItems = (jid_1, node_1, ...args_1) => __awaiter(this, [jid_1, node_1, ...args_1], void 0, function* (jid, node, opts = {}) {
        const resp = yield client.sendIQ({
            pubsub: {
                context: 'user',
                fetch: {
                    max: opts.max,
                    node
                },
                paging: opts
            },
            to: jid,
            type: 'get'
        });
        const result = resp.pubsub.fetch;
        result.paging = resp.pubsub.paging;
        return result;
    });
    client.retract = (jid, node, id, notify) => {
        return client.sendIQ({
            pubsub: {
                context: 'user',
                retract: {
                    id,
                    node,
                    notify
                }
            },
            to: jid,
            type: 'set'
        });
    };
    client.purgeNode = (jid, node) => {
        return client.sendIQ({
            pubsub: {
                context: 'owner',
                purge: node
            },
            to: jid,
            type: 'set'
        });
    };
    client.deleteNode = (jid, node, redirect) => {
        return client.sendIQ({
            pubsub: {
                context: 'owner',
                destroy: {
                    node,
                    redirect
                }
            },
            to: jid,
            type: 'set'
        });
    };
    client.createNode = (jid, node, config) => __awaiter(this, void 0, void 0, function* () {
        const resp = yield client.sendIQ({
            pubsub: {
                configure: config
                    ? {
                        form: config
                    }
                    : undefined,
                context: 'user',
                create: {
                    node
                }
            },
            to: jid,
            type: 'set'
        });
        if (!resp.pubsub || !resp.pubsub.create) {
            return {
                node
            };
        }
        return resp.pubsub.create;
    });
    client.getSubscriptions = (jid_1, ...args_1) => __awaiter(this, [jid_1, ...args_1], void 0, function* (jid, opts = {}) {
        const resp = yield client.sendIQ({
            pubsub: {
                context: 'user',
                subscriptions: opts
            },
            to: jid,
            type: 'get'
        });
        return resp.pubsub.subscriptions;
    });
    client.getAffiliations = (jid, node) => {
        return client.sendIQ({
            pubsub: {
                affiliations: {
                    node
                }
            },
            to: jid,
            type: 'get'
        });
    };
    client.getNodeSubscribers = (jid, node, opts = {}) => {
        if (typeof node === 'string') {
            opts.node = node;
        }
        else {
            opts = Object.assign(Object.assign({}, opts), node);
        }
        return client.sendIQ({
            pubsub: {
                context: 'owner',
                subscriptions: opts
            },
            to: jid,
            type: 'get'
        });
    };
    client.updateNodeSubscriptions = (jid, node, delta) => {
        return client.sendIQ({
            pubsub: {
                context: 'owner',
                subscriptions: {
                    items: delta,
                    node
                }
            },
            to: jid,
            type: 'set'
        });
    };
    client.getNodeAffiliations = (jid, node) => __awaiter(this, void 0, void 0, function* () {
        const resp = yield client.sendIQ({
            pubsub: {
                affiliations: {
                    node
                },
                context: 'owner'
            },
            to: jid,
            type: 'get'
        });
        return resp.pubsub.affiliations;
    });
    client.updateNodeAffiliations = (jid, node, items) => {
        return client.sendIQ({
            pubsub: {
                affiliations: {
                    items,
                    node
                },
                context: 'owner'
            },
            to: jid,
            type: 'set'
        });
    };
    client.getNodeConfig = (jid, node) => __awaiter(this, void 0, void 0, function* () {
        const resp = yield client.sendIQ({
            pubsub: {
                configure: {
                    node
                },
                context: 'owner'
            },
            to: jid,
            type: 'get'
        });
        return resp.pubsub.configure.form || {};
    });
    client.getDefaultNodeConfig = (jid) => __awaiter(this, void 0, void 0, function* () {
        const resp = yield client.sendIQ({
            pubsub: {
                context: 'owner',
                defaultConfiguration: {}
            },
            to: jid,
            type: 'get'
        });
        return resp.pubsub.defaultConfiguration.form || {};
    });
    client.configureNode = (jid, node, config) => __awaiter(this, void 0, void 0, function* () {
        return client.sendIQ({
            pubsub: {
                configure: {
                    form: config,
                    node
                },
                context: 'owner'
            },
            to: jid,
            type: 'set'
        });
    });
    client.getDefaultSubscriptionOptions = (jid) => __awaiter(this, void 0, void 0, function* () {
        const resp = yield client.sendIQ({
            pubsub: {
                defaultSubscriptionOptions: {}
            },
            to: jid,
            type: 'get'
        });
        return resp.pubsub.defaultSubscriptionOptions.form || {};
    });
    client.publishOmemoDevice = (jid, node, item) => __awaiter(this, void 0, void 0, function* () {
        return client.sendIQ({
            from: JID.toBare(client.jid),
            pubsub: {
                publish: { node, item },
                publishOptions: {
                    form: {
                        fields: [
                            { name: 'FORM_TYPE', type: 'hidden', value: 'http://jabber.org/protocol/pubsub#publish-options' },
                            { name: 'pubsub#access_model', value: 'open' }
                        ],
                        type: 'submit'
                    }
                }
            },
            to: jid,
            type: 'set'
        });
    });
    client.publishOmemoBundle = (jid, node, item) => __awaiter(this, void 0, void 0, function* () {
        return client.sendIQ({
            from: JID.toBare(client.jid),
            pubsub: {
                publish: { node, item },
                publishOptions: {
                    form: {
                        fields: [
                            { name: 'FORM_TYPE', type: 'hidden', value: 'http://jabber.org/protocol/pubsub#publish-options' },
                            { name: 'pubsub#max_items', value: '100' },
                            { name: 'pubsub#access_model', value: 'open' }
                        ],
                        type: 'submit'
                    }
                }
            },
            to: jid,
            type: 'set'
        });
    });
    client.getOmemoItems = (jid_1, node_1, ...args_1) => __awaiter(this, [jid_1, node_1, ...args_1], void 0, function* (jid, node, opts = {}) {
        return client.sendIQ({
            pubsub: {
                context: 'user',
                fetch: {
                    items: opts.item ? [opts.item] : undefined,
                    max: opts.max,
                    node
                },
                rsm: opts.rsm
            },
            to: jid,
            type: 'get'
        });
    });
}
