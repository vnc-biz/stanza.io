var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { priorityQueue } from './lib/AsyncPriorityQueue';
import { EventEmitter } from 'events';
import StreamManagement from './helpers/StreamManagement';
import * as JID from './JID';
import * as JXT from './jxt';
import * as SASL from './lib/sasl';
import { core as corePlugins } from './plugins';
import Protocol from './protocol';
import BOSH from './transports/bosh';
import WebSocket from './transports/websocket';
import { timeoutPromise, uuid } from './Utils';
import NetworkDiscovery from './helpers/NetworkDiscovery';
export default class Client extends EventEmitter {
    constructor(opts = {}) {
        super();
        this.reconnectAttempts = 0;
        this.setMaxListeners(100);
        // Some EventEmitter shims don't include off()
        this.off = this.removeListener;
        this.updateConfig(opts);
        this.jid = '';
        this.sasl = new SASL.Factory();
        this.sasl.register('EXTERNAL', SASL.EXTERNAL, 1000);
        this.sasl.register('SCRAM-SHA-256-PLUS', SASL.SCRAM, 350);
        this.sasl.register('SCRAM-SHA-256', SASL.SCRAM, 300);
        this.sasl.register('SCRAM-SHA-1-PLUS', SASL.SCRAM, 250);
        this.sasl.register('SCRAM-SHA-1', SASL.SCRAM, 200);
        this.sasl.register('DIGEST-MD5', SASL.DIGEST, 100);
        this.sasl.register('OAUTHBEARER', SASL.OAUTH, 100);
        this.sasl.register('X-OAUTH2', SASL.PLAIN, 50);
        this.sasl.register('PLAIN', SASL.PLAIN, 1);
        this.sasl.register('ANONYMOUS', SASL.ANONYMOUS, 0);
        this.stanzas = new JXT.Registry();
        this.stanzas.define(Protocol);
        this.resolver = new NetworkDiscovery();
        this.use(corePlugins);
        this.sm = new StreamManagement();
        if (this.config.allowResumption !== undefined) {
            this.sm.allowResume = this.config.allowResumption;
        }
        this.sm.on('prebound', jid => {
            this.jid = jid;
            this.emit('session:bound', jid);
        });
        this.on('session:bound', jid => this.sm.bind(jid));
        this.sm.on('send', sm => this.send('sm', sm));
        this.sm.on('acked', acked => this.emit('stanza:acked', acked));
        this.sm.on('failed', failed => this.emit('stanza:failed', failed));
        this.sm.on('hibernated', data => this.emit('stanza:hibernated', data));
        // We disable outgoing processing while stanza resends are queued up
        // to prevent any interleaving.
        this.sm.on('begin-resend', () => this.outgoingDataQueue.pause());
        this.sm.on('resend', ({ kind, stanza }) => this.send(kind, stanza, true));
        this.sm.on('end-resend', () => this.outgoingDataQueue.resume());
        // Create message:* flavors of stanza:* SM events
        for (const type of ['acked', 'hibernated', 'failed']) {
            this.on(`stanza:${type}`, (data) => {
                if (data.kind === 'message') {
                    this.emit(`message:${type}`, data.stanza);
                }
            });
        }
        this.transports = {
            bosh: BOSH,
            websocket: WebSocket
        };
        this.incomingDataQueue = priorityQueue((task, done) => __awaiter(this, void 0, void 0, function* () {
            const { kind, stanza } = task;
            this.emit(kind, stanza);
            if (stanza.id) {
                this.emit((kind + ':id:' + stanza.id), stanza);
            }
            if (kind === 'message' || kind === 'presence' || kind === 'iq') {
                this.emit('stanza', stanza);
                yield this.sm.handle();
            }
            else if (kind === 'sm') {
                if (stanza.type === 'ack') {
                    yield this.sm.process(stanza);
                    this.emit('stream:management:ack', stanza);
                }
                if (stanza.type === 'request') {
                    this.sm.ack();
                }
            }
            if (done) {
                done();
            }
        }), 1);
        const handleFailedSend = (kind, stanza) => {
            if (['message', 'presence', 'iq'].includes(kind)) {
                if (!this.sm.started || !this.sm.resumable) {
                    this.emit('stanza:failed', {
                        kind,
                        stanza
                    });
                }
                else if (this.sm.resumable && !this.transport) {
                    this.emit('stanza:hibernated', {
                        kind,
                        stanza
                    });
                }
            }
        };
        this.outgoingDataQueue = priorityQueue((task, done) => __awaiter(this, void 0, void 0, function* () {
            var _a;
            const { kind, stanza, replay } = task;
            const ackRequest = replay || (yield this.sm.track(kind, stanza));
            if (kind === 'message') {
                if (replay) {
                    this.emit('message:retry', stanza);
                }
                else {
                    this.emit('message:sent', stanza, false);
                }
            }
            if (this.transport) {
                try {
                    yield this.transport.send(kind, stanza);
                    if (ackRequest) {
                        (_a = this.transport) === null || _a === void 0 ? void 0 : _a.send('sm', { type: 'request' });
                    }
                }
                catch (err) {
                    console.error(err);
                    handleFailedSend(kind, stanza);
                }
            }
            else {
                handleFailedSend(kind, stanza);
            }
            if (done) {
                done();
            }
        }), 1);
        this.on('stream:data', (json, kind) => {
            this.incomingDataQueue.push({
                kind,
                stanza: json
            }, 0);
        });
        this.on('--transport-disconnected', () => __awaiter(this, void 0, void 0, function* () {
            const drains = [];
            if (!this.incomingDataQueue.idle()) {
                drains.push(this.incomingDataQueue.drain());
            }
            if (!this.outgoingDataQueue.idle()) {
                drains.push(this.outgoingDataQueue.drain());
            }
            yield Promise.all(drains);
            yield this.sm.hibernate();
            if (this.transport) {
                delete this.transport;
            }
            this.emit('--reset-stream-features');
            if (!this.sessionTerminating && this.config.autoReconnect) {
                this.reconnectAttempts += 1;
                clearTimeout(this.reconnectTimer);
                this.reconnectTimer = setTimeout(() => {
                    this.connect();
                }, 1000 * Math.min(Math.pow(2, this.reconnectAttempts) + Math.random(), this.config.maxReconnectBackoff || 32));
            }
            this.emit('disconnected');
        }));
        this.on('iq', (iq) => {
            const iqType = iq.type;
            const payloadType = iq.payloadType;
            const iqEvent = 'iq:' + iqType + ':' + payloadType;
            if (iqType === 'get' || iqType === 'set') {
                if (payloadType === 'invalid-payload-count') {
                    return this.sendIQError(iq, {
                        error: {
                            condition: 'bad-request',
                            type: 'modify'
                        }
                    });
                }
                if (payloadType === 'unknown-payload' || this.listenerCount(iqEvent) === 0) {
                    return this.sendIQError(iq, {
                        error: {
                            condition: 'service-unavailable',
                            type: 'cancel'
                        }
                    });
                }
                this.emit(iqEvent, iq);
            }
        });
        this.on('message', msg => {
            const isChat = (msg.alternateLanguageBodies && msg.alternateLanguageBodies.length) ||
                (msg.links && msg.links.length);
            const isMarker = msg.marker && msg.marker.type !== 'markable';
            if (isChat && !isMarker) {
                if (msg.type === 'chat' || msg.type === 'normal') {
                    this.emit('chat', msg);
                }
                else if (msg.type === 'groupchat') {
                    this.emit('groupchat', msg);
                }
            }
            if (msg.type === 'error') {
                this.emit('message:error', msg);
            }
        });
        this.on('presence', (pres) => {
            let presType = pres.type || 'available';
            if (presType === 'error') {
                presType = 'presence:error';
            }
            this.emit(presType, pres);
        });
        this.on('session:started', () => {
            this.sessionStarting = false;
            this.reconnectAttempts = 0;
            if (this.reconnectTimer) {
                clearTimeout(this.reconnectTimer);
            }
        });
    }
    updateConfig(opts = {}) {
        var _a;
        const currConfig = this.config || {};
        this.config = Object.assign(Object.assign({ allowResumption: true, jid: '', transports: {
                bosh: true,
                websocket: true
            }, useStreamManagement: true, transportPreferenceOrder: ['websocket', 'bosh'] }, currConfig), opts);
        if (!this.config.server) {
            this.config.server = JID.getDomain(this.config.jid);
        }
        if (this.config.password) {
            this.config.credentials = this.config.credentials || {};
            this.config.credentials.password = this.config.password;
            delete this.config.password;
        }
        if (!this.config.transportPreferenceOrder) {
            this.config.transportPreferenceOrder = Object.keys((_a = this.config.transports) !== null && _a !== void 0 ? _a : {});
        }
    }
    get stream() {
        return this.transport ? this.transport.stream : undefined;
    }
    emit(name, ...args) {
        // Continue supporting the most common and useful wildcard events
        const res = super.emit(name, ...args);
        if (name === 'raw') {
            super.emit(`raw:${args[0]}`, args[1]);
            super.emit('raw:*', `raw:${args[0]}`, args[1]);
            super.emit('*', `raw:${args[0]}`, args[1]);
        }
        else {
            super.emit('*', name, ...args);
        }
        return res;
    }
    use(pluginInit) {
        if (typeof pluginInit !== 'function') {
            return;
        }
        pluginInit(this, this.stanzas, this.config);
    }
    nextId() {
        return uuid();
    }
    getCredentials() {
        return __awaiter(this, void 0, void 0, function* () {
            return this._getConfiguredCredentials();
        });
    }
    connect() {
        return __awaiter(this, void 0, void 0, function* () {
            var _a, _b, _c;
            this.sessionTerminating = false;
            this.sessionStarting = true;
            this.emit('--reset-stream-features');
            if (this.transport) {
                this.transport.disconnect(false);
            }
            const transportPref = (_a = this.config.transportPreferenceOrder) !== null && _a !== void 0 ? _a : [];
            let endpoints;
            for (const name of transportPref) {
                const settings = this.config.transports[name];
                if (!settings || !this.transports[name]) {
                    continue;
                }
                let config = {
                    acceptLanguages: this.config.acceptLanguages || [(_b = this.config.lang) !== null && _b !== void 0 ? _b : 'en'],
                    jid: this.config.jid,
                    lang: (_c = this.config.lang) !== null && _c !== void 0 ? _c : 'en',
                    server: this.config.server
                };
                const transport = new this.transports[name](this, this.sm, this.stanzas);
                if (typeof settings === 'string') {
                    config.url = settings;
                }
                else if (settings == true) {
                    if (transport.discoverBindings) {
                        const discovered = yield transport.discoverBindings(this.config.server);
                        if (!discovered) {
                            continue;
                        }
                        config = Object.assign(Object.assign({}, config), discovered);
                    }
                    else {
                        if (!endpoints) {
                            try {
                                endpoints = yield this.discoverBindings(this.config.server);
                            }
                            catch (err) {
                                console.error(err);
                                continue;
                            }
                        }
                        endpoints[name] = (endpoints[name] || []).filter(url => url.startsWith('wss:') || url.startsWith('https:'));
                        if (!endpoints[name] || !endpoints[name].length) {
                            continue;
                        }
                        config.url = endpoints[name][0];
                    }
                }
                this.transport = transport;
                this.transport.connect(config);
                return;
            }
            console.error('No endpoints found for the requested transports.');
            this.emit('--transport-disconnected');
        });
    }
    disconnect() {
        return __awaiter(this, void 0, void 0, function* () {
            this.sessionTerminating = true;
            clearTimeout(this.reconnectTimer);
            this.outgoingDataQueue.pause();
            if (this.sessionStarted && !this.sm.started) {
                // Only emit session:end if we had a session, and we aren't using
                // stream management to keep the session alive.
                this.emit('session:end');
            }
            this.emit('--reset-stream-features');
            this.sessionStarted = false;
            if (this.transport) {
                this.transport.disconnect();
            }
            else {
                this.emit('--transport-disconnected');
            }
            this.outgoingDataQueue.resume();
            if (!this.outgoingDataQueue.idle()) {
                yield this.outgoingDataQueue.drain();
            }
            yield this.sm.shutdown();
        });
    }
    send(kind_1, stanza_1) {
        return __awaiter(this, arguments, void 0, function* (kind, stanza, replay = false) {
            return new Promise((resolve, reject) => {
                this.outgoingDataQueue.push({ kind, stanza, replay }, replay ? 0 : 1, err => err ? reject(err) : resolve());
            });
        });
    }
    sendMessage(data) {
        const id = data.id || this.nextId();
        const msg = Object.assign({ id, originId: id }, data);
        this.send('message', msg);
        return msg.id;
    }
    sendPresence(data = {}) {
        const pres = Object.assign({ id: this.nextId() }, data);
        this.send('presence', pres);
        return pres.id;
    }
    sendIQ(data) {
        const iq = Object.assign({ id: this.nextId() }, data);
        const allowed = JID.allowedResponders(this.jid, data.to);
        const respEvent = 'iq:id:' + iq.id;
        const request = new Promise((resolve, reject) => {
            const handler = (res) => {
                // Only process result from the correct responder
                if (!allowed.has(res.from)) {
                    return;
                }
                // Only process result or error responses, if the responder
                // happened to send us a request using the same ID value at
                // the same time.
                if (res.type !== 'result' && res.type !== 'error') {
                    return;
                }
                this.off(respEvent, handler);
                if (res.type === 'result') {
                    resolve(res);
                }
                else {
                    reject(res);
                }
            };
            this.on(respEvent, handler);
        });
        this.send('iq', iq);
        const timeout = this.config.timeout || 15;
        return timeoutPromise(request, timeout * 1000, () => (Object.assign(Object.assign({}, iq), { to: undefined, from: undefined, error: {
                condition: 'timeout',
                text: `Request timed out after ${timeout} seconds.`
            }, id: iq.id, type: 'error' })));
    }
    sendIQResult(original, reply) {
        this.send('iq', Object.assign(Object.assign({}, reply), { id: original.id, to: original.from, type: 'result' }));
    }
    sendIQError(original, error) {
        this.send('iq', Object.assign(Object.assign({}, error), { id: original.id, to: original.from, type: 'error' }));
    }
    sendStreamError(error) {
        this.emit('stream:error', error);
        this.send('error', error);
        this.disconnect();
    }
    _getConfiguredCredentials() {
        const creds = this.config.credentials || {};
        const requestedJID = JID.parse(this.config.jid || '');
        const username = creds.username || requestedJID.local;
        const server = creds.host || requestedJID.domain;
        return Object.assign({ host: server, password: this.config.password, realm: server, serviceName: server, serviceType: 'xmpp', username }, creds);
    }
}
