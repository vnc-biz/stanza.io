var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { EventEmitter } from 'events';
const MAX_SEQ = Math.pow(2, 32);
const mod = (v, n) => ((v % n) + n) % n;
export default class StreamManagement extends EventEmitter {
    constructor() {
        super();
        this.allowResume = true;
        this.lastAck = 0;
        this.handled = 0;
        this.unacked = [];
        this.inboundStarted = false;
        this.outboundStarted = false;
        this.id = undefined;
        this.jid = undefined;
        this.allowResume = true;
        this.started = false;
        this.cacheHandler = () => undefined;
        this._reset();
    }
    get started() {
        return this.outboundStarted && this.inboundStarted;
    }
    set started(value) {
        if (!value) {
            this.outboundStarted = false;
            this.inboundStarted = false;
        }
    }
    get resumable() {
        return this.started && this.allowResume;
    }
    load(opts) {
        var _a;
        this.id = opts.id;
        this.allowResume = (_a = opts.allowResume) !== null && _a !== void 0 ? _a : true;
        this.handled = opts.handled;
        this.lastAck = opts.lastAck;
        this.unacked = opts.unacked;
        this.emit('prebound', opts.jid);
    }
    cache(handler) {
        this.cacheHandler = handler;
    }
    bind(jid) {
        return __awaiter(this, void 0, void 0, function* () {
            this.jid = jid;
            yield this._cache();
        });
    }
    enable() {
        return __awaiter(this, void 0, void 0, function* () {
            this.emit('send', {
                allowResumption: this.allowResume,
                type: 'enable'
            });
        });
    }
    resume() {
        return __awaiter(this, void 0, void 0, function* () {
            this.emit('send', {
                handled: this.handled,
                previousSession: this.id,
                type: 'resume'
            });
        });
    }
    enabled(resp) {
        return __awaiter(this, void 0, void 0, function* () {
            this.id = resp.id;
            this.allowResume = resp.resume || false;
            this.handled = 0;
            this.inboundStarted = true;
            yield this._cache();
        });
    }
    resumed(resp) {
        return __awaiter(this, void 0, void 0, function* () {
            this.id = resp.previousSession;
            this.inboundStarted = true;
            yield this.process(resp, true);
            yield this._cache();
        });
    }
    failed(resp) {
        return __awaiter(this, void 0, void 0, function* () {
            // Resumption might fail, but the server can still tell us how far
            // the old session progressed.
            yield this.process(resp);
            // We alert that any remaining unacked stanzas failed to send. It has
            // been too long for auto-retrying these to be the right thing to do.
            for (const [kind, stanza] of this.unacked) {
                this.emit('failed', { kind, stanza });
            }
            this._reset();
            yield this._cache();
        });
    }
    ack() {
        this.emit('send', {
            handled: this.handled,
            type: 'ack'
        });
    }
    request() {
        this.emit('send', {
            type: 'request'
        });
    }
    process(ack_1) {
        return __awaiter(this, arguments, void 0, function* (ack, resend = false) {
            if (ack.handled === undefined) {
                return;
            }
            const numAcked = mod(ack.handled - this.lastAck, MAX_SEQ);
            for (let i = 0; i < numAcked && this.unacked.length > 0; i++) {
                const [kind, stanza] = this.unacked.shift();
                this.emit('acked', { kind, stanza });
            }
            this.lastAck = ack.handled;
            if (resend) {
                const resendUnacked = this.unacked;
                this.unacked = [];
                if (resendUnacked.length) {
                    this.emit('begin-resend');
                    for (const [kind, stanza] of resendUnacked) {
                        this.emit('resend', { kind, stanza });
                    }
                    this.emit('end-resend');
                }
            }
            yield this._cache();
        });
    }
    track(kind, stanza) {
        return __awaiter(this, void 0, void 0, function* () {
            const isStanzaEnable = stanza.type === 'enable';
            if (kind === 'sm' && (isStanzaEnable || stanza.type === 'resume')) {
                if (isStanzaEnable) {
                    this.handled = 0;
                }
                this.outboundStarted = true;
                yield this._cache();
                return false;
            }
            if (!this.outboundStarted) {
                return false;
            }
            if (kind !== 'message' && kind !== 'presence' && kind !== 'iq') {
                return false;
            }
            this.unacked.push([kind, stanza]);
            yield this._cache();
            return true;
        });
    }
    handle() {
        return __awaiter(this, void 0, void 0, function* () {
            if (this.inboundStarted) {
                this.handled = mod(this.handled + 1, MAX_SEQ);
                yield this._cache();
            }
        });
    }
    hibernate() {
        return __awaiter(this, void 0, void 0, function* () {
            if (!this.resumable) {
                return this.shutdown();
            }
            for (const [kind, stanza] of this.unacked) {
                this.emit('hibernated', { kind, stanza });
            }
        });
    }
    shutdown() {
        return __awaiter(this, void 0, void 0, function* () {
            return this.failed({ type: 'failed' });
        });
    }
    _cache() {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                yield this.cacheHandler({
                    allowResume: this.allowResume,
                    handled: this.handled,
                    id: this.id,
                    jid: this.jid,
                    lastAck: this.lastAck,
                    unacked: this.unacked
                });
            }
            catch (err) {
                // TODO: Is there a good way to handle this?
                // istanbul ignore next
                console.error('Failed to cache stream state', err);
            }
        });
    }
    _reset() {
        this.id = '';
        this.inboundStarted = false;
        this.outboundStarted = false;
        this.lastAck = 0;
        this.handled = 0;
        this.unacked = [];
    }
}
