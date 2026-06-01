var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { JINGLE_INFO_ACTIVE, JINGLE_INFO_HOLD, JINGLE_INFO_MUTE, JINGLE_INFO_RINGING, JINGLE_INFO_UNHOLD, JINGLE_INFO_UNMUTE, JingleAction } from '../Constants';
import ICESession from './ICESession';
import { exportToSDP, importFromSDP } from './sdp/Intermediate';
import { convertIntermediateToRequest, convertRequestToIntermediate } from './sdp/Protocol';
function applyStreamsCompatibility(content) {
    const application = content.application;
    /* signal .streams as a=ssrc: msid */
    if (application.streams &&
        application.streams.length &&
        application.sources &&
        application.sources.length) {
        const msid = application.streams[0];
        application.sources[0].parameters.msid = `${msid.id} ${msid.track}`;
        if (application.sourceGroups && application.sourceGroups.length > 0) {
            application.sources.push({
                parameters: {
                    cname: application.sources[0].parameters.cname,
                    msid: `${msid.id} ${msid.track}`
                },
                ssrc: application.sourceGroups[0].sources[1]
            });
        }
    }
}
export default class MediaSession extends ICESession {
    constructor(opts) {
        super(opts);
        this.includesAudio = false;
        this.includesVideo = false;
        this._ringing = false;
        this.pc.addEventListener('track', (e) => {
            this.onAddTrack(e.track, e.streams[0]);
        });
        if (opts.stream) {
            for (const track of opts.stream.getTracks()) {
                this.addTrack(track, opts.stream);
            }
        }
    }
    get ringing() {
        return this._ringing;
    }
    set ringing(value) {
        if (value !== this._ringing) {
            this._ringing = value;
        }
    }
    get streams() {
        if (this.pc.signalingState !== 'closed') {
            return this.pc.getRemoteStreams();
        }
        return [];
    }
    // ----------------------------------------------------------------
    // Session control methods
    // ----------------------------------------------------------------
    start(opts, next) {
        var arguments_1 = arguments;
        return __awaiter(this, void 0, void 0, function* () {
            this.state = 'pending';
            if (arguments_1.length === 1 && typeof opts === 'function') {
                next = opts;
                opts = {};
            }
            next = next || (() => undefined);
            opts = opts || {};
            this.role = 'initiator';
            this.offerOptions = opts;
            try {
                yield this.processLocal(JingleAction.SessionInitiate, () => __awaiter(this, void 0, void 0, function* () {
                    const offer = yield this.pc.createOffer(opts);
                    const json = importFromSDP(offer.sdp);
                    const jingle = convertIntermediateToRequest(json, this.role, this.transportType);
                    jingle.sid = this.sid;
                    jingle.action = JingleAction.SessionInitiate;
                    for (const content of jingle.contents || []) {
                        content.creator = 'initiator';
                        applyStreamsCompatibility(content);
                    }
                    yield this.pc.setLocalDescription(offer);
                    this.send('session-initiate', jingle);
                }));
                next();
            }
            catch (err) {
                this._log('error', 'Could not create WebRTC offer', err);
                this.end('failed-application', true);
            }
        });
    }
    accept(opts, next) {
        var arguments_2 = arguments;
        return __awaiter(this, void 0, void 0, function* () {
            // support calling with accept(next) or accept(opts, next)
            if (arguments_2.length === 1 && typeof opts === 'function') {
                next = opts;
                opts = {};
            }
            next = next || (() => undefined);
            opts = opts || {};
            this._log('info', 'Accepted incoming session');
            this.state = 'active';
            this.role = 'responder';
            try {
                yield this.processLocal(JingleAction.SessionAccept, () => __awaiter(this, void 0, void 0, function* () {
                    const answer = yield this.pc.createAnswer(opts);
                    const json = importFromSDP(answer.sdp);
                    const jingle = convertIntermediateToRequest(json, this.role, this.transportType);
                    jingle.sid = this.sid;
                    jingle.action = JingleAction.SessionAccept;
                    for (const content of jingle.contents || []) {
                        content.creator = 'initiator';
                    }
                    yield this.pc.setLocalDescription(answer);
                    yield this.processBufferedCandidates();
                    this.send('session-accept', jingle);
                }));
                next();
            }
            catch (err) {
                this._log('error', 'Could not create WebRTC answer', err);
                this.end('failed-application');
            }
        });
    }
    end(reason = 'success', silent = false) {
        for (const receiver of this.pc.getReceivers()) {
            this.onRemoveTrack(receiver.track);
        }
        super.end(reason, silent);
    }
    ring() {
        return this.processLocal('ring', () => __awaiter(this, void 0, void 0, function* () {
            this._log('info', 'Ringing on incoming session');
            this.ringing = true;
            this.send(JingleAction.SessionInfo, {
                info: {
                    infoType: JINGLE_INFO_RINGING
                }
            });
        }));
    }
    mute(creator, name) {
        return this.processLocal('mute', () => __awaiter(this, void 0, void 0, function* () {
            this._log('info', 'Muting', name);
            this.send(JingleAction.SessionInfo, {
                info: {
                    creator,
                    infoType: JINGLE_INFO_MUTE,
                    name
                }
            });
        }));
    }
    unmute(creator, name) {
        return this.processLocal('unmute', () => __awaiter(this, void 0, void 0, function* () {
            this._log('info', 'Unmuting', name);
            this.send(JingleAction.SessionInfo, {
                info: {
                    creator,
                    infoType: JINGLE_INFO_UNMUTE,
                    name
                }
            });
        }));
    }
    hold() {
        return this.processLocal('hold', () => __awaiter(this, void 0, void 0, function* () {
            this._log('info', 'Placing on hold');
            this.send('session-info', {
                info: {
                    infoType: JINGLE_INFO_HOLD
                }
            });
        }));
    }
    resume() {
        return this.processLocal('resume', () => __awaiter(this, void 0, void 0, function* () {
            this._log('info', 'Resuming from hold');
            this.send('session-info', {
                info: {
                    infoType: JINGLE_INFO_ACTIVE
                }
            });
        }));
    }
    // ----------------------------------------------------------------
    // Track control methods
    // ----------------------------------------------------------------
    addTrack(track, stream, cb) {
        if (track.kind === 'audio') {
            this.includesAudio = true;
        }
        if (track.kind === 'video') {
            this.includesVideo = true;
        }
        return this.processLocal('addtrack', () => __awaiter(this, void 0, void 0, function* () {
            if (this.pc.addTrack) {
                this.pc.addTrack(track, stream);
            }
            else {
                this.pc.addStream(stream);
            }
            if (cb) {
                cb();
            }
        }));
    }
    removeTrack(sender, cb) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.processLocal('removetrack', () => __awaiter(this, void 0, void 0, function* () {
                this.pc.removeTrack(sender);
                if (cb) {
                    return cb();
                }
            }));
        });
    }
    // ----------------------------------------------------------------
    // Track event handlers
    // ----------------------------------------------------------------
    onAddTrack(track, stream) {
        this._log('info', 'Track added');
        this.parent.emit('peerTrackAdded', this, track, stream);
    }
    onRemoveTrack(track) {
        this._log('info', 'Track removed');
        this.parent.emit('peerTrackRemoved', this, track);
    }
    // ----------------------------------------------------------------
    // Jingle action handers
    // ----------------------------------------------------------------
    onSessionInitiate(changes, cb) {
        return __awaiter(this, void 0, void 0, function* () {
            this._log('info', 'Initiating incoming session');
            this.state = 'pending';
            this.role = 'responder';
            this.transportType = changes.contents[0].transport.transportType;
            const json = convertRequestToIntermediate(changes, this.peerRole);
            for (const media of json.media) {
                if (media.kind === 'audio') {
                    this.includesAudio = true;
                }
                if (media.kind === 'video') {
                    this.includesVideo = true;
                }
                if (!media.streams) {
                    media.streams = [{ stream: 'legacy', track: media.kind }];
                }
            }
            const sdp = exportToSDP(json);
            try {
                yield this.pc.setRemoteDescription({ type: 'offer', sdp });
                yield this.processBufferedCandidates();
                return cb();
            }
            catch (err) {
                this._log('error', 'Could not create WebRTC answer', err);
                return cb({ condition: 'general-error' });
            }
        });
    }
    onSessionTerminate(changes, cb) {
        for (const receiver of this.pc.getReceivers()) {
            this.onRemoveTrack(receiver.track);
        }
        super.onSessionTerminate(changes, cb);
    }
    onSessionInfo(changes, cb) {
        const info = changes.info || { infoType: '' };
        switch (info.infoType) {
            case JINGLE_INFO_RINGING:
                this._log('info', 'Outgoing session is ringing');
                this.ringing = true;
                this.parent.emit('ringing', this);
                return cb();
            case JINGLE_INFO_HOLD:
                this._log('info', 'On hold');
                this.parent.emit('hold', this);
                return cb();
            case JINGLE_INFO_UNHOLD:
            case JINGLE_INFO_ACTIVE:
                this._log('info', 'Resuming from hold');
                this.parent.emit('resumed', this);
                return cb();
            case JINGLE_INFO_MUTE:
                this._log('info', 'Muting', info);
                this.parent.emit('mute', this, info);
                return cb();
            case JINGLE_INFO_UNMUTE:
                this._log('info', 'Unmuting', info);
                this.parent.emit('unmute', this, info);
                return cb();
            default:
        }
        return cb();
    }
}
