var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import * as SDPUtils from 'sdp';
import { JingleAction, JingleReasonCondition, JingleSessionRole } from '../Constants';
import { NS_JINGLE_ICE_UDP_1 } from '../Namespaces';
import { exportToSDP, importFromSDP } from './sdp/Intermediate';
import { convertCandidateToIntermediate, convertIntermediateToCandidate, convertIntermediateToTransport, convertRequestToIntermediate } from './sdp/Protocol';
import BaseSession from './Session';
export default class ICESession extends BaseSession {
    constructor(opts) {
        super(opts);
        this.bitrateLimit = 0;
        this.candidateBuffer = [];
        this.transportType = NS_JINGLE_ICE_UDP_1;
        this.restartingIce = false;
        this.usingRelay = false;
        this.maxRelayBandwidth = opts.maxRelayBandwidth;
        this.pc = this.parent.createPeerConnection(this, Object.assign(Object.assign({}, opts.config), { iceServers: opts.iceServers }));
        this.pc.oniceconnectionstatechange = () => {
            this.onIceStateChange();
        };
        this.pc.onicecandidate = e => {
            if (e.candidate) {
                this.onIceCandidate(e);
            }
            else {
                this.onIceEndOfCandidates();
            }
        };
        this.restrictRelayBandwidth();
    }
    end(reason = 'success', silent = false) {
        this.pc.close();
        super.end(reason, silent);
    }
    /* actually do an ice restart */
    restartIce() {
        return __awaiter(this, void 0, void 0, function* () {
            // only initiators do an ice-restart to avoid conflicts.
            if (!this.isInitiator) {
                return;
            }
            if (this._maybeRestartingIce !== undefined) {
                clearTimeout(this._maybeRestartingIce);
            }
            this.restartingIce = true;
            try {
                yield this.processLocal('restart-ice', () => __awaiter(this, void 0, void 0, function* () {
                    const offer = yield this.pc.createOffer({ iceRestart: true });
                    // extract new ufrag / pwd, send transport-info with just that.
                    const json = importFromSDP(offer.sdp);
                    this.send(JingleAction.TransportInfo, {
                        contents: json.media.map(media => ({
                            creator: JingleSessionRole.Initiator,
                            name: media.mid,
                            transport: convertIntermediateToTransport(media, this.transportType)
                        })),
                        sid: this.sid
                    });
                    yield this.pc.setLocalDescription(offer);
                }));
            }
            catch (err) {
                this._log('error', 'Could not create WebRTC offer', err);
                this.end(JingleReasonCondition.FailedTransport, true);
            }
        });
    }
    // set the maximum bitrate. Only supported in Chrome and Firefox right now.
    setMaximumBitrate(maximumBitrate) {
        return __awaiter(this, void 0, void 0, function* () {
            if (this.maximumBitrate) {
                // potentially take into account bandwidth restrictions due to using TURN.
                maximumBitrate = Math.min(maximumBitrate, this.maximumBitrate);
            }
            this.currentBitrate = maximumBitrate;
            // changes the maximum bandwidth using RTCRtpSender.setParameters.
            const sender = this.pc.getSenders().find(s => !!s.track && s.track.kind === 'video');
            if (!sender || !sender.getParameters) {
                return;
            }
            try {
                yield this.processLocal('set-bitrate', () => __awaiter(this, void 0, void 0, function* () {
                    const parameters = sender.getParameters();
                    if (!parameters.encodings || !parameters.encodings.length) {
                        parameters.encodings = [{}];
                    }
                    if (maximumBitrate === 0) {
                        delete parameters.encodings[0].maxBitrate;
                    }
                    else {
                        parameters.encodings[0].maxBitrate = maximumBitrate;
                    }
                    yield sender.setParameters(parameters);
                }));
            }
            catch (err) {
                this._log('error', 'Set maximumBitrate failed', err);
            }
        });
    }
    // ----------------------------------------------------------------
    // Jingle action handers
    // ----------------------------------------------------------------
    onTransportInfo(changes, cb) {
        return __awaiter(this, void 0, void 0, function* () {
            if (changes.contents &&
                changes.contents[0] &&
                changes.contents[0].transport.gatheringComplete) {
                const candidate = { sdpMid: changes.contents[0].name, candidate: '' };
                try {
                    if (this.pc.signalingState === 'stable') {
                        yield this.pc.addIceCandidate(candidate);
                    }
                    else {
                        this.candidateBuffer.push(candidate);
                    }
                }
                catch (err) {
                    this._log('debug', 'Could not add null end-of-candidate');
                }
                finally {
                    cb();
                }
                return;
            }
            // detect an ice restart.
            if (this.pc.remoteDescription) {
                const remoteDescription = this.pc.remoteDescription;
                const remoteJSON = importFromSDP(remoteDescription.sdp);
                const remoteMedia = remoteJSON.media.find(m => m.mid === changes.contents[0].name);
                const currentUsernameFragment = remoteMedia.iceParameters.usernameFragment;
                const remoteUsernameFragment = changes.contents[0].transport
                    .usernameFragment;
                if (remoteUsernameFragment && currentUsernameFragment !== remoteUsernameFragment) {
                    for (const [idx, content] of changes.contents.entries()) {
                        const transport = content.transport;
                        remoteJSON.media[idx].iceParameters = {
                            password: transport.password,
                            usernameFragment: transport.usernameFragment
                        };
                        remoteJSON.media[idx].candidates = [];
                    }
                    try {
                        yield this.pc.setRemoteDescription({
                            type: remoteDescription.type,
                            sdp: exportToSDP(remoteJSON)
                        });
                        yield this.processBufferedCandidates();
                        if (remoteDescription.type === 'offer') {
                            const answer = yield this.pc.createAnswer();
                            yield this.pc.setLocalDescription(answer);
                            const json = importFromSDP(answer.sdp);
                            this.send(JingleAction.TransportInfo, {
                                contents: json.media.map(media => ({
                                    creator: JingleSessionRole.Initiator,
                                    name: media.mid,
                                    transport: convertIntermediateToTransport(media, this.transportType)
                                })),
                                sid: this.sid
                            });
                        }
                        else {
                            this.restartingIce = false;
                        }
                    }
                    catch (err) {
                        this._log('error', 'Could not do remote ICE restart', err);
                        cb(err);
                        this.end(JingleReasonCondition.FailedTransport);
                        return;
                    }
                }
            }
            const all = (changes.contents || []).map(content => {
                const sdpMid = content.name;
                const results = (content.transport.candidates || []).map((json) => __awaiter(this, void 0, void 0, function* () {
                    const candidate = SDPUtils.writeCandidate(convertCandidateToIntermediate(json));
                    if (this.pc.remoteDescription && this.pc.signalingState === 'stable') {
                        try {
                            yield this.pc.addIceCandidate({ sdpMid, candidate });
                        }
                        catch (err) {
                            this._log('error', 'Could not add ICE candidate', err);
                        }
                    }
                    else {
                        this.candidateBuffer.push({ sdpMid, candidate });
                    }
                }));
                return Promise.all(results);
            });
            try {
                yield Promise.all(all);
                cb();
            }
            catch (err) {
                this._log('error', `Could not process transport-info: ${err}`);
                cb(err);
            }
        });
    }
    onSessionAccept(changes, cb) {
        return __awaiter(this, void 0, void 0, function* () {
            this.state = 'active';
            const json = convertRequestToIntermediate(changes, this.peerRole);
            const sdp = exportToSDP(json);
            try {
                yield this.pc.setRemoteDescription({ type: 'answer', sdp });
                yield this.processBufferedCandidates();
                this.parent.emit('accepted', this, undefined);
                cb();
            }
            catch (err) {
                this._log('error', `Could not process WebRTC answer: ${err}`);
                cb({ condition: 'general-error' });
            }
        });
    }
    onSessionTerminate(changes, cb) {
        this._log('info', 'Terminating session');
        this.pc.close();
        super.end(changes.reason, true);
        cb();
    }
    // ----------------------------------------------------------------
    // ICE action handers
    // ----------------------------------------------------------------
    onIceCandidate(e) {
        if (!e.candidate || !e.candidate.candidate) {
            return;
        }
        const candidate = SDPUtils.parseCandidate(e.candidate.candidate);
        const jingle = {
            contents: [
                {
                    creator: JingleSessionRole.Initiator,
                    name: e.candidate.sdpMid,
                    transport: {
                        candidates: [convertIntermediateToCandidate(candidate)],
                        transportType: this.transportType,
                        usernameFragment: candidate.usernameFragment
                    }
                }
            ]
        };
        this._log('info', 'Discovered new ICE candidate', jingle);
        this.send(JingleAction.TransportInfo, jingle);
    }
    onIceEndOfCandidates() {
        this._log('info', 'ICE end of candidates');
        const json = importFromSDP(this.pc.localDescription.sdp);
        const firstMedia = json.media[0];
        // signal end-of-candidates with our first media mid/ufrag
        this.send(JingleAction.TransportInfo, {
            contents: [
                {
                    creator: JingleSessionRole.Initiator,
                    name: firstMedia.mid,
                    transport: {
                        gatheringComplete: true,
                        transportType: this.transportType,
                        usernameFragment: firstMedia.iceParameters.usernameFragment
                    }
                }
            ]
        });
    }
    onIceStateChange() {
        switch (this.pc.iceConnectionState) {
            case 'checking':
                this.connectionState = 'connecting';
                break;
            case 'completed':
            case 'connected':
                this.connectionState = 'connected';
                break;
            case 'disconnected':
                if (this.pc.signalingState === 'stable') {
                    this.connectionState = 'interrupted';
                }
                else {
                    this.connectionState = 'disconnected';
                }
                if (this.restartingIce) {
                    this.end(JingleReasonCondition.FailedTransport);
                    return;
                }
                this.maybeRestartIce();
                break;
            case 'failed':
                if (this.connectionState === 'failed' || this.restartingIce) {
                    this.end(JingleReasonCondition.FailedTransport);
                    return;
                }
                this.connectionState = 'failed';
                this.restartIce();
                break;
            case 'closed':
                this.connectionState = 'disconnected';
                if (this.restartingIce) {
                    this.end(JingleReasonCondition.FailedTransport);
                }
                else {
                    this.end();
                }
                break;
        }
    }
    processBufferedCandidates() {
        return __awaiter(this, void 0, void 0, function* () {
            for (const candidate of this.candidateBuffer) {
                try {
                    yield this.pc.addIceCandidate(candidate);
                }
                catch (err) {
                    this._log('error', 'Could not add ICE candidate', err);
                }
            }
            this.candidateBuffer = [];
        });
    }
    /* when using TURN, we might want to restrict the bandwidth
     * to the value specified by MAX_RELAY_BANDWIDTH
     * in order to prevent sending excessive traffic through
     * the TURN server.
     */
    restrictRelayBandwidth() {
        this.pc.addEventListener('iceconnectionstatechange', () => __awaiter(this, void 0, void 0, function* () {
            if (this.pc.iceConnectionState !== 'completed' &&
                this.pc.iceConnectionState !== 'connected') {
                return;
            }
            const stats = yield this.pc.getStats();
            let activeCandidatePair;
            stats.forEach(report => {
                if (report.type === 'transport') {
                    activeCandidatePair = stats.get(report.selectedCandidatePairId);
                }
            });
            // Fallback for Firefox.
            if (!activeCandidatePair) {
                stats.forEach(report => {
                    if (report.type === 'candidate-pair' && report.selected) {
                        activeCandidatePair = report;
                    }
                });
            }
            if (!activeCandidatePair) {
                return;
            }
            let isRelay = false;
            let localCandidateType = '';
            let remoteCandidateType = '';
            if (activeCandidatePair.remoteCandidateId) {
                const remoteCandidate = stats.get(activeCandidatePair.remoteCandidateId);
                if (remoteCandidate) {
                    remoteCandidateType = remoteCandidate.candidateType;
                }
            }
            if (activeCandidatePair.localCandidateId) {
                const localCandidate = stats.get(activeCandidatePair.localCandidateId);
                if (localCandidate) {
                    localCandidateType = localCandidate.candidateType;
                }
            }
            if (localCandidateType === 'relay' || remoteCandidateType === 'relay') {
                isRelay = true;
            }
            this.usingRelay = isRelay;
            this.parent.emit('iceConnectionType', this, {
                localCandidateType,
                relayed: isRelay,
                remoteCandidateType
            });
            if (isRelay && this.maxRelayBandwidth !== undefined) {
                this.maximumBitrate = this.maxRelayBandwidth;
                if (this.currentBitrate) {
                    this.setMaximumBitrate(Math.min(this.currentBitrate, this.maximumBitrate));
                }
                else {
                    this.setMaximumBitrate(this.maximumBitrate);
                }
            }
        }));
    }
    /* determine whether an ICE restart is in order
     * when transitioning to disconnected. Strategy is
     * 'wait 2 seconds for things to repair themselves'
     * 'maybe check if bytes are sent/received' by comparing
     *   getStats measurements
     */
    maybeRestartIce() {
        // only initiators do an ice-restart to avoid conflicts.
        if (!this.isInitiator) {
            return;
        }
        if (this._maybeRestartingIce !== undefined) {
            clearTimeout(this._maybeRestartingIce);
        }
        this._maybeRestartingIce = setTimeout(() => {
            this._maybeRestartingIce = undefined;
            if (this.pc.iceConnectionState === 'disconnected') {
                this.restartIce();
            }
        }, 2000);
    }
}
