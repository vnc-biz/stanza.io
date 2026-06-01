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
import * as Hashes from '../platform';
import { JINGLE_INFO_CHECKSUM_5, JingleAction, JingleSessionRole } from '../Constants';
import { NS_JINGLE_FILE_TRANSFER_5 } from '../Namespaces';
import ICESession from './ICESession';
import { exportToSDP, importFromSDP } from './sdp/Intermediate';
import { convertIntermediateToRequest, convertRequestToIntermediate } from './sdp/Protocol';
export class Sender extends EventEmitter {
    constructor(opts = {}) {
        super();
        this.config = Object.assign({ chunkSize: 16384, hash: 'sha-1' }, opts);
        this.file = undefined;
        this.channel = undefined;
        this.hash = Hashes.createHash(this.config.hash);
    }
    send(file, channel) {
        if (this.file && this.channel) {
            return;
        }
        this.file = file;
        this.channel = channel;
        this.channel.binaryType = 'arraybuffer';
        const fileReader = new FileReader();
        let offset = 0;
        let pendingRead = false;
        const sliceFile = () => {
            if (pendingRead || offset >= file.size) {
                return;
            }
            pendingRead = true;
            const slice = file.slice(offset, offset + this.config.chunkSize);
            fileReader.readAsArrayBuffer(slice);
        };
        channel.bufferedAmountLowThreshold = 8 * this.config.chunkSize;
        channel.onbufferedamountlow = () => {
            sliceFile();
        };
        fileReader.addEventListener('load', (event) => {
            const data = event.target.result;
            pendingRead = false;
            offset += data.byteLength;
            this.channel.send(data);
            this.hash.update(new Uint8Array(data));
            this.emit('progress', offset, file.size, data);
            if (offset < file.size) {
                if (this.channel.bufferedAmount <= this.channel.bufferedAmountLowThreshold) {
                    sliceFile();
                }
                // Otherwise wait for bufferedamountlow event to trigger reading more data
            }
            else {
                this.emit('progress', file.size, file.size, null);
                this.emit('sentFile', {
                    algorithm: this.config.hash,
                    name: file.name,
                    size: file.size,
                    value: this.hash.digest()
                });
            }
        });
        sliceFile();
    }
}
export class Receiver extends EventEmitter {
    constructor(opts = {}) {
        super();
        this.config = Object.assign({ hash: 'sha-1' }, opts);
        this.receiveBuffer = [];
        this.received = 0;
        this.channel = undefined;
        this.hash = Hashes.createHash(this.config.hash);
    }
    receive(metadata, channel) {
        this.metadata = metadata;
        this.channel = channel;
        this.channel.binaryType = 'arraybuffer';
        this.channel.onmessage = e => {
            const len = e.data.byteLength;
            this.received += len;
            this.receiveBuffer.push(e.data);
            if (e.data) {
                this.hash.update(new Uint8Array(e.data));
            }
            this.emit('progress', this.received, this.metadata.size, e.data);
            if (this.received === this.metadata.size) {
                this.metadata.actualhash = this.hash.digest('hex');
                this.emit('receivedFile', new Blob(this.receiveBuffer), this.metadata);
                this.receiveBuffer = [];
            }
            else if (this.received > this.metadata.size) {
                // FIXME
                console.error('received more than expected, discarding...');
                this.receiveBuffer = []; // just discard...
            }
        };
    }
}
export default class FileTransferSession extends ICESession {
    constructor(opts) {
        super(opts);
        this.sender = undefined;
        this.receiver = undefined;
        this.file = undefined;
    }
    start(file, next) {
        return __awaiter(this, void 0, void 0, function* () {
            next = next || (() => undefined);
            if (!file || typeof file === 'function') {
                throw new Error('File object required');
            }
            this.state = 'pending';
            this.role = 'initiator';
            this.file = file;
            this.sender = new Sender();
            this.sender.on('progress', (sent, size) => {
                this._log('info', 'Send progress ' + sent + '/' + size);
            });
            this.sender.on('sentFile', meta => {
                this._log('info', 'Sent file', meta.name);
                this.send(JingleAction.SessionInfo, {
                    info: {
                        creator: JingleSessionRole.Initiator,
                        file: {
                            hashes: [
                                {
                                    algorithm: meta.algorithm,
                                    value: meta.value
                                }
                            ]
                        },
                        infoType: JINGLE_INFO_CHECKSUM_5,
                        name: this.contentName
                    }
                });
                this.parent.emit('sentFile', this, meta);
            });
            this.channel = this.pc.createDataChannel('filetransfer', {
                ordered: true
            });
            this.channel.onopen = () => {
                this.sender.send(this.file, this.channel);
            };
            try {
                yield this.processLocal(JingleAction.SessionInitiate, () => __awaiter(this, void 0, void 0, function* () {
                    const offer = yield this.pc.createOffer({
                        offerToReceiveAudio: false,
                        offerToReceiveVideo: false
                    });
                    const json = importFromSDP(offer.sdp);
                    const jingle = convertIntermediateToRequest(json, this.role, this.transportType);
                    this.contentName = jingle.contents[0].name;
                    jingle.sid = this.sid;
                    jingle.action = JingleAction.SessionInitiate;
                    jingle.contents[0].application = {
                        applicationType: NS_JINGLE_FILE_TRANSFER_5,
                        file: {
                            date: file.lastModified ? new Date(file.lastModified) : undefined,
                            hashesUsed: [
                                {
                                    algorithm: 'sha-1'
                                }
                            ],
                            name: file.name,
                            size: file.size
                        }
                    };
                    this.send('session-initiate', jingle);
                    yield this.pc.setLocalDescription(offer);
                }));
                next();
            }
            catch (err) {
                this._log('error', 'Could not create WebRTC offer', err);
                return this.end('failed-application', true);
            }
        });
    }
    accept(next) {
        return __awaiter(this, void 0, void 0, function* () {
            this._log('info', 'Accepted incoming session');
            this.role = 'responder';
            this.state = 'active';
            next = next || (() => undefined);
            try {
                yield this.processLocal(JingleAction.SessionAccept, () => __awaiter(this, void 0, void 0, function* () {
                    const answer = yield this.pc.createAnswer();
                    const json = importFromSDP(answer.sdp);
                    const jingle = convertIntermediateToRequest(json, this.role, this.transportType);
                    jingle.sid = this.sid;
                    jingle.action = 'session-accept';
                    for (const content of jingle.contents) {
                        content.creator = 'initiator';
                    }
                    this.contentName = jingle.contents[0].name;
                    this.send('session-accept', jingle);
                    yield this.pc.setLocalDescription(answer);
                    yield this.processBufferedCandidates();
                }));
                next();
            }
            catch (err) {
                this._log('error', 'Could not create WebRTC answer', err);
                this.end('failed-application');
            }
        });
    }
    onSessionInitiate(changes, cb) {
        return __awaiter(this, void 0, void 0, function* () {
            this._log('info', 'Initiating incoming session');
            this.role = 'responder';
            this.state = 'pending';
            this.transportType = changes.contents[0].transport.transportType;
            const json = convertRequestToIntermediate(changes, this.peerRole);
            const sdp = exportToSDP(json);
            const desc = changes.contents[0].application;
            const hashes = desc.file.hashesUsed ? desc.file.hashesUsed : desc.file.hashes || [];
            this.receiver = new Receiver({ hash: hashes[0] && hashes[0].algorithm });
            this.receiver.on('progress', (received, size) => {
                this._log('info', 'Receive progress ' + received + '/' + size);
            });
            this.receiver.on('receivedFile', file => {
                this.receivedFile = file;
                this._maybeReceivedFile();
            });
            this.receiver.metadata = desc.file;
            this.pc.addEventListener('datachannel', e => {
                this.channel = e.channel;
                this.receiver.receive(this.receiver.metadata, e.channel);
            });
            try {
                yield this.pc.setRemoteDescription({ type: 'offer', sdp });
                yield this.processBufferedCandidates();
                cb();
            }
            catch (err) {
                this._log('error', 'Could not create WebRTC answer', err);
                cb({ condition: 'general-error' });
            }
        });
    }
    onSessionInfo(changes, cb) {
        const info = changes.info;
        if (!info || !info.file || !info.file.hashes) {
            return;
        }
        this.receiver.metadata.hashes = info.file.hashes;
        if (this.receiver.metadata.actualhash) {
            this._maybeReceivedFile();
        }
        cb();
    }
    _maybeReceivedFile() {
        if (!this.receiver.metadata.hashes || !this.receiver.metadata.hashes.length) {
            // unknown hash, file transfer not completed
            return;
        }
        for (const hash of this.receiver.metadata.hashes || []) {
            if (hash.value && hash.value.toString('hex') === this.receiver.metadata.actualhash) {
                this._log('info', 'File hash matches');
                this.parent.emit('receivedFile', this, this.receivedFile, this.receiver.metadata);
                this.end('success');
                return;
            }
        }
        this._log('error', 'File hash does not match');
        this.end('media-error');
    }
}
