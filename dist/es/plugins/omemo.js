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
import { NS_OMEMO_1, NS_OMEMO_1_BUNDLES, NS_OMEMO_1_DEVICES } from '../Namespaces';
const ENCRYPTED_MSG_DEFAULT_HINT = 'Encrypted message';
let KeyHelper;
let SignalProtocolAddress;
let SessionBuilder;
let SessionCipher;
let Curve;
export default function (client) {
    client.createOmemo = (store) => {
        client.omemo = new OmemoClient({ client, store });
    };
}
function notImplemented() {
    throw new Error('Function is not Implemented');
}
export class OmemoStorage {
    constructor() {
        this.Direction = OmemoStorage.Direction;
    }
    storeDevices(_jid, _devices) {
        notImplemented();
    }
    getDevices(_jid) {
        notImplemented();
    }
    hasDevices(_jid) {
        notImplemented();
    }
    storeWhisper(_address, _id, _whisper) {
        notImplemented();
    }
    getWhisper(_address, _id) {
        notImplemented();
    }
    getLocalRegistrationId() {
        notImplemented();
    }
    storeLocalRegistration(_device) {
        notImplemented();
    }
    getIdentityKeyPair() {
        notImplemented();
    }
    storeIdentityKeyPair(_keyPair) {
        notImplemented();
    }
    isTrustedIdentity(_identity, _identityKey, _direction) {
        notImplemented();
    }
    loadIdentityKey(_identity) {
        notImplemented();
    }
    saveIdentity(_identity, _identityKey) {
        notImplemented();
    }
    loadPreKey(_keyId) {
        notImplemented();
    }
    storePreKey(_keyId, _preKey) {
        notImplemented();
    }
    removePreKey(_keyId) {
        notImplemented();
    }
    loadSignedPreKey(_keyId) {
        notImplemented();
    }
    storeSignedPreKey(_keyId, _signedPreKey) {
        notImplemented();
    }
    removeSignedPreKey(_keyId) {
        notImplemented();
    }
    loadSession(_identifier) {
        notImplemented();
    }
    storeSession(_identifier, _session) {
        notImplemented();
    }
    removeSession(_identifier) {
        notImplemented();
    }
    removeAllSessions(_prefix) {
        notImplemented();
    }
    wrapFunction(name, func) {
        const orig = this[name].bind(this);
        this[name] = (...args) => func(orig, ...args);
    }
}
OmemoStorage.Direction = {
    SENDING: 1,
    RECEIVING: 2
};
export class OmemoUtils {
    static arrayBufferToBase64String(arrayBuffer) {
        const charArray = new Uint8Array(arrayBuffer);
        return btoa(charArray.reduce((carry, x) => carry + String.fromCharCode(x), ''));
    }
    static base64StringToArrayBuffer(str) {
        const byteStr = atob(str);
        const arrayBuffer = new ArrayBuffer(byteStr.length);
        const byteArray = new Uint8Array(arrayBuffer);
        for (let i = 0; i < byteStr.length; i++) {
            byteArray[i] = byteStr.charCodeAt(i);
        }
        return arrayBuffer;
    }
}
export class OmemoClient {
    constructor({ client, store = new OmemoStorage() }) {
        this.client = client;
        this.store = store;
        this.subscriptions = new Set();
        this.actualizedOpponentDevices = new Set();
        this.getAnnouncedDeviceIdsRequests = {};
        this.getAnnouncedDeviceIdsRequests2 = {};
        this.client.on('pubsub:event', (event) => this.handleDeviceList(event));
    }
    handleDeviceList(msg) {
        return __awaiter(this, void 0, void 0, function* () {
            var _a, _b, _c, _d, _e, _f;
            if (!((_b = (_a = msg.pubsub) === null || _a === void 0 ? void 0 : _a.items) === null || _b === void 0 ? void 0 : _b.published)) {
                return;
            }
            const node = (_d = (_c = msg.pubsub) === null || _c === void 0 ? void 0 : _c.items) === null || _d === void 0 ? void 0 : _d.node;
            if (node !== NS_OMEMO_1_DEVICES) {
                return;
            }
            const published = msg.pubsub.items.published;
            if (!published || published.length === 0) {
                return;
            }
            let devices = ((_f = (_e = published[0]) === null || _e === void 0 ? void 0 : _e.deviceList) === null || _f === void 0 ? void 0 : _f.devices) || [];
            devices = this.processDevices(devices);
            const from = typeof msg.from === 'string' ? msg.from : JID.toBare(msg.from);
            yield this.storeDevices(from, devices);
        });
    }
    processDevices(devices) {
        const ids = {};
        const processedDevices = [];
        devices = devices.map(d => (Object.assign(Object.assign({}, d), { id: +d.id })));
        devices.forEach(d => {
            if (!ids[d.id]) {
                processedDevices.push(d);
                ids[d.id] = true;
            }
        });
        return processedDevices;
    }
    storeDevices(jidBare, devices) {
        return __awaiter(this, void 0, void 0, function* () {
            yield this.store.storeDevices(jidBare, devices);
        });
    }
    start(platform) {
        return __awaiter(this, void 0, void 0, function* () {
            this.platform = `${platform} ${new Date().toISOString().split('T')[0]}`;
            const libsignal = window.libsignal;
            KeyHelper = libsignal.KeyHelper;
            SignalProtocolAddress = libsignal.SignalProtocolAddress;
            SessionBuilder = libsignal.SessionBuilder;
            SessionCipher = libsignal.SessionCipher;
            Curve = libsignal.Curve;
            let identityKeyPair = yield this.store.getIdentityKeyPair();
            let registrationId = yield this.store.getLocalRegistrationId();
            let isNew = false;
            this.store.wrapFunction('removePreKey', (next, id) => __awaiter(this, void 0, void 0, function* () {
                yield this.announce(this.buildDeviceInfo(yield this.store.getLocalRegistrationId()), yield this.store.getIdentityKeyPair(), false, id);
                yield next(id);
            }));
            if (!identityKeyPair || !registrationId) {
                registrationId = KeyHelper.generateRegistrationId();
                identityKeyPair = yield KeyHelper.generateIdentityKeyPair();
                isNew = true;
                yield this.store.storeIdentityKeyPair(identityKeyPair);
                yield this.store.storeLocalRegistration(this.buildDeviceInfo(registrationId));
            }
            yield this.announce(this.buildDeviceInfo(registrationId), identityKeyPair, isNew, null, true);
        });
    }
    buildDeviceInfo(deviceId) {
        return { id: deviceId, label: this.platform };
    }
    getAnnouncedDevices(jid_1) {
        return __awaiter(this, arguments, void 0, function* (jid, force = true) {
            var _a, _b, _c, _d, _e, _f;
            let localUserJid = this.client.jid;
            const localUserJidBare = typeof localUserJid === 'string' ? localUserJid : JID.toBare(localUserJid);
            if (!jid || jid === localUserJidBare) {
                jid = localUserJidBare;
            }
            if (force || !this.subscriptions.has(jid)) {
                try {
                    yield this.client.subscribeToNode(jid, {
                        node: NS_OMEMO_1_DEVICES,
                        jid: localUserJidBare
                    });
                }
                catch (e) {
                    // Server may not support PEP subscriptions — not fatal, continue with getItems
                    console.warn(`[OmemoClient][getAnnouncedDevices] subscribe to user ${jid} failed (server may not support PEP)`, ((_a = e === null || e === void 0 ? void 0 : e.error) === null || _a === void 0 ? void 0 : _a.condition) || e);
                }
                this.subscriptions.add(jid);
            }
            if (!force && (yield this.store.hasDevices(jid))) {
                return yield this.store.getDevices(jid);
            }
            let deviceList;
            try {
                deviceList = yield this.client.getOmemoItems(jid, NS_OMEMO_1_DEVICES);
                this.actualizedOpponentDevices.add(jid);
            }
            catch (e) {
                // Server timeout or node not found — return cached or empty
                console.warn(`[OmemoClient][getAnnouncedDevices] get items for ${jid} failed`, ((_b = e === null || e === void 0 ? void 0 : e.error) === null || _b === void 0 ? void 0 : _b.condition) || e);
                return [];
            }
            let devices = [];
            try {
                devices = ((_f = (_e = (_d = (_c = deviceList === null || deviceList === void 0 ? void 0 : deviceList.pubsub) === null || _c === void 0 ? void 0 : _c.retrieve) === null || _d === void 0 ? void 0 : _d.item) === null || _e === void 0 ? void 0 : _e.deviceList) === null || _f === void 0 ? void 0 : _f.devices) || [];
            }
            catch (e) {
                console.warn('[OmemoClient][getAnnouncedDevices] error parsing devices list', e);
            }
            devices = this.processDevices(devices);
            yield this.storeDevices(jid, devices);
            return devices;
        });
    }
    getDeviceKeyBundle(recipient, registrationId) {
        return __awaiter(this, void 0, void 0, function* () {
            var _a, _b, _c;
            const recipientJid = typeof recipient === 'string' ? recipient : JID.toBare(recipient);
            let keyBundle;
            try {
                keyBundle = yield this.client.getOmemoItems(recipientJid, NS_OMEMO_1_BUNDLES, {
                    item: { id: registrationId }
                });
            }
            catch (e) {
                console.error('[OmemoClient][getDeviceKeyBundle] error getting bundles', e);
                return null;
            }
            try {
                return ((_c = (_b = (_a = keyBundle === null || keyBundle === void 0 ? void 0 : keyBundle.pubsub) === null || _a === void 0 ? void 0 : _a.retrieve) === null || _b === void 0 ? void 0 : _b.item) === null || _c === void 0 ? void 0 : _c.bundle) || null;
            }
            catch (e) {
                console.warn('[OmemoClient][getDeviceKeyBundle] error parsing bundle', keyBundle);
                return null;
            }
        });
    }
    announceDevices(devices, newRegistrationId) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const maxDevices = 5;
                devices.sort((d1, d2) => {
                    const getTs = (d) => {
                        if (!d.label) {
                            return 0;
                        }
                        const parts = d.label.split(' ');
                        return Date.parse(parts[parts.length - 1]) || 0;
                    };
                    return getTs(d2) - getTs(d1);
                });
                const devicesMap = {};
                const devicesIdsToRemove = [];
                devices.forEach(d => {
                    if (d.label && d.label.includes(',')) {
                        const parts = d.label.split(' ');
                        const createdAt = parts[parts.length - 1];
                        const deviceName = d.label.replace(` ${createdAt}`, '');
                        if (devicesMap[deviceName]) {
                            const prevCreatedAt = devicesMap[deviceName].createdAt;
                            if (Date.parse(createdAt) > Date.parse(prevCreatedAt)) {
                                devicesIdsToRemove.push(devicesMap[deviceName].id);
                                devicesMap[deviceName] = { createdAt, id: d.id };
                            }
                            else if (newRegistrationId) {
                                if (newRegistrationId === d.id) {
                                    devicesIdsToRemove.push(devicesMap[deviceName].id);
                                    devicesMap[deviceName] = { createdAt, id: d.id };
                                }
                                else {
                                    devicesIdsToRemove.push(d.id);
                                }
                            }
                        }
                        else {
                            devicesMap[deviceName] = { createdAt, id: d.id };
                        }
                    }
                });
                if (devicesIdsToRemove.length > 0) {
                    devices = devices.filter(d => !devicesIdsToRemove.includes(d.id));
                }
                if (devices.length > maxDevices) {
                    devices = devices.slice(0, maxDevices);
                }
            }
            catch (e) {
                console.error('[OmemoClient][announceDevices] error removing old devices:', e);
            }
            const localDeviceId = yield this.store.getLocalRegistrationId();
            const clientJidBare = typeof this.client.jid === 'string' ? this.client.jid : JID.toBare(this.client.jid);
            yield this.client.publishOmemoDevice(clientJidBare, NS_OMEMO_1_DEVICES, {
                id: `${localDeviceId}`,
                deviceList: { devices }
            });
        });
    }
    announce(device_1, identityKeyPair_1, isNew_1) {
        return __awaiter(this, arguments, void 0, function* (device, identityKeyPair, isNew, removePreKey = null, isForceGetAnnouncedDevices = false) {
            let registrationId = device.id;
            const announcedDevices = yield this.getAnnouncedDevices(null, isForceGetAnnouncedDevices);
            const announcedDeviceIds = announcedDevices.map(d => d.id);
            if (announcedDeviceIds.includes(registrationId) && isNew) {
                registrationId = KeyHelper.generateRegistrationId();
                yield this.store.storeLocalRegistration(this.buildDeviceInfo(registrationId));
                yield this.announce(this.buildDeviceInfo(registrationId), identityKeyPair, true);
                return;
            }
            if (!announcedDeviceIds.includes(registrationId)) {
                announcedDevices.push(this.buildDeviceInfo(registrationId));
                try {
                    yield this.announceDevices(announcedDevices, isNew ? registrationId : null);
                }
                catch (e) {
                    console.warn('[OmemoClient][announce] announceDevices failed (server timeout?), continuing', e);
                }
            }
            const keyBundle = yield this.getDeviceKeyBundle(this.client.jid, registrationId);
            if (keyBundle &&
                OmemoUtils.arrayBufferToBase64String(identityKeyPair.pubKey) !== keyBundle.identityKey) {
                registrationId = KeyHelper.generateRegistrationId();
                yield this.store.storeLocalRegistration(this.buildDeviceInfo(registrationId));
                yield this.announce(this.buildDeviceInfo(registrationId), identityKeyPair, true);
                return;
            }
            const bundle = yield this.refillPreKeys(keyBundle, removePreKey);
            const clientJidBare = typeof this.client.jid === 'string' ? this.client.jid : JID.toBare(this.client.jid);
            try {
                yield this.client.publishOmemoBundle(clientJidBare, NS_OMEMO_1_BUNDLES, {
                    id: registrationId,
                    bundle
                });
            }
            catch (e) {
                console.warn('[OmemoClient][announce] publishOmemoBundle failed (server timeout?), continuing', e);
            }
        });
    }
    refillPreKeys(keyBundle_1) {
        return __awaiter(this, arguments, void 0, function* (keyBundle, removePreKey = null) {
            const identityPair = yield this.store.getIdentityKeyPair();
            if (!keyBundle) {
                keyBundle = {
                    preKeys: [],
                    signedPreKeyPublic: { id: '' }
                };
            }
            keyBundle.identityKey = OmemoUtils.arrayBufferToBase64String(identityPair.pubKey);
            let highestPreKeyId = keyBundle.preKeys.reduce((a, b) => Math.max(a, b), 1);
            keyBundle.preKeys = keyBundle.preKeys.filter((key) => !!this.store.loadPreKey(key.id) || `${removePreKey}` === `${key.id}`);
            while (keyBundle.preKeys.length < 100) {
                const { keyPair, keyId } = yield KeyHelper.generatePreKey(++highestPreKeyId);
                yield this.store.storePreKey(keyId, keyPair);
                keyBundle.preKeys.push({
                    id: keyId,
                    content: OmemoUtils.arrayBufferToBase64String(keyPair.pubKey)
                });
            }
            if (!keyBundle.signedPreKeyPublic.id) {
                const { keyPair, signature, keyId } = yield KeyHelper.generateSignedPreKey(identityPair, Math.floor(Math.random() * 235234));
                yield this.store.storeSignedPreKey(keyId, keyPair);
                keyBundle.signedPreKeySignature = OmemoUtils.arrayBufferToBase64String(signature);
                keyBundle.signedPreKeyPublic = {
                    content: OmemoUtils.arrayBufferToBase64String(keyPair.pubKey),
                    id: `${keyId}`
                };
            }
            return keyBundle;
        });
    }
    getRecipientSessions(isMUC, recipient) {
        return __awaiter(this, void 0, void 0, function* () {
            const recipientBareJid = JID.toBare(recipient);
            let devices = yield this.getAnnouncedDevices(recipient, !this.actualizedOpponentDevices.has(recipientBareJid));
            const deviceIds = devices.map(d => d.id);
            const sessions = [];
            const ownDeviceId = yield this.store.getLocalRegistrationId();
            const clientJidBare = typeof this.client.jid === 'string' ? this.client.jid : JID.toBare(this.client.jid);
            if (recipientBareJid === clientJidBare && !deviceIds.includes(ownDeviceId)) {
                deviceIds.push(ownDeviceId);
            }
            for (const deviceId of deviceIds) {
                const address = new SignalProtocolAddress(recipientBareJid, deviceId);
                const session = yield this.store.loadSession(address.toString());
                if (!session) {
                    const keyBundle = yield this.getDeviceKeyBundle(recipientBareJid, deviceId);
                    if (!keyBundle) {
                        continue;
                    }
                    const sessionBuilder = new SessionBuilder(this.store, address);
                    const preKey = keyBundle.preKeys[Math.floor(Math.random() * keyBundle.preKeys.length)];
                    try {
                        yield sessionBuilder.processPreKey({
                            registrationId: deviceId,
                            identityKey: OmemoUtils.base64StringToArrayBuffer(keyBundle.identityKey),
                            signedPreKey: {
                                keyId: parseInt(keyBundle.signedPreKeyPublic.id, 10),
                                publicKey: OmemoUtils.base64StringToArrayBuffer(keyBundle.signedPreKeyPublic.content),
                                signature: OmemoUtils.base64StringToArrayBuffer(keyBundle.signedPreKeySignature)
                            },
                            preKey: {
                                keyId: parseInt(preKey.id, 10),
                                publicKey: OmemoUtils.base64StringToArrayBuffer(preKey.content)
                            }
                        });
                    }
                    catch (e) {
                        console.warn(`[OmemoClient][getRecipientSessions] Failed processing PreKey[${recipientBareJid}:${preKey.id}]`);
                        continue;
                    }
                }
                sessions.push(new SessionCipher(this.store, address));
            }
            return sessions;
        });
    }
    decryptMessage(message) {
        return __awaiter(this, void 0, void 0, function* () {
            var _a, _b, _c;
            const header = (_a = message.encrypted) === null || _a === void 0 ? void 0 : _a.header;
            const localDeviceId = yield this.store.getLocalRegistrationId();
            const keys = ((header === null || header === void 0 ? void 0 : header.keys) || []).filter((key) => `${key.rid}` === `${localDeviceId}`);
            // v12: message.from is a plain string JID, not a JID object
            const fromStr = typeof message.from === 'string' ? message.from : String((_b = message.from) !== null && _b !== void 0 ? _b : '');
            const senderJid = (_c = (message.type === 'groupchat' ? JID.getResource(fromStr) : JID.toBare(fromStr))) !== null && _c !== void 0 ? _c : fromStr;
            const currentSenderDevice = parseInt(header === null || header === void 0 ? void 0 : header.sid, 10);
            let req = this.getAnnouncedDeviceIdsRequests[senderJid];
            if (!req) {
                req = this.getAnnouncedDevices(senderJid, true);
                this.getAnnouncedDeviceIdsRequests[senderJid] = req;
            }
            const localSenderDevicesMap = yield req;
            delete this.getAnnouncedDeviceIdsRequests[senderJid];
            if (!localSenderDevicesMap.map(d => d.id).includes(currentSenderDevice)) {
                let req2 = this.getAnnouncedDeviceIdsRequests2[senderJid];
                if (!req2) {
                    req2 = this.getAnnouncedDevices(senderJid, true);
                    this.getAnnouncedDeviceIdsRequests2[senderJid] = req2;
                }
                yield req2;
                delete this.getAnnouncedDeviceIdsRequests2[senderJid];
            }
            if (keys.length === 0) {
                console.warn('[OmemoClient][decryptMessage] ignore message: not encrypted for current device', localDeviceId);
                return null;
            }
            const subtleCrypto = window.crypto.subtle;
            const iv = OmemoUtils.base64StringToArrayBuffer(header.iv);
            const payload = OmemoUtils.base64StringToArrayBuffer(message.encrypted.payload);
            for (const key of keys) {
                const whisper = yield this.decryptWhisper(message, key);
                return yield this.decryptData(subtleCrypto, whisper, iv, payload);
            }
            return null;
        });
    }
    decryptWhisper(message, key) {
        return __awaiter(this, void 0, void 0, function* () {
            var _a, _b, _c, _d;
            const isMUC = message.type === 'groupchat';
            // v12: message.from is a plain string JID, not a JID object
            const fromStr = typeof message.from === 'string' ? message.from : String((_a = message.from) !== null && _a !== void 0 ? _a : '');
            const storeKey = (_b = (isMUC ? JID.getResource(fromStr) : JID.toBare(fromStr))) !== null && _b !== void 0 ? _b : fromStr;
            let whisper = yield this.store.getWhisper(storeKey, message.id);
            if (whisper) {
                return whisper;
            }
            const address = new SignalProtocolAddress(storeKey, (_d = (_c = message.encrypted) === null || _c === void 0 ? void 0 : _c.header) === null || _d === void 0 ? void 0 : _d.sid);
            const session = new SessionCipher(this.store, address);
            const keyData = OmemoUtils.base64StringToArrayBuffer(key.content);
            let plaintext;
            if (key.prekey) {
                plaintext = yield session.decryptPreKeyWhisperMessage(keyData, 'binary');
            }
            else {
                plaintext = yield session.decryptWhisperMessage(keyData, 'binary');
            }
            yield this.store.storeWhisper(storeKey, message.id, plaintext);
            return plaintext;
        });
    }
    decryptData(subtleCrypto, keyData, iv, data) {
        return __awaiter(this, void 0, void 0, function* () {
            const gcmKey = keyData.slice(0, 16);
            const authTag = new Uint8Array(keyData.byteLength - 16);
            authTag.set(new Uint8Array(keyData.slice(16)));
            const subtleKey = yield subtleCrypto.importKey('raw', gcmKey, { name: 'AES-GCM' }, false, [
                'decrypt',
                'encrypt'
            ]);
            const decryptData = new Uint8Array(data.byteLength + authTag.byteLength);
            decryptData.set(new Uint8Array(data));
            decryptData.set(authTag, data.byteLength);
            try {
                return yield subtleCrypto.decrypt({
                    name: 'AES-GCM',
                    iv,
                    tagLength: authTag.byteLength === 0 ? 128 : authTag.byteLength * 8
                }, subtleKey, decryptData);
            }
            catch (e) {
                console.error('[OmemoClient][decryptData] Failed decrypting data', e);
                return null;
            }
        });
    }
    sendMessage(rawMessage_1) {
        return __awaiter(this, arguments, void 0, function* (rawMessage, members = [rawMessage.to, rawMessage.from], encryptedMsgHint = ENCRYPTED_MSG_DEFAULT_HINT) {
            const isMUC = rawMessage.type === 'groupchat';
            const omemoMsg = Object.assign(Object.assign({}, rawMessage), { body: encryptedMsgHint, store: true, encrypted: yield this.createMessage(isMUC, rawMessage.body, members), encryption: {
                    namespace: NS_OMEMO_1,
                    name: 'OMEMO'
                } });
            return yield this.client.sendMessage(omemoMsg);
        });
    }
    createMessage(isMUC, plaintext, recipients) {
        return __awaiter(this, void 0, void 0, function* () {
            const subtleCrypto = window.crypto.subtle;
            const randomSource = new Uint8Array(32);
            yield window.crypto.getRandomValues(randomSource);
            const gcmKey = randomSource.slice(0, 16);
            const iv = randomSource.slice(16);
            const subtleKey = yield subtleCrypto.importKey('raw', gcmKey, { name: 'AES-GCM' }, false, [
                'decrypt',
                'encrypt'
            ]);
            const payload = new TextEncoder().encode(plaintext);
            const ciphertextWithAuth = yield subtleCrypto.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, subtleKey, payload.buffer);
            const ciphertext = ciphertextWithAuth.slice(0, ciphertextWithAuth.byteLength - 16);
            const authTag = ciphertextWithAuth.slice(ciphertextWithAuth.byteLength - 16);
            return {
                // authTag is ArrayBuffer (from ArrayBuffer.slice), not TypedArray — pass directly, no .buffer
                header: yield this.createHeader(isMUC, gcmKey.buffer, authTag, iv.buffer, recipients),
                payload: OmemoUtils.arrayBufferToBase64String(ciphertext)
            };
        });
    }
    createHeader(isMUC, key, auth, iv, recipients) {
        return __awaiter(this, void 0, void 0, function* () {
            const uniqueRecipients = new Set(recipients.map(jid => (typeof jid === 'string' ? jid : JID.toBare(jid))));
            const encryptedKeys = [];
            const payload = new ArrayBuffer(key.byteLength + auth.byteLength);
            const payloadArr = new Uint8Array(payload);
            payloadArr.set(new Uint8Array(key));
            payloadArr.set(new Uint8Array(auth), key.byteLength);
            for (const recipient of uniqueRecipients) {
                const recipientSessions = yield this.getRecipientSessions(isMUC, recipient);
                for (const recipientSession of recipientSessions) {
                    const { type, body } = yield recipientSession.encrypt(payload);
                    const keyObj = {
                        rid: yield recipientSession.getRemoteRegistrationId(),
                        content: btoa(body)
                    };
                    if (type === 3) {
                        keyObj.prekey = true;
                    }
                    encryptedKeys.push(keyObj);
                }
            }
            return {
                iv: OmemoUtils.arrayBufferToBase64String(iv),
                keys: encryptedKeys,
                sid: yield this.store.getLocalRegistrationId()
            };
        });
    }
}
