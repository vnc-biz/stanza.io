import { Agent } from '../';
import * as JID from '../JID';
import { NS_OMEMO_1, NS_OMEMO_1_BUNDLES, NS_OMEMO_1_DEVICES } from '../Namespaces';

declare module '../' {
    export interface Agent {
        omemo?: OmemoClient;
        createOmemo(store: OmemoStorage): void;
        publishOmemoDevice(jid: string, node: string, item: any): Promise<any>;
        publishOmemoBundle(jid: string, node: string, item: any): Promise<any>;
        getOmemoItems(jid: string, node: string, opts?: any): Promise<any>;
    }
}

const ENCRYPTED_MSG_DEFAULT_HINT = 'Encrypted message';

declare const window: any;

let KeyHelper: any;
let SignalProtocolAddress: any;
let SessionBuilder: any;
let SessionCipher: any;
let Curve: any;

export default function (client: Agent): void {
    client.createOmemo = (store: OmemoStorage) => {
        client.omemo = new OmemoClient({ client, store });
    };
}

function notImplemented(): never {
    throw new Error('Function is not Implemented');
}

export class OmemoStorage {
    static Direction = {
        SENDING: 1,
        RECEIVING: 2
    };

    Direction = OmemoStorage.Direction;

    storeDevices(_jid: string, _devices: OmemoDeviceInfo[]): Promise<void> {
        notImplemented();
    }

    getDevices(_jid: string): Promise<OmemoDeviceInfo[]> {
        notImplemented();
    }

    hasDevices(_jid: string): Promise<boolean> {
        notImplemented();
    }

    storeWhisper(_address: string, _id: string, _whisper: ArrayBuffer): Promise<void> {
        notImplemented();
    }

    getWhisper(_address: string, _id: string): Promise<ArrayBuffer | null> {
        notImplemented();
    }

    getLocalRegistrationId(): Promise<number> {
        notImplemented();
    }

    storeLocalRegistration(_device: OmemoDeviceInfo): Promise<void> {
        notImplemented();
    }

    getIdentityKeyPair(): Promise<{ pubKey: ArrayBuffer; privKey: ArrayBuffer } | null> {
        notImplemented();
    }

    storeIdentityKeyPair(_keyPair: { pubKey: ArrayBuffer; privKey: ArrayBuffer }): Promise<void> {
        notImplemented();
    }

    isTrustedIdentity(
        _identity: string,
        _identityKey: ArrayBuffer,
        _direction: number
    ): Promise<boolean> {
        notImplemented();
    }

    loadIdentityKey(_identity: string): Promise<ArrayBuffer | null> {
        notImplemented();
    }

    saveIdentity(_identity: string, _identityKey: ArrayBuffer): Promise<boolean> {
        notImplemented();
    }

    loadPreKey(_keyId: number): Promise<{ pubKey: ArrayBuffer; privKey: ArrayBuffer } | null> {
        notImplemented();
    }

    storePreKey(
        _keyId: number,
        _preKey: { pubKey: ArrayBuffer; privKey: ArrayBuffer }
    ): Promise<void> {
        notImplemented();
    }

    removePreKey(_keyId: number): Promise<void> {
        notImplemented();
    }

    loadSignedPreKey(
        _keyId: number
    ): Promise<{ pubKey: ArrayBuffer; privKey: ArrayBuffer } | null> {
        notImplemented();
    }

    storeSignedPreKey(
        _keyId: number,
        _signedPreKey: { pubKey: ArrayBuffer; privKey: ArrayBuffer }
    ): Promise<void> {
        notImplemented();
    }

    removeSignedPreKey(_keyId: number): Promise<void> {
        notImplemented();
    }

    loadSession(_identifier: string): Promise<string | null> {
        notImplemented();
    }

    storeSession(_identifier: string, _session: string): Promise<void> {
        notImplemented();
    }

    removeSession(_identifier: string): Promise<void> {
        notImplemented();
    }

    removeAllSessions(_prefix: string): Promise<void> {
        notImplemented();
    }

    wrapFunction(name: string, func: (orig: Function, ...args: any[]) => any): void {
        const orig = (this as any)[name].bind(this);
        (this as any)[name] = (...args: any[]) => func(orig, ...args);
    }
}

export interface OmemoDeviceInfo {
    id: number;
    label?: string;
}

export class OmemoUtils {
    static arrayBufferToBase64String(arrayBuffer: ArrayBuffer): string {
        const charArray = new Uint8Array(arrayBuffer);
        return btoa(charArray.reduce((carry, x) => carry + String.fromCharCode(x), ''));
    }

    static base64StringToArrayBuffer(str: string): ArrayBuffer {
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
    private client: Agent;
    private store: OmemoStorage;
    private subscriptions: Set<string>;
    private actualizedOpponentDevices: Set<string>;
    private getAnnouncedDeviceIdsRequests: Record<string, Promise<OmemoDeviceInfo[]>>;
    private getAnnouncedDeviceIdsRequests2: Record<string, Promise<OmemoDeviceInfo[]>>;
    private platform?: string;

    constructor({ client, store = new OmemoStorage() }: { client: Agent; store?: OmemoStorage }) {
        this.client = client;
        this.store = store;
        this.subscriptions = new Set();
        this.actualizedOpponentDevices = new Set();
        this.getAnnouncedDeviceIdsRequests = {};
        this.getAnnouncedDeviceIdsRequests2 = {};

        this.client.on('pubsub:event', (event: any) => this.handleDeviceList(event));
    }

    async handleDeviceList(msg: any): Promise<void> {
        if (!msg.pubsub?.items?.published) {
            return;
        }

        const node = msg.pubsub?.items?.node;
        if (node !== NS_OMEMO_1_DEVICES) {
            return;
        }

        const published = msg.pubsub.items.published;
        if (!published || published.length === 0) {
            return;
        }

        let devices: OmemoDeviceInfo[] = published[0]?.deviceList?.devices || [];
        devices = this.processDevices(devices);

        const from = typeof msg.from === 'string' ? msg.from : JID.toBare(msg.from);
        await this.storeDevices(from, devices);
    }

    processDevices(devices: OmemoDeviceInfo[]): OmemoDeviceInfo[] {
        const ids: Record<number, boolean> = {};
        const processedDevices: OmemoDeviceInfo[] = [];

        devices = devices.map(d => ({ ...d, id: +d.id }));

        devices.forEach(d => {
            if (!ids[d.id]) {
                processedDevices.push(d);
                ids[d.id] = true;
            }
        });

        return processedDevices;
    }

    async storeDevices(jidBare: string, devices: OmemoDeviceInfo[]): Promise<void> {
        await this.store.storeDevices(jidBare, devices);
    }

    async start(platform: string): Promise<void> {
        this.platform = `${platform} ${new Date().toISOString().split('T')[0]}`;

        const libsignal = window.libsignal;
        KeyHelper = libsignal.KeyHelper;
        SignalProtocolAddress = libsignal.SignalProtocolAddress;
        SessionBuilder = libsignal.SessionBuilder;
        SessionCipher = libsignal.SessionCipher;
        Curve = libsignal.Curve;

        let identityKeyPair = await this.store.getIdentityKeyPair();
        let registrationId = await this.store.getLocalRegistrationId();
        let isNew = false;

        this.store.wrapFunction('removePreKey', async (next: Function, id: number) => {
            await this.announce(
                this.buildDeviceInfo(await this.store.getLocalRegistrationId()),
                await this.store.getIdentityKeyPair(),
                false,
                id
            );
            await next(id);
        });

        if (!identityKeyPair || !registrationId) {
            registrationId = KeyHelper.generateRegistrationId();
            identityKeyPair = await KeyHelper.generateIdentityKeyPair();
            isNew = true;

            await this.store.storeIdentityKeyPair(identityKeyPair!);
            await this.store.storeLocalRegistration(this.buildDeviceInfo(registrationId));
        }

        await this.announce(this.buildDeviceInfo(registrationId), identityKeyPair, isNew, null, true);
    }

    buildDeviceInfo(deviceId: number): OmemoDeviceInfo {
        return { id: deviceId, label: this.platform };
    }

    async getAnnouncedDevices(jid?: string | null, force = true): Promise<OmemoDeviceInfo[]> {
        let localUserJid = this.client.jid;
        const localUserJidBare =
            JID.toBare(localUserJid);  // v12: always call toBare — jid may be full JID string

        if (!jid || jid === localUserJidBare) {
            jid = localUserJidBare;
        }

        if (force || !this.subscriptions.has(jid)) {
            try {
                await this.client.subscribeToNode(jid, {
                    node: NS_OMEMO_1_DEVICES,
                    jid: localUserJidBare
                });
            } catch (e) {
                // Server may not support PEP subscriptions — not fatal, continue with getItems
                console.warn(`[OmemoClient][getAnnouncedDevices] subscribe to user ${jid} failed (server may not support PEP)`, (e as any)?.error?.condition || e);
            }
            this.subscriptions.add(jid);
        }

        if (!force && (await this.store.hasDevices(jid))) {
            return await this.store.getDevices(jid);
        }

        let deviceList: any;
        try {
            deviceList = await this.client.getOmemoItems(jid, NS_OMEMO_1_DEVICES);
            this.actualizedOpponentDevices.add(jid);
        } catch (e) {
            // Server timeout or node not found — return cached or empty
            console.warn(`[OmemoClient][getAnnouncedDevices] get items for ${jid} failed`, (e as any)?.error?.condition || e);
            return [];
        }

        let devices: OmemoDeviceInfo[] = [];
        try {
            // v12 pubsub uses fetch.items[] not retrieve.item
            devices = deviceList?.pubsub?.fetch?.items?.[0]?.deviceList?.devices || [];
        } catch (e) {
            console.warn('[OmemoClient][getAnnouncedDevices] error parsing devices list', e);
        }

        devices = this.processDevices(devices);
        await this.storeDevices(jid, devices);
        return devices;
    }

    async getDeviceKeyBundle(recipient: string | any, registrationId: number): Promise<any> {
        const recipientJid =
            typeof recipient === 'string' ? recipient : JID.toBare(recipient);
        let keyBundle: any;
        try {
            keyBundle = await this.client.getOmemoItems(recipientJid, NS_OMEMO_1_BUNDLES, {
                item: { id: registrationId }
            });
        } catch (e) {
            console.error('[OmemoClient][getDeviceKeyBundle] error getting bundles', e);
            return null;
        }

        try {
            // v12 pubsub uses fetch.items[] not retrieve.item
            return keyBundle?.pubsub?.fetch?.items?.[0]?.omemo1Bundle || null;
        } catch (e) {
            console.warn('[OmemoClient][getDeviceKeyBundle] error parsing bundle', keyBundle);
            return null;
        }
    }

    async announceDevices(devices: OmemoDeviceInfo[], newRegistrationId?: number | null): Promise<void> {
        try {
            const maxDevices = 5;

            devices.sort((d1, d2) => {
                const getTs = (d: OmemoDeviceInfo) => {
                    if (!d.label) {
                        return 0;
                    }
                    const parts = d.label.split(' ');
                    return Date.parse(parts[parts.length - 1]) || 0;
                };
                return getTs(d2) - getTs(d1);
            });

            const devicesMap: Record<string, { createdAt: string; id: number }> = {};
            const devicesIdsToRemove: number[] = [];

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
                        } else if (newRegistrationId) {
                            if (newRegistrationId === d.id) {
                                devicesIdsToRemove.push(devicesMap[deviceName].id);
                                devicesMap[deviceName] = { createdAt, id: d.id };
                            } else {
                                devicesIdsToRemove.push(d.id);
                            }
                        }
                    } else {
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
        } catch (e) {
            console.error('[OmemoClient][announceDevices] error removing old devices:', e);
        }

        const localDeviceId = await this.store.getLocalRegistrationId();
        const clientJidBare =
            JID.toBare(this.client.jid)  // v12: always call toBare — jid may be full JID string;

        await this.client.publishOmemoDevice(clientJidBare, NS_OMEMO_1_DEVICES, {
            id: `${localDeviceId}`,
            deviceList: { devices }
        });
    }

    async announce(
        device: OmemoDeviceInfo,
        identityKeyPair: any,
        isNew: boolean,
        removePreKey: number | null = null,
        isForceGetAnnouncedDevices = false
    ): Promise<void> {
        let registrationId = device.id;

        const announcedDevices = await this.getAnnouncedDevices(null, isForceGetAnnouncedDevices);
        const announcedDeviceIds = announcedDevices.map(d => d.id);

        if (announcedDeviceIds.includes(registrationId) && isNew) {
            registrationId = KeyHelper.generateRegistrationId();
            await this.store.storeLocalRegistration(this.buildDeviceInfo(registrationId));
            await this.announce(this.buildDeviceInfo(registrationId), identityKeyPair, true);
            return;
        }

        if (!announcedDeviceIds.includes(registrationId)) {
            announcedDevices.push(this.buildDeviceInfo(registrationId));
            try {
                await this.announceDevices(announcedDevices, isNew ? registrationId : null);
            } catch (e) {
                console.warn('[OmemoClient][announce] announceDevices failed (server timeout?), continuing', e);
            }
        }

        const keyBundle = await this.getDeviceKeyBundle(this.client.jid, registrationId);

        if (
            keyBundle &&
            OmemoUtils.arrayBufferToBase64String(identityKeyPair.pubKey) !== keyBundle.identityKey
        ) {
            registrationId = KeyHelper.generateRegistrationId();
            await this.store.storeLocalRegistration(this.buildDeviceInfo(registrationId));
            await this.announce(this.buildDeviceInfo(registrationId), identityKeyPair, true);
            return;
        }

        const bundle = await this.refillPreKeys(keyBundle, removePreKey);
        const clientJidBare =
            JID.toBare(this.client.jid)  // v12: always call toBare — jid may be full JID string;

        try {
            await this.client.publishOmemoBundle(clientJidBare, NS_OMEMO_1_BUNDLES, {
                id: registrationId,
                bundle
            });
        } catch (e) {
            console.warn('[OmemoClient][announce] publishOmemoBundle failed (server timeout?), continuing', e);
        }
    }

    async refillPreKeys(keyBundle: any, removePreKey: number | null = null): Promise<any> {
        const identityPair = await this.store.getIdentityKeyPair();

        if (!keyBundle) {
            keyBundle = {
                preKeys: [],
                signedPreKeyPublic: { id: '' }
            };
        }

        keyBundle.identityKey = OmemoUtils.arrayBufferToBase64String(identityPair!.pubKey);

        let highestPreKeyId: number = keyBundle.preKeys.reduce(
            (a: number, b: any) => Math.max(a, b),
            1
        );

        keyBundle.preKeys = keyBundle.preKeys.filter(
            (key: any) =>
                !!this.store.loadPreKey(key.id) || `${removePreKey}` === `${key.id}`
        );

        while (keyBundle.preKeys.length < 100) {
            const { keyPair, keyId } = await KeyHelper.generatePreKey(++highestPreKeyId);
            await this.store.storePreKey(keyId, keyPair);
            keyBundle.preKeys.push({
                id: keyId,
                content: OmemoUtils.arrayBufferToBase64String(keyPair.pubKey)
            });
        }

        if (!keyBundle.signedPreKeyPublic.id) {
            const { keyPair, signature, keyId } = await KeyHelper.generateSignedPreKey(
                identityPair,
                Math.floor(Math.random() * 235234)
            );
            await this.store.storeSignedPreKey(keyId, keyPair);

            keyBundle.signedPreKeySignature = OmemoUtils.arrayBufferToBase64String(signature);
            keyBundle.signedPreKeyPublic = {
                content: OmemoUtils.arrayBufferToBase64String(keyPair.pubKey),
                id: `${keyId}`
            };
        }

        return keyBundle;
    }

    async getRecipientSessions(isMUC: boolean, recipient: string): Promise<any[]> {
        const recipientBareJid = JID.toBare(recipient);

        let devices = await this.getAnnouncedDevices(
            recipient,
            !this.actualizedOpponentDevices.has(recipientBareJid)
        );
        const deviceIds = devices.map(d => d.id);
        const sessions: any[] = [];
        const ownDeviceId = await this.store.getLocalRegistrationId();

        const clientJidBare =
            JID.toBare(this.client.jid)  // v12: always call toBare — jid may be full JID string;

        if (recipientBareJid === clientJidBare && !deviceIds.includes(ownDeviceId)) {
            deviceIds.push(ownDeviceId);
        }

        for (const deviceId of deviceIds) {
            const address = new SignalProtocolAddress(recipientBareJid, deviceId);
            const session = await this.store.loadSession(address.toString());
            if (!session) {
                const keyBundle = await this.getDeviceKeyBundle(recipientBareJid, deviceId);
                if (!keyBundle) {
                    continue;
                }

                const sessionBuilder = new SessionBuilder(this.store, address);
                const preKey = keyBundle.preKeys[Math.floor(Math.random() * keyBundle.preKeys.length)];

                try {
                    await sessionBuilder.processPreKey({
                        registrationId: deviceId,
                        identityKey: OmemoUtils.base64StringToArrayBuffer(keyBundle.identityKey),
                        signedPreKey: {
                            keyId: parseInt(keyBundle.signedPreKeyPublic.id, 10),
                            publicKey: OmemoUtils.base64StringToArrayBuffer(
                                keyBundle.signedPreKeyPublic.content
                            ),
                            signature: OmemoUtils.base64StringToArrayBuffer(
                                keyBundle.signedPreKeySignature
                            )
                        },
                        preKey: {
                            keyId: parseInt(preKey.id, 10),
                            publicKey: OmemoUtils.base64StringToArrayBuffer(preKey.content)
                        }
                    });
                } catch (e) {
                    console.warn(
                        `[OmemoClient][getRecipientSessions] Failed processing PreKey[${recipientBareJid}:${preKey.id}]`
                    );
                    continue;
                }
            }

            sessions.push(new SessionCipher(this.store, address));
        }

        return sessions;
    }

    async decryptMessage(message: any): Promise<ArrayBuffer | null> {
        const header = message.encrypted?.header;
        const localDeviceId = await this.store.getLocalRegistrationId();
        const keys = (header?.keys || []).filter(
            (key: any) => `${key.rid}` === `${localDeviceId}`
        );

        // v12: message.from is a plain string JID, not a JID object
        const fromStr = typeof message.from === 'string' ? message.from : String(message.from ?? '');
        const senderJid: string =
            (message.type === 'groupchat' ? JID.getResource(fromStr) : JID.toBare(fromStr)) ?? fromStr;
        const currentSenderDevice = parseInt(header?.sid, 10);

        let req = this.getAnnouncedDeviceIdsRequests[senderJid];
        if (!req) {
            req = this.getAnnouncedDevices(senderJid, true);
            this.getAnnouncedDeviceIdsRequests[senderJid] = req;
        }
        const localSenderDevicesMap = await req;
        delete this.getAnnouncedDeviceIdsRequests[senderJid];

        if (!localSenderDevicesMap.map(d => d.id).includes(currentSenderDevice)) {
            let req2 = this.getAnnouncedDeviceIdsRequests2[senderJid];
            if (!req2) {
                req2 = this.getAnnouncedDevices(senderJid, true);
                this.getAnnouncedDeviceIdsRequests2[senderJid] = req2;
            }
            await req2;
            delete this.getAnnouncedDeviceIdsRequests2[senderJid];
        }

        if (keys.length === 0) {
            console.warn(
                '[OmemoClient][decryptMessage] ignore message: not encrypted for current device',
                localDeviceId
            );
            return null;
        }

        const subtleCrypto = window.crypto.subtle;
        const iv = OmemoUtils.base64StringToArrayBuffer(header.iv);
        const payload = OmemoUtils.base64StringToArrayBuffer(message.encrypted.payload);

        for (const key of keys) {
            const whisper = await this.decryptWhisper(message, key);
            return await this.decryptData(subtleCrypto, whisper, iv, payload);
        }

        return null;
    }

    async decryptWhisper(message: any, key: any): Promise<ArrayBuffer> {
        const isMUC = message.type === 'groupchat';
        // v12: message.from is a plain string JID, not a JID object
        const fromStr = typeof message.from === 'string' ? message.from : String(message.from ?? '');
        const storeKey: string = (isMUC ? JID.getResource(fromStr) : JID.toBare(fromStr)) ?? fromStr;

        let whisper = await this.store.getWhisper(storeKey, message.id);
        if (whisper) {
            return whisper;
        }

        const address = new SignalProtocolAddress(
            storeKey,
            message.encrypted?.header?.sid
        );
        const session = new SessionCipher(this.store, address);
        const keyData = OmemoUtils.base64StringToArrayBuffer(key.content);

        let plaintext: ArrayBuffer;
        if (key.prekey) {
            plaintext = await session.decryptPreKeyWhisperMessage(keyData, 'binary');
        } else {
            plaintext = await session.decryptWhisperMessage(keyData, 'binary');
        }

        await this.store.storeWhisper(storeKey, message.id, plaintext);
        return plaintext;
    }

    async decryptData(
        subtleCrypto: SubtleCrypto,
        keyData: ArrayBuffer,
        iv: ArrayBuffer,
        data: ArrayBuffer
    ): Promise<ArrayBuffer | null> {
        const gcmKey = keyData.slice(0, 16);
        const authTag = new Uint8Array(keyData.byteLength - 16);
        authTag.set(new Uint8Array(keyData.slice(16)));

        const subtleKey = await subtleCrypto.importKey('raw', gcmKey, { name: 'AES-GCM' }, false, [
            'decrypt',
            'encrypt'
        ]);

        const decryptData = new Uint8Array(data.byteLength + authTag.byteLength);
        decryptData.set(new Uint8Array(data));
        decryptData.set(authTag, data.byteLength);

        try {
            return await subtleCrypto.decrypt(
                {
                    name: 'AES-GCM',
                    iv,
                    tagLength: authTag.byteLength === 0 ? 128 : authTag.byteLength * 8
                },
                subtleKey,
                decryptData
            );
        } catch (e) {
            console.error('[OmemoClient][decryptData] Failed decrypting data', e);
            return null;
        }
    }

    async sendMessage(
        rawMessage: any,
        members: any[] = [rawMessage.to, rawMessage.from],
        encryptedMsgHint = ENCRYPTED_MSG_DEFAULT_HINT
    ): Promise<any> {
        const isMUC = rawMessage.type === 'groupchat';
        const omemoMsg = {
            ...rawMessage,
            body: encryptedMsgHint,
            processingHints: { store: true },  // XEP-0334: tells server to archive this message
            encrypted: await this.createMessage(isMUC, rawMessage.body, members),
            encryption: {
                namespace: NS_OMEMO_1,
                name: 'OMEMO'
            }
        };
        return await this.client.sendMessage(omemoMsg);
    }

    async createMessage(isMUC: boolean, plaintext: string, recipients: any[]): Promise<any> {
        const subtleCrypto = window.crypto.subtle;
        const randomSource = new Uint8Array(32);
        await window.crypto.getRandomValues(randomSource);

        const gcmKey = randomSource.slice(0, 16);
        const iv = randomSource.slice(16);

        const subtleKey = await subtleCrypto.importKey('raw', gcmKey, { name: 'AES-GCM' }, false, [
            'decrypt',
            'encrypt'
        ]);
        const payload = new TextEncoder().encode(plaintext);

        const ciphertextWithAuth = await subtleCrypto.encrypt(
            { name: 'AES-GCM', iv, tagLength: 128 },
            subtleKey,
            payload.buffer
        );

        const ciphertext = ciphertextWithAuth.slice(0, ciphertextWithAuth.byteLength - 16);
        const authTag = ciphertextWithAuth.slice(ciphertextWithAuth.byteLength - 16);

        return {
            // authTag is ArrayBuffer (from ArrayBuffer.slice), not TypedArray — pass directly, no .buffer
            header: await this.createHeader(isMUC, gcmKey.buffer, authTag, iv.buffer, recipients),
            payload: OmemoUtils.arrayBufferToBase64String(ciphertext)
        };
    }

    async createHeader(
        isMUC: boolean,
        key: ArrayBuffer,
        auth: ArrayBuffer,
        iv: ArrayBuffer,
        recipients: any[]
    ): Promise<any> {
        const uniqueRecipients = new Set(
            recipients.map(jid => (typeof jid === 'string' ? jid : JID.toBare(jid)))
        );

        const encryptedKeys: any[] = [];
        const payload = new ArrayBuffer(key.byteLength + auth.byteLength);
        const payloadArr = new Uint8Array(payload);
        payloadArr.set(new Uint8Array(key));
        payloadArr.set(new Uint8Array(auth), key.byteLength);

        for (const recipient of uniqueRecipients) {
            const recipientSessions = await this.getRecipientSessions(isMUC, recipient);
            for (const recipientSession of recipientSessions) {
                const { type, body } = await recipientSession.encrypt(payload);
                const keyObj: any = {
                    rid: await recipientSession.getRemoteRegistrationId(),
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
            sid: await this.store.getLocalRegistrationId()
        };
    }
}
