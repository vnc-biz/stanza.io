import { Agent } from '../';
declare module '../' {
    interface Agent {
        omemo?: OmemoClient;
        createOmemo(store: OmemoStorage): void;
        publishOmemoDevice(jid: string, node: string, item: any): Promise<any>;
        publishOmemoBundle(jid: string, node: string, item: any): Promise<any>;
        getOmemoItems(jid: string, node: string, opts?: any): Promise<any>;
    }
}
export default function (client: Agent): void;
export declare class OmemoStorage {
    static Direction: {
        SENDING: number;
        RECEIVING: number;
    };
    Direction: {
        SENDING: number;
        RECEIVING: number;
    };
    storeDevices(_jid: string, _devices: OmemoDeviceInfo[]): Promise<void>;
    getDevices(_jid: string): Promise<OmemoDeviceInfo[]>;
    hasDevices(_jid: string): Promise<boolean>;
    storeWhisper(_address: string, _id: string, _whisper: ArrayBuffer): Promise<void>;
    getWhisper(_address: string, _id: string): Promise<ArrayBuffer | null>;
    getLocalRegistrationId(): Promise<number>;
    storeLocalRegistration(_device: OmemoDeviceInfo): Promise<void>;
    getIdentityKeyPair(): Promise<{
        pubKey: ArrayBuffer;
        privKey: ArrayBuffer;
    } | null>;
    storeIdentityKeyPair(_keyPair: {
        pubKey: ArrayBuffer;
        privKey: ArrayBuffer;
    }): Promise<void>;
    isTrustedIdentity(_identity: string, _identityKey: ArrayBuffer, _direction: number): Promise<boolean>;
    loadIdentityKey(_identity: string): Promise<ArrayBuffer | null>;
    saveIdentity(_identity: string, _identityKey: ArrayBuffer): Promise<boolean>;
    loadPreKey(_keyId: number): Promise<{
        pubKey: ArrayBuffer;
        privKey: ArrayBuffer;
    } | null>;
    storePreKey(_keyId: number, _preKey: {
        pubKey: ArrayBuffer;
        privKey: ArrayBuffer;
    }): Promise<void>;
    removePreKey(_keyId: number): Promise<void>;
    loadSignedPreKey(_keyId: number): Promise<{
        pubKey: ArrayBuffer;
        privKey: ArrayBuffer;
    } | null>;
    storeSignedPreKey(_keyId: number, _signedPreKey: {
        pubKey: ArrayBuffer;
        privKey: ArrayBuffer;
    }): Promise<void>;
    removeSignedPreKey(_keyId: number): Promise<void>;
    loadSession(_identifier: string): Promise<string | null>;
    storeSession(_identifier: string, _session: string): Promise<void>;
    removeSession(_identifier: string): Promise<void>;
    removeAllSessions(_prefix: string): Promise<void>;
    wrapFunction(name: string, func: (orig: Function, ...args: any[]) => any): void;
}
export interface OmemoDeviceInfo {
    id: number;
    label?: string;
}
export declare class OmemoUtils {
    static arrayBufferToBase64String(arrayBuffer: ArrayBuffer): string;
    static base64StringToArrayBuffer(str: string): ArrayBuffer;
}
export declare class OmemoClient {
    private client;
    private store;
    private subscriptions;
    private actualizedOpponentDevices;
    private getAnnouncedDeviceIdsRequests;
    private getAnnouncedDeviceIdsRequests2;
    private platform?;
    constructor({ client, store }: {
        client: Agent;
        store?: OmemoStorage;
    });
    handleDeviceList(msg: any): Promise<void>;
    processDevices(devices: OmemoDeviceInfo[]): OmemoDeviceInfo[];
    storeDevices(jidBare: string, devices: OmemoDeviceInfo[]): Promise<void>;
    start(platform: string): Promise<void>;
    buildDeviceInfo(deviceId: number): OmemoDeviceInfo;
    getAnnouncedDevices(jid?: string | null, force?: boolean): Promise<OmemoDeviceInfo[]>;
    getDeviceKeyBundle(recipient: string | any, registrationId: number): Promise<any>;
    announceDevices(devices: OmemoDeviceInfo[], newRegistrationId?: number | null): Promise<void>;
    announce(device: OmemoDeviceInfo, identityKeyPair: any, isNew: boolean, removePreKey?: number | null, isForceGetAnnouncedDevices?: boolean): Promise<void>;
    refillPreKeys(keyBundle: any, removePreKey?: number | null): Promise<any>;
    getRecipientSessions(isMUC: boolean, recipient: string): Promise<any[]>;
    decryptMessage(message: any): Promise<ArrayBuffer | null>;
    decryptWhisper(message: any, key: any): Promise<ArrayBuffer>;
    decryptData(subtleCrypto: SubtleCrypto, keyData: ArrayBuffer, iv: ArrayBuffer, data: ArrayBuffer): Promise<ArrayBuffer | null>;
    sendMessage(rawMessage: any, members?: any[], encryptedMsgHint?: string): Promise<any>;
    createMessage(isMUC: boolean, plaintext: string, recipients: any[]): Promise<any>;
    createHeader(isMUC: boolean, key: ArrayBuffer, auth: ArrayBuffer, iv: ArrayBuffer, recipients: any[]): Promise<any>;
}
