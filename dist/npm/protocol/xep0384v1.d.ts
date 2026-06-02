import { DefinitionOptions } from '../jxt';
import { NS_OMEMO_1_BUNDLES, NS_OMEMO_1_DEVICES } from '../Namespaces';
declare module './' {
    interface Message {
        encrypted?: OMEMO1Encrypted;
        encryption?: OMEMO1Encryption;
    }
}
export interface OMEMO1Encrypted {
    payload?: string;
    header?: OMEMO1Header;
}
export interface OMEMO1Header {
    sid?: string;
    iv?: string;
    keys?: OMEMO1Key[];
}
export interface OMEMO1Key {
    rid?: string;
    prekey?: boolean;
    content?: string;
}
export interface OMEMO1PreKeyPublic {
    id?: string;
    content?: string;
}
export interface OMEMO1SignedPreKeyPublic {
    id?: string;
    content?: string;
}
export interface OMEMO1Bundle {
    itemType?: typeof NS_OMEMO_1_BUNDLES;
    signedPreKeySignature?: string;
    identityKey?: string;
    signedPreKeyPublic?: OMEMO1SignedPreKeyPublic;
    preKeys?: OMEMO1PreKeyPublic[];
}
export interface OMEMO1Device {
    id?: string;
    label?: string;
}
export interface OMEMO1DeviceList {
    itemType?: typeof NS_OMEMO_1_DEVICES;
    devices?: OMEMO1Device[];
}
export interface OMEMO1Encryption {
    name?: string;
    namespace?: string;
}
declare const Protocol: DefinitionOptions[];
export default Protocol;
