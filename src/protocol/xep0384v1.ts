// ====================================================================
// XEP-0384: OMEMO Encryption (v1 — urn:xmpp:omemo:1)
// --------------------------------------------------------------------
// Source: https://xmpp.org/extensions/xep-0384.html
// Version: 0.8.3+ (urn:xmpp:omemo:1 namespace)
//
// This file provides stanza definitions for the newer OMEMO namespace
// used by the VNC OMEMO plugin (src/plugins/omemo.ts).
// The older eu.siacs.conversations.axolotl namespace is in xep0384.ts.
// ====================================================================

import {
    attribute,
    booleanAttribute,
    childText,
    DefinitionOptions,
    multipleChildAttribute,
    pubsubItemContentAliases,
    splicePath,
    text
} from '../jxt';
import { NS_EME_0, NS_OMEMO_1, NS_OMEMO_1_BUNDLES, NS_OMEMO_1_DEVICES } from '../Namespaces';

declare module './' {
    export interface Message {
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

const Protocol: DefinitionOptions[] = [
    // <encrypted xmlns='urn:xmpp:omemo:1'> on message stanzas
    {
        aliases: ['message.encrypted'],
        element: 'encrypted',
        fields: {
            payload: childText(NS_OMEMO_1, 'payload')
        },
        namespace: NS_OMEMO_1,
        path: 'encrypted'
    },
    // <header sid="..."> inside <encrypted>
    {
        element: 'header',
        fields: {
            iv: childText(NS_OMEMO_1, 'iv'),
            sid: attribute('sid')
        },
        namespace: NS_OMEMO_1,
        path: 'encrypted.header'
    },
    // <key rid="..." prekey="...">base64</key> inside <header>
    {
        aliases: [{ path: 'encrypted.header.keys', multiple: true }],
        element: 'key',
        fields: {
            content: text(),
            prekey: booleanAttribute('prekey'),
            rid: attribute('rid')
        },
        namespace: NS_OMEMO_1
    },
    // <devices xmlns='urn:xmpp:omemo:1'> as pubsub item content
    {
        aliases: pubsubItemContentAliases(),
        element: 'devices',
        fields: {
            devices: splicePath(NS_OMEMO_1, 'device', 'omemo1Device', true)
        },
        namespace: NS_OMEMO_1,
        path: 'deviceList',
        type: NS_OMEMO_1_DEVICES,
        typeField: 'itemType'
    },
    // <device id="..." label="..."> inside <devices>
    {
        element: 'device',
        fields: {
            id: attribute('id'),
            label: attribute('label')
        },
        namespace: NS_OMEMO_1,
        path: 'omemo1Device'
    },
    // <pk id="...">base64</pk> inside <prekeys>
    {
        element: 'pk',
        fields: {
            content: text(),
            id: attribute('id')
        },
        namespace: NS_OMEMO_1,
        path: 'omemo1PreKey'
    },
    // <spk id="...">base64</spk> inside <bundle>
    {
        element: 'spk',
        fields: {
            content: text(),
            id: attribute('id')
        },
        namespace: NS_OMEMO_1,
        path: 'omemo1Bundle.signedPreKeyPublic'
    },
    // <bundle xmlns='urn:xmpp:omemo:1'> as pubsub item content
    {
        aliases: pubsubItemContentAliases(),
        element: 'bundle',
        fields: {
            identityKey: childText(NS_OMEMO_1, 'ik'),
            preKeys: splicePath(NS_OMEMO_1, 'prekeys', 'omemo1PreKey', true),
            signedPreKeySignature: childText(NS_OMEMO_1, 'spks')
        },
        namespace: NS_OMEMO_1,
        path: 'omemo1Bundle',
        type: NS_OMEMO_1_BUNDLES,
        typeField: 'itemType'
    },
    // <encryption xmlns='urn:xmpp:eme:0' name="OMEMO" namespace="urn:xmpp:omemo:1">
    {
        aliases: ['message.encryption'],
        element: 'encryption',
        fields: {
            name: attribute('name'),
            namespace: attribute('namespace')
        },
        namespace: NS_EME_0,
        path: 'encryption'
    }
];

export default Protocol;
