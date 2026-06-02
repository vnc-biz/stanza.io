// ====================================================================
// XEP-0384: OMEMO Encryption (v1 — urn:xmpp:omemo:1)
// --------------------------------------------------------------------
// Source: https://xmpp.org/extensions/xep-0384.html
// Version: 0.8.3+ (urn:xmpp:omemo:1 namespace)
//
// Provides stanza definitions for the newer OMEMO namespace used by
// the VNC OMEMO plugin (src/plugins/omemo.ts).
// The older eu.siacs.conversations.axolotl namespace is in xep0384.ts.
// The <encryption xmlns='urn:xmpp:eme:0'> element is in xep0380.ts
// (mapped to message.encryptionMethod).
// ====================================================================

import {
    attribute,
    booleanAttribute,
    childText,
    createElement,
    DefinitionOptions,
    FieldDefinition,
    pubsubItemContentAliases,
    splicePath,
    text
} from '../jxt';
import { NS_OMEMO_1, NS_OMEMO_1_BUNDLES, NS_OMEMO_1_DEVICES } from '../Namespaces';

/**
 * Custom field for OMEMO v1 device list.
 * Handles both integer[] and OmemoDeviceInfo[] on export (the OMEMO plugin passes objects).
 * Returns integer[] on import (processDevices() converts to {id,label} objects).
 */
function omemoDeviceList(namespace: string): FieldDefinition<any[]> {
    return {
        importer(xml: any) {
            const result: any[] = [];
            const children = xml.getChildren('device', namespace || xml.getNamespace());
            for (const child of children) {
                const id = child.getAttribute('id');
                if (id !== undefined) {
                    // Return OmemoDeviceInfo objects so processDevices() works correctly
                    const label = child.getAttribute('label');
                    result.push({ id: parseInt(id, 10), ...(label ? { label } : {}) });
                }
            }
            return result;
        },
        exporter(xml: any, values: any, context: any) {
            if (!Array.isArray(values)) return;
            for (const value of values) {
                const id = typeof value === 'object' && value !== null ? value.id : value;
                if (id === undefined || id === null) continue;
                const child = createElement(namespace || xml.getNamespace(), 'device', context.namespace, xml);
                child.setAttribute('id', id.toString());
                const label = typeof value === 'object' && value?.label;
                if (label) child.setAttribute('label', label);
                xml.appendChild(child);
            }
        }
    };
}

declare module './' {
    export interface Message {
        encrypted?: OMEMO1Encrypted;
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

const Protocol: DefinitionOptions[] = [
    // <key rid="..." prekey="...">base64</key> — direct children of <header>
    // Use aliases (like xep0384.ts axolotl format) NOT splicePath.
    // splicePath expects a wrapper element; OMEMO keys are flat direct children.
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
    // <header sid="..."><iv>...</iv><key ...>...</key></header>
    // Note: keys field is NOT here — populated via the alias above
    {
        element: 'header',
        fields: {
            iv: childText(NS_OMEMO_1, 'iv'),
            sid: attribute('sid')
        },
        namespace: NS_OMEMO_1,
        path: 'encrypted.header'
    },
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
    // <devices xmlns='urn:xmpp:omemo:1'> as pubsub item content
    // Custom device list field — handles both integer[] and OmemoDeviceInfo[] on export
    {
        aliases: pubsubItemContentAliases(),
        element: 'devices',
        fields: {
            devices: omemoDeviceList(NS_OMEMO_1)
        },
        namespace: NS_OMEMO_1,
        path: 'deviceList',
        type: NS_OMEMO_1_DEVICES,
        typeField: 'itemType'
    },
    // <pk id="...">base64</pk> prekey public
    {
        element: 'pk',
        fields: {
            content: text(),
            id: attribute('id')
        },
        namespace: NS_OMEMO_1,
        path: 'omemo1PreKey'
    },
    // <spk id="...">base64</spk> signed prekey public inside <bundle>
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
    }
];

export default Protocol;
