"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
const jxt_1 = require("../jxt");
const Namespaces_1 = require("../Namespaces");
/**
 * Custom field for OMEMO v1 device list.
 * Handles both integer[] and OmemoDeviceInfo[] on export (the OMEMO plugin passes objects).
 * Returns integer[] on import (processDevices() converts to {id,label} objects).
 */
function omemoDeviceList(namespace) {
    return {
        importer(xml) {
            const result = [];
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
        exporter(xml, values, context) {
            if (!Array.isArray(values))
                return;
            for (const value of values) {
                const id = typeof value === 'object' && value !== null ? value.id : value;
                if (id === undefined || id === null)
                    continue;
                const child = (0, jxt_1.createElement)(namespace || xml.getNamespace(), 'device', context.namespace, xml);
                child.setAttribute('id', id.toString());
                const label = typeof value === 'object' && value?.label;
                if (label)
                    child.setAttribute('label', label);
                xml.appendChild(child);
            }
        }
    };
}
const Protocol = [
    // <key rid="..." prekey="...">base64</key> — direct children of <header>
    // Use aliases (like xep0384.ts axolotl format) NOT splicePath.
    // splicePath expects a wrapper element; OMEMO keys are flat direct children.
    {
        aliases: [{ path: 'encrypted.header.keys', multiple: true }],
        element: 'key',
        fields: {
            content: (0, jxt_1.text)(),
            prekey: (0, jxt_1.booleanAttribute)('prekey'),
            rid: (0, jxt_1.attribute)('rid')
        },
        namespace: Namespaces_1.NS_OMEMO_1
    },
    // <header sid="..."><iv>...</iv><key ...>...</key></header>
    // Note: keys field is NOT here — populated via the alias above
    {
        element: 'header',
        fields: {
            iv: (0, jxt_1.childText)(Namespaces_1.NS_OMEMO_1, 'iv'),
            sid: (0, jxt_1.attribute)('sid')
        },
        namespace: Namespaces_1.NS_OMEMO_1,
        path: 'encrypted.header'
    },
    // <encrypted xmlns='urn:xmpp:omemo:1'> on message stanzas
    {
        aliases: ['message.encrypted'],
        element: 'encrypted',
        fields: {
            payload: (0, jxt_1.childText)(Namespaces_1.NS_OMEMO_1, 'payload')
        },
        namespace: Namespaces_1.NS_OMEMO_1,
        path: 'encrypted'
    },
    // <devices xmlns='urn:xmpp:omemo:1'> as pubsub item content
    // Custom device list field — handles both integer[] and OmemoDeviceInfo[] on export
    {
        aliases: (0, jxt_1.pubsubItemContentAliases)(),
        element: 'devices',
        fields: {
            devices: omemoDeviceList(Namespaces_1.NS_OMEMO_1)
        },
        namespace: Namespaces_1.NS_OMEMO_1,
        path: 'deviceList',
        type: Namespaces_1.NS_OMEMO_1_DEVICES,
        typeField: 'itemType'
    },
    // <pk id="...">base64</pk> prekey public
    {
        element: 'pk',
        fields: {
            content: (0, jxt_1.text)(),
            id: (0, jxt_1.attribute)('id')
        },
        namespace: Namespaces_1.NS_OMEMO_1,
        path: 'omemo1PreKey'
    },
    // <spk id="...">base64</spk> signed prekey public inside <bundle>
    {
        element: 'spk',
        fields: {
            content: (0, jxt_1.text)(),
            id: (0, jxt_1.attribute)('id')
        },
        namespace: Namespaces_1.NS_OMEMO_1,
        path: 'omemo1Bundle.signedPreKeyPublic'
    },
    // <bundle xmlns='urn:xmpp:omemo:1'> as pubsub item content
    {
        aliases: (0, jxt_1.pubsubItemContentAliases)(),
        element: 'bundle',
        fields: {
            identityKey: (0, jxt_1.childText)(Namespaces_1.NS_OMEMO_1, 'ik'),
            preKeys: (0, jxt_1.splicePath)(Namespaces_1.NS_OMEMO_1, 'prekeys', 'omemo1PreKey', true),
            signedPreKeySignature: (0, jxt_1.childText)(Namespaces_1.NS_OMEMO_1, 'spks')
        },
        namespace: Namespaces_1.NS_OMEMO_1,
        path: 'omemo1Bundle',
        type: Namespaces_1.NS_OMEMO_1_BUNDLES,
        typeField: 'itemType'
    }
];
exports.default = Protocol;
