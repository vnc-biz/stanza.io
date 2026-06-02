"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
const jxt_1 = require("../jxt");
const Namespaces_1 = require("../Namespaces");
const Protocol = [
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
    // <header sid="..."> inside <encrypted>
    {
        element: 'header',
        fields: {
            iv: (0, jxt_1.childText)(Namespaces_1.NS_OMEMO_1, 'iv'),
            sid: (0, jxt_1.attribute)('sid')
        },
        namespace: Namespaces_1.NS_OMEMO_1,
        path: 'encrypted.header'
    },
    // <key rid="..." prekey="...">base64</key> inside <header>
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
    // <devices xmlns='urn:xmpp:omemo:1'> as pubsub item content
    {
        aliases: (0, jxt_1.pubsubItemContentAliases)(),
        element: 'devices',
        fields: {
            devices: (0, jxt_1.splicePath)(Namespaces_1.NS_OMEMO_1, 'device', 'omemo1Device', true)
        },
        namespace: Namespaces_1.NS_OMEMO_1,
        path: 'deviceList',
        type: Namespaces_1.NS_OMEMO_1_DEVICES,
        typeField: 'itemType'
    },
    // <device id="..." label="..."> inside <devices>
    {
        element: 'device',
        fields: {
            id: (0, jxt_1.attribute)('id'),
            label: (0, jxt_1.attribute)('label')
        },
        namespace: Namespaces_1.NS_OMEMO_1,
        path: 'omemo1Device'
    },
    // <pk id="...">base64</pk> inside <prekeys>
    {
        element: 'pk',
        fields: {
            content: (0, jxt_1.text)(),
            id: (0, jxt_1.attribute)('id')
        },
        namespace: Namespaces_1.NS_OMEMO_1,
        path: 'omemo1PreKey'
    },
    // <spk id="...">base64</spk> inside <bundle>
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
    },
    // <encryption xmlns='urn:xmpp:eme:0' name="OMEMO" namespace="urn:xmpp:omemo:1">
    {
        aliases: ['message.encryption'],
        element: 'encryption',
        fields: {
            name: (0, jxt_1.attribute)('name'),
            namespace: (0, jxt_1.attribute)('namespace')
        },
        namespace: Namespaces_1.NS_EME_0,
        path: 'encryption'
    }
];
exports.default = Protocol;
