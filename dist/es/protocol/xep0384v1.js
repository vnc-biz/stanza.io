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
import { attribute, booleanAttribute, childText, pubsubItemContentAliases, splicePath, text } from '../jxt';
import { NS_OMEMO_1, NS_OMEMO_1_BUNDLES, NS_OMEMO_1_DEVICES } from '../Namespaces';
const Protocol = [
    // <key rid="..." prekey="...">base64</key> — must be defined before header
    {
        element: 'key',
        fields: {
            content: text(),
            prekey: booleanAttribute('prekey'),
            rid: attribute('rid')
        },
        namespace: NS_OMEMO_1,
        path: 'omemo1Key'
    },
    // <header sid="..."><iv>...</iv><key ...>...</key></header>
    {
        element: 'header',
        fields: {
            iv: childText(NS_OMEMO_1, 'iv'),
            keys: splicePath(NS_OMEMO_1, 'key', 'omemo1Key', true),
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
