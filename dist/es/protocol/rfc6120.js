// ====================================================================
// RFC 6120: Extensible Messaging and Presence Protocol (XMPP): Core
// --------------------------------------------------------------------
// Source: https://tools.ietf.org/html/rfc6120
// ====================================================================
import { SASLFailureCondition, StanzaErrorCondition, StreamErrorCondition, StreamType } from '../Constants';
import { attribute, childAlternateLanguageText, childBoolean, childEnum, childText, JIDAttribute, languageAttribute, multipleChildText, textBuffer } from '../jxt';
import { NS_BIND, NS_CLIENT, NS_SASL, NS_STANZAS, NS_STARTTLS, NS_STREAM, NS_STREAMS } from '../Namespaces';
const _Stream = {
    defaultType: 'stream',
    element: 'stream',
    fields: {
        from: attribute('from'),
        id: attribute('id'),
        lang: languageAttribute(),
        to: attribute('to'),
        version: attribute('version')
    },
    namespace: NS_STREAM,
    path: 'stream',
    type: 'stream',
    typeField: 'action'
};
const _StreamFeatures = {
    element: 'features',
    namespace: NS_STREAM,
    path: 'features'
};
const _StreamError = {
    element: 'error',
    fields: {
        alternateLanguageText: childAlternateLanguageText(NS_STREAMS, 'text'),
        condition: childEnum(NS_STREAMS, Object.values(StreamErrorCondition), StreamErrorCondition.UndefinedCondition),
        seeOtherHost: childText(NS_STREAMS, StreamErrorCondition.SeeOtherHost),
        text: childText(NS_STREAMS, 'text')
    },
    namespace: NS_STREAM,
    path: 'streamError'
};
// --------------------------------------------------------------------
const _StanzaError = Object.values(StreamType).map(streamNS => ({
    aliases: ['stanzaError', 'message.error', 'presence.error', 'iq.error'],
    defaultType: NS_CLIENT,
    element: 'error',
    fields: {
        alternateLanguageText: childAlternateLanguageText(NS_STANZAS, 'text'),
        by: JIDAttribute('by'),
        condition: childEnum(NS_STANZAS, Object.values(StanzaErrorCondition), StanzaErrorCondition.UndefinedCondition),
        gone: childText(NS_STANZAS, StanzaErrorCondition.Gone),
        redirect: childText(NS_STANZAS, StanzaErrorCondition.Redirect),
        text: childText(NS_STANZAS, 'text'),
        type: attribute('type')
    },
    namespace: streamNS,
    type: streamNS,
    typeField: 'streamType'
}));
// --------------------------------------------------------------------
const baseIQFields = new Set([
    'from',
    'id',
    'lang',
    'to',
    'type',
    'payloadType',
    'error',
    'streamType'
]);
const _IQ = Object.values(StreamType).map((streamNS) => ({
    childrenExportOrder: {
        error: 200000
    },
    defaultType: NS_CLIENT,
    element: 'iq',
    fields: {
        from: JIDAttribute('from'),
        id: attribute('id'),
        lang: languageAttribute(),
        payloadType: {
            order: -10000,
            importer(xml, context) {
                if (context.data.type !== 'get' &&
                    context.data.type !== 'set') {
                    return;
                }
                const childCount = xml.children.filter(child => typeof child !== 'string')
                    .length;
                if (childCount !== 1) {
                    return 'invalid-payload-count';
                }
                const extensions = Object.keys(context.data).filter(key => !baseIQFields.has(key));
                if (extensions.length !== 1) {
                    return 'unknown-payload';
                }
                return extensions[0];
            }
        },
        to: JIDAttribute('to'),
        type: attribute('type')
    },
    namespace: streamNS,
    path: 'iq',
    type: streamNS,
    typeField: 'streamType'
}));
// --------------------------------------------------------------------
const _Message = Object.values(StreamType).map(streamNS => ({
    childrenExportOrder: {
        error: 200000
    },
    defaultType: NS_CLIENT,
    element: 'message',
    fields: {
        from: JIDAttribute('from'),
        id: attribute('id'),
        lang: languageAttribute(),
        to: JIDAttribute('to')
    },
    namespace: streamNS,
    path: 'message',
    type: streamNS,
    typeField: 'streamType'
}));
// --------------------------------------------------------------------
const _Presence = Object.values(StreamType).map(streamNS => ({
    childrenExportOrder: {
        error: 200000
    },
    defaultType: NS_CLIENT,
    element: 'presence',
    fields: {
        from: JIDAttribute('from'),
        id: attribute('id'),
        lang: languageAttribute(),
        to: JIDAttribute('to')
    },
    namespace: streamNS,
    path: 'presence',
    type: streamNS,
    typeField: 'streamType'
}));
// --------------------------------------------------------------------
const _SASL = [
    {
        element: 'mechanisms',
        fields: {
            mechanisms: multipleChildText(null, 'mechanism')
        },
        namespace: NS_SASL,
        path: 'features.sasl'
    },
    {
        element: 'abort',
        namespace: NS_SASL,
        path: 'sasl',
        type: 'abort',
        typeField: 'type'
    },
    {
        element: 'auth',
        fields: {
            mechanism: attribute('mechanism'),
            value: textBuffer('base64')
        },
        namespace: NS_SASL,
        path: 'sasl',
        type: 'auth',
        typeField: 'type'
    },
    {
        element: 'challenge',
        fields: {
            value: textBuffer('base64')
        },
        namespace: NS_SASL,
        path: 'sasl',
        type: 'challenge',
        typeField: 'type'
    },
    {
        element: 'response',
        fields: {
            value: textBuffer('base64')
        },
        namespace: NS_SASL,
        path: 'sasl',
        type: 'response',
        typeField: 'type'
    },
    {
        element: 'success',
        fields: {
            value: textBuffer('base64')
        },
        namespace: NS_SASL,
        path: 'sasl',
        type: 'success',
        typeField: 'type'
    },
    {
        element: 'failure',
        fields: {
            alternateLanguageText: childAlternateLanguageText(NS_SASL, 'text'),
            condition: childEnum(NS_SASL, Object.values(SASLFailureCondition)),
            text: childText(NS_SASL, 'text')
        },
        namespace: NS_SASL,
        path: 'sasl',
        type: 'failure',
        typeField: 'type'
    }
];
// --------------------------------------------------------------------
const _STARTTLS = [
    {
        aliases: ['features.tls'],
        defaultType: 'start',
        element: 'starttls',
        fields: {
            required: childBoolean(null, 'required')
        },
        namespace: NS_STARTTLS,
        path: 'tls',
        type: 'start',
        typeField: 'type'
    },
    {
        element: 'proceed',
        namespace: NS_STARTTLS,
        path: 'tls',
        type: 'proceed',
        typeField: 'type'
    },
    {
        element: 'failure',
        namespace: NS_STARTTLS,
        path: 'tls',
        type: 'failure',
        typeField: 'type'
    }
];
// --------------------------------------------------------------------
const _Bind = {
    aliases: ['features.bind', 'iq.bind'],
    element: 'bind',
    fields: {
        jid: childText(null, 'jid'),
        resource: childText(null, 'resource')
    },
    namespace: NS_BIND
};
// --------------------------------------------------------------------
const Protocol = [
    _Stream,
    _StreamFeatures,
    _StreamError,
    ..._StanzaError,
    ..._SASL,
    ..._STARTTLS,
    ..._IQ,
    ..._Message,
    ..._Presence,
    _Bind
];
export default Protocol;
