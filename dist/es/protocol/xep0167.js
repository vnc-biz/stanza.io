// ====================================================================
// XEP-0167: Jingle RTP Sessions
// --------------------------------------------------------------------
// Source: https://xmpp.org/extensions/xep-0167.html
// Version: 1.1.1 (2016-07-08)
//
// Additional:
// - rtcpMux flag
// - rtcpReducedSize flag
// - media streams list
//
// --------------------------------------------------------------------
// XEP-0262: Use of ZRTP in Jingle RTP Sessions
// --------------------------------------------------------------------
// Source: https://xmpp.org/extensions/xep-0262.html
// Version: 1.0 (2011-06-15)
//
// --------------------------------------------------------------------
// XEP-0293: Jingle RTP Feedback Negotiation
// --------------------------------------------------------------------
// Source: https://xmpp.org/extensions/xep-0293.html
// Version: 1.0 (2015-08-11)
//
// --------------------------------------------------------------------
// XEP-0294: Jingle RTP Header Extensions Negotiation
// --------------------------------------------------------------------
// Source: https://xmpp.org/extensions/xep-0294.html
// Version: 1.0 (2015-08-11)
//
// --------------------------------------------------------------------
// XEP-0339: Source-Specific Media Attributes in Jingle
// --------------------------------------------------------------------
// Source: https://xmpp.org/extensions/xep-0339.html
// Version: 0.3 (2017-09-11)
// ====================================================================
import { JINGLE_INFO_ACTIVE, JINGLE_INFO_HOLD, JINGLE_INFO_MUTE, JINGLE_INFO_RINGING, JINGLE_INFO_UNHOLD, JINGLE_INFO_UNMUTE } from '../Constants';
import { attribute, booleanAttribute, childBoolean, createElement, findAll, integerAttribute, multipleChildAttribute, parameterMap, textBuffer } from '../jxt';
import { NS_JINGLE_RTP_1, NS_JINGLE_RTP_HDREXT_0, NS_JINGLE_RTP_INFO_1, NS_JINGLE_RTP_MSID_0, NS_JINGLE_RTP_RTCP_FB_0, NS_JINGLE_RTP_SSMA_0 } from '../Namespaces';
function rtcpFeedback() {
    return {
        importer(xml, context) {
            let existing = findAll(xml, NS_JINGLE_RTP_RTCP_FB_0, 'rtcp-fb');
            const typeImporter = attribute('type').importer;
            const subtypeImporter = attribute('subtype').importer;
            const valueImporter = attribute('value').importer;
            const result = [];
            for (const child of existing) {
                const type = typeImporter(child, context);
                const parameter = subtypeImporter(child, context);
                result.push(parameter ? { type, parameter } : { type });
            }
            existing = findAll(xml, NS_JINGLE_RTP_RTCP_FB_0, 'rtcp-fb-trr-int');
            for (const child of existing) {
                const parameter = valueImporter(child, context);
                result.push(parameter ? { type: 'trr-int', parameter } : { type: 'trr-int' });
            }
            return result;
        },
        exporter(xml, values, context) {
            const typeExporter = attribute('type').exporter;
            const subtypeExporter = attribute('subtype').exporter;
            const valueExporter = attribute('value').exporter;
            for (const fb of values) {
                let child;
                if (fb.type === 'trr-int') {
                    child = createElement(NS_JINGLE_RTP_RTCP_FB_0, 'rtcp-fb-trr-int', context.namespace, xml);
                    if (fb.parameter) {
                        valueExporter(child, fb.parameter, context);
                    }
                }
                else {
                    child = createElement(NS_JINGLE_RTP_RTCP_FB_0, 'rtcp-fb', context.namespace, xml);
                    typeExporter(child, fb.type, context);
                    if (fb.parameter) {
                        subtypeExporter(child, fb.parameter, context);
                    }
                }
                xml.appendChild(child);
            }
        }
    };
}
const info = 'iq.jingle.info';
const Protocol = [
    {
        aliases: ['iq.jingle.contents.application'],
        childrenExportOrder: {
            codecs: 4,
            encryption: 5,
            headerExtensions: 6,
            sourceGroups: 8,
            sources: 7,
            streams: 9
        },
        element: 'description',
        fields: {
            media: attribute('media'),
            rtcpFeedback: Object.assign(Object.assign({}, rtcpFeedback()), { exportOrder: 3 }),
            rtcpMux: Object.assign(Object.assign({}, childBoolean(null, 'rtcp-mux')), { exportOrder: 1 }),
            rtcpReducedSize: Object.assign(Object.assign({}, childBoolean(null, 'rtcp-reduced-size')), { exportOrder: 2 }),
            ssrc: attribute('ssrc')
        },
        namespace: NS_JINGLE_RTP_1,
        optionalNamespaces: {
            rtcpf: NS_JINGLE_RTP_RTCP_FB_0,
            rtph: NS_JINGLE_RTP_HDREXT_0
        },
        type: NS_JINGLE_RTP_1
    },
    {
        aliases: [
            {
                multiple: true,
                path: 'iq.jingle.contents.application.headerExtensions',
                selector: NS_JINGLE_RTP_1
            }
        ],
        element: 'rtp-hdrext',
        fields: {
            id: integerAttribute('id'),
            senders: attribute('senders'),
            uri: attribute('uri')
        },
        namespace: NS_JINGLE_RTP_HDREXT_0
    },
    {
        aliases: [
            {
                multiple: true,
                path: 'iq.jingle.contents.application.codecs',
                selector: NS_JINGLE_RTP_1
            },
            'rtpcodec'
        ],
        element: 'payload-type',
        fields: {
            channels: integerAttribute('channels'),
            clockRate: integerAttribute('clockrate'),
            id: attribute('id'),
            maxptime: integerAttribute('maxptime'),
            name: attribute('name'),
            parameters: parameterMap(NS_JINGLE_RTP_1, 'parameter', 'name', 'value'),
            ptime: integerAttribute('ptime'),
            rtcpFeedback: rtcpFeedback()
        },
        namespace: NS_JINGLE_RTP_1
    },
    {
        aliases: [
            {
                multiple: true,
                path: 'iq.jingle.contents.application.sources',
                selector: NS_JINGLE_RTP_1
            }
        ],
        element: 'source',
        fields: {
            parameters: parameterMap(NS_JINGLE_RTP_SSMA_0, 'parameter', 'name', 'value'),
            ssrc: attribute('ssrc')
        },
        namespace: NS_JINGLE_RTP_SSMA_0
    },
    {
        aliases: [
            {
                multiple: true,
                path: 'iq.jingle.contents.application.sourceGroups',
                selector: NS_JINGLE_RTP_1
            }
        ],
        element: 'ssrc-group',
        fields: {
            semantics: attribute('semantics'),
            sources: multipleChildAttribute(null, 'source', 'ssrc')
        },
        namespace: NS_JINGLE_RTP_SSMA_0
    },
    {
        aliases: [
            {
                multiple: true,
                path: 'iq.jingle.contents.application.streams',
                selector: NS_JINGLE_RTP_1
            }
        ],
        element: 'stream',
        fields: {
            id: attribute('id'),
            track: attribute('track')
        },
        namespace: NS_JINGLE_RTP_MSID_0
    },
    {
        aliases: [{ path: 'iq.jingle.contents.application.encryption', selector: NS_JINGLE_RTP_1 }],
        element: 'encryption',
        fields: {
            required: booleanAttribute('required')
        },
        namespace: NS_JINGLE_RTP_1
    },
    {
        aliases: [
            {
                multiple: true,
                path: 'iq.jingle.contents.application.encryption.sdes',
                selector: NS_JINGLE_RTP_1
            }
        ],
        element: 'crypto',
        fields: {
            cryptoSuite: attribute('crypto-suite'),
            keyParameters: attribute('key-params'),
            sessionParameters: attribute('session-params'),
            tag: integerAttribute('tag')
        },
        namespace: NS_JINGLE_RTP_1
    },
    {
        aliases: [
            {
                path: 'iq.jingle.contents.application.encryption.zrtp',
                selector: NS_JINGLE_RTP_1
            }
        ],
        element: 'zrtp-hash',
        fields: {
            value: textBuffer('hex'),
            version: attribute('version')
        },
        namespace: NS_JINGLE_RTP_1
    },
    {
        element: 'mute',
        fields: {
            creator: attribute('creator'),
            name: attribute('name')
        },
        namespace: NS_JINGLE_RTP_INFO_1,
        path: info,
        type: JINGLE_INFO_MUTE
    },
    {
        element: 'unmute',
        fields: {
            creator: attribute('creator'),
            name: attribute('name')
        },
        namespace: NS_JINGLE_RTP_INFO_1,
        path: info,
        type: JINGLE_INFO_UNMUTE
    },
    {
        element: 'hold',
        namespace: NS_JINGLE_RTP_INFO_1,
        path: info,
        type: JINGLE_INFO_HOLD
    },
    {
        element: 'unhold',
        namespace: NS_JINGLE_RTP_INFO_1,
        path: info,
        type: JINGLE_INFO_UNHOLD
    },
    {
        element: 'active',
        namespace: NS_JINGLE_RTP_INFO_1,
        path: info,
        type: JINGLE_INFO_ACTIVE
    },
    {
        element: 'ringing',
        namespace: NS_JINGLE_RTP_INFO_1,
        path: info,
        type: JINGLE_INFO_RINGING
    }
];
export default Protocol;
