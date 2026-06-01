// ====================================================================
// XEP-0343: Signaling WebRTC datachannels in Jingle
// --------------------------------------------------------------------
// Source: https://xmpp.org/extensions/xep-0343.html
// Version: 0.3 (2017-09-11)
// ====================================================================
import { attribute, integerAttribute } from '../jxt';
import { NS_JINGLE_DTLS_SCTP_1, NS_JINGLE_ICE_0, NS_JINGLE_ICE_UDP_1 } from '../Namespaces';
const Protocol = {
    aliases: [
        {
            path: 'iq.jingle.contents.transport.sctp',
            selector: NS_JINGLE_ICE_UDP_1
        },
        {
            path: 'iq.jingle.contents.transport.sctp',
            selector: NS_JINGLE_ICE_0
        }
    ],
    element: 'sctpmap',
    fields: {
        port: integerAttribute('number'),
        protocol: attribute('protocol'),
        streams: attribute('streams')
    },
    namespace: NS_JINGLE_DTLS_SCTP_1
};
export default Protocol;
