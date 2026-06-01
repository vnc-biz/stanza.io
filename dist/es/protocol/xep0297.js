// ====================================================================
// XEP-0297: Stanza Forwarding
// --------------------------------------------------------------------
// Source: https://xmpp.org/extensions/xep-0297.html
// Version: 1.0 (2013-10-02)
// ====================================================================
import { addAlias } from '../jxt';
import { StreamType } from '../Constants';
import { NS_DELAY, NS_FORWARD_0 } from '../Namespaces';
const Protocol = [
    ...Object.values(StreamType).map(streamNS => addAlias(streamNS, 'message', ['forward.message'])),
    ...Object.values(StreamType).map(streamNS => addAlias(streamNS, 'presence', ['forward.presence'])),
    ...Object.values(StreamType).map(streamNS => addAlias(streamNS, 'iq', ['forward.iq'])),
    addAlias(NS_DELAY, 'delay', ['forward.delay']),
    {
        aliases: ['message.forward'],
        element: 'forwarded',
        namespace: NS_FORWARD_0,
        path: 'forward'
    }
];
export default Protocol;
