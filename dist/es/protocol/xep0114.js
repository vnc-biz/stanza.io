// ====================================================================
// XEP-0114: Jabber Component Protocol
// --------------------------------------------------------------------
// Source: https://xmpp.org/extensions/xep-0114.html
// Version: 1.6 (2012-01-25)
// ====================================================================
import { textBuffer } from '../jxt';
import { NS_COMPONENT } from '../Namespaces';
const Protocol = {
    element: 'handshake',
    fields: {
        value: textBuffer('hex')
    },
    namespace: NS_COMPONENT,
    path: 'handshake'
};
export default Protocol;
