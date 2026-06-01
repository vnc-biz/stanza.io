// ====================================================================
// XEP-0131: Stanza Headers and Internet Metadata
// --------------------------------------------------------------------
// Source: https://xmpp.org/extensions/xep-0131.html
// Version: 1.2 (2006-07-12)
// ====================================================================
import { attribute, extendMessage, extendPresence, splicePath, text } from '../jxt';
import { NS_SHIM } from '../Namespaces';
const Protocol = [
    extendMessage({
        headers: splicePath(NS_SHIM, 'headers', 'header', true)
    }),
    extendPresence({
        headers: splicePath(NS_SHIM, 'headers', 'header', true)
    }),
    {
        element: 'header',
        fields: {
            name: attribute('name'),
            value: text()
        },
        namespace: NS_SHIM,
        path: 'header'
    }
];
export default Protocol;
