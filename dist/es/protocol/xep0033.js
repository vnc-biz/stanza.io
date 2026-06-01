// ====================================================================
// XEP-0033: Extended Stanza Addressing
// --------------------------------------------------------------------
// Source: https://xmpp.org/extensions/xep-0033.html
// Version:	1.2.1 (2017-01-11)
// --------------------------------------------------------------------
import { attribute, booleanAttribute, childAlternateLanguageText, extendMessage, extendPresence, JIDAttribute, splicePath } from '../jxt';
import { NS_ADDRESS } from '../Namespaces';
const Protocol = [
    extendMessage({
        addresses: splicePath(NS_ADDRESS, 'addresses', 'extendedAddress', true)
    }),
    extendPresence({
        addresses: splicePath(NS_ADDRESS, 'addresses', 'extendedAddress', true)
    }),
    {
        element: 'address',
        fields: {
            alternateLanguageDescriptions: childAlternateLanguageText(null, 'desc'),
            delivered: booleanAttribute('delivered'),
            description: attribute('desc'),
            jid: JIDAttribute('jid'),
            node: attribute('node'),
            type: attribute('type'),
            uri: attribute('uri')
        },
        namespace: NS_ADDRESS,
        path: 'extendedAddress'
    }
];
export default Protocol;
