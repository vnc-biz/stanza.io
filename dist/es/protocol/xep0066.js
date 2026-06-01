// ====================================================================
// XEP-0066: Out of Band Data
// --------------------------------------------------------------------
// Source: https://xmpp.org/extensions/xep-0066.html
// Version: 1.5 (2006-08-16)
// ====================================================================
import { childText } from '../jxt';
import { NS_OOB, NS_OOB_TRANSFER } from '../Namespaces';
const Protocol = [
    {
        aliases: [{ multiple: true, path: 'message.links' }],
        element: 'x',
        fields: {
            description: childText(null, 'desc'),
            url: childText(null, 'url')
        },
        namespace: NS_OOB
    },
    {
        element: 'query',
        fields: {
            description: childText(null, 'desc'),
            url: childText(null, 'url')
        },
        namespace: NS_OOB_TRANSFER,
        path: 'iq.transferLink'
    }
];
export default Protocol;
