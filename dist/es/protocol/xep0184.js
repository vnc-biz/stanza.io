// ====================================================================
// XEP-0184: Message Delivery Receipts
// --------------------------------------------------------------------
// Source: https://xmpp.org/extensions/xep-0184.html
// Version: 1.2 (2011-03-01)
// ====================================================================
import { attribute } from '../jxt';
import { NS_RECEIPTS } from '../Namespaces';
const Protocol = [
    {
        element: 'request',
        namespace: NS_RECEIPTS,
        path: 'message.receipt',
        type: 'request',
        typeField: 'type'
    },
    {
        element: 'received',
        fields: {
            id: attribute('id')
        },
        namespace: NS_RECEIPTS,
        path: 'message.receipt',
        type: 'received',
        typeField: 'type'
    }
];
export default Protocol;
