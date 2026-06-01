// ====================================================================
// XEP-0357: Push Notifications
// --------------------------------------------------------------------
// Source: https://xmpp.org/extensions/xep-0357.html
// Version: 0.3 (2017-08-24)
// ====================================================================
import { addAlias, attribute, JIDAttribute, pubsubItemContentAliases } from '../jxt';
import { NS_DATAFORM, NS_PUSH_0 } from '../Namespaces';
const Protocol = [
    addAlias(NS_DATAFORM, 'x', ['iq.push.form', 'pushNotification.form']),
    {
        element: 'enable',
        fields: {
            jid: JIDAttribute('jid'),
            node: attribute('node')
        },
        namespace: NS_PUSH_0,
        path: 'iq.push',
        type: 'enable',
        typeField: 'action'
    },
    {
        element: 'disable',
        fields: {
            jid: JIDAttribute('jid'),
            node: attribute('node')
        },
        namespace: NS_PUSH_0,
        path: 'iq.push',
        type: 'disable',
        typeField: 'action'
    },
    {
        aliases: pubsubItemContentAliases(),
        element: 'notification',
        namespace: NS_PUSH_0,
        path: 'pushNotification',
        type: NS_PUSH_0,
        typeField: 'itemType'
    }
];
export default Protocol;
