// ====================================================================
// XEP-0335: JSON Containers
// --------------------------------------------------------------------
// Source: https://xmpp.org/extensions/xep-0335.html
// Version: 0.1 (2013-10-25)
//
// --------------------------------------------------------------------
// XEP-0432: Simple JSON Messaging
// --------------------------------------------------------------------
// Source: https://xmpp.org/extensions/xep-0432.html
// Version: 0.1.0 (2020-02-25)
// ====================================================================
import { childJSON, extendMessage, pubsubItemContentAliases, textJSON, attribute } from '../jxt';
import { NS_JSON_0, NS_JSON_MESSAGE_0 } from '../Namespaces';
const Protocol = [
    extendMessage({
        json: childJSON(NS_JSON_0, 'json')
    }),
    {
        aliases: pubsubItemContentAliases(),
        element: 'json',
        fields: {
            json: textJSON()
        },
        namespace: NS_JSON_0,
        type: NS_JSON_0
    },
    {
        aliases: [{ path: 'message.jsonPayloads', multiple: true }],
        element: 'payload',
        fields: {
            type: attribute('datatype'),
            data: childJSON(NS_JSON_0, 'json')
        },
        namespace: NS_JSON_MESSAGE_0
    }
];
export default Protocol;
