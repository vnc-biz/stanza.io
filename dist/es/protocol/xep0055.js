// ====================================================================
// XEP-0055: Jabber Search
// --------------------------------------------------------------------
// Source: https://xmpp.org/extensions/xep-0055.html
// Version: 1.3 (2009-09-15)
// ====================================================================
import { addAlias, childText, JIDAttribute } from '../jxt';
import { NS_DATAFORM, NS_RSM, NS_SEARCH } from '../Namespaces';
const Protocol = [
    addAlias(NS_DATAFORM, 'x', ['iq.search.form']),
    addAlias(NS_RSM, 'set', ['iq.search.paging']),
    {
        element: 'query',
        fields: {
            email: childText(null, 'email'),
            familyName: childText(null, 'last'),
            givenName: childText(null, 'first'),
            instructions: childText(null, 'instructions'),
            nick: childText(null, 'nick')
        },
        namespace: NS_SEARCH,
        path: 'iq.search'
    },
    {
        aliases: [{ path: 'iq.search.items', multiple: true }],
        element: 'item',
        fields: {
            email: childText(null, 'email'),
            familyName: childText(null, 'last'),
            givenName: childText(null, 'first'),
            jid: JIDAttribute('jid'),
            nick: childText(null, 'nick')
        },
        namespace: NS_SEARCH
    }
];
export default Protocol;
