// ====================================================================
// XEP-0048: Bookmarks
// --------------------------------------------------------------------
// Source: https://xmpp.org/extensions/xep-0048.html
// Version: 1.1 (2007-11-07)
// ====================================================================
import { attribute, booleanAttribute, childText, JIDAttribute, pubsubItemContentAliases } from '../jxt';
import { NS_BOOKMARKS } from '../Namespaces';
const Protocol = [
    {
        aliases: [
            { path: 'bookmarkStorage', impliedType: true },
            { path: 'iq.privateStorage.bookmarks', impliedType: true },
            ...pubsubItemContentAliases()
        ],
        element: 'storage',
        namespace: NS_BOOKMARKS,
        type: NS_BOOKMARKS,
        typeField: 'itemType'
    },
    {
        aliases: [{ path: 'bookmarkStorage.rooms', multiple: true }],
        element: 'conference',
        fields: {
            autoJoin: booleanAttribute('autojoin'),
            jid: JIDAttribute('jid'),
            name: attribute('name'),
            nick: childText(null, 'nick'),
            password: childText(null, 'password')
        },
        namespace: NS_BOOKMARKS
    }
];
export default Protocol;
