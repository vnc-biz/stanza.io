// ====================================================================
// XEP-0172: User Nickname
// --------------------------------------------------------------------
// Source: https://xmpp.org/extensions/xep-0172.html
// Version: 1.1 (2012-03-21)
// ====================================================================
import { childText, extendMessage, extendPresence, pubsubItemContentAliases, text } from '../jxt';
import { NS_NICK } from '../Namespaces';
const Protocol = [
    extendMessage({
        nick: childText(NS_NICK, 'nick')
    }),
    extendPresence({
        nick: childText(NS_NICK, 'nick')
    }),
    {
        aliases: pubsubItemContentAliases(),
        element: 'nick',
        fields: {
            nick: text()
        },
        namespace: NS_NICK,
        type: NS_NICK
    }
];
export default Protocol;
