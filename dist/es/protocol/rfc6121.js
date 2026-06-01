// ====================================================================
// RFC 6121: Extensible Messaging and Presence Protocol (XMPP):
//      Instant Messaging and Presence
// --------------------------------------------------------------------
// Source: https://tools.ietf.org/html/rfc6121
// ====================================================================
import { attribute, booleanAttribute, childAlternateLanguageText, childAttribute, childBoolean, childInteger, childText, extendMessage, extendPresence, extendStreamFeatures, JIDAttribute, multipleChildText } from '../jxt';
import { NS_ROSTER, NS_ROSTER_VERSIONING, NS_SUBSCRIPTION_PREAPPROVAL } from '../Namespaces';
const Protocol = [
    extendStreamFeatures({
        rosterPreApproval: childBoolean(NS_SUBSCRIPTION_PREAPPROVAL, 'sub'),
        rosterVersioning: childBoolean(NS_ROSTER_VERSIONING, 'ver')
    }),
    extendMessage({
        alternateLanguageBodies: childAlternateLanguageText(null, 'body'),
        alternateLanguageSubjects: childAlternateLanguageText(null, 'subject'),
        body: childText(null, 'body'),
        hasSubject: childBoolean(null, 'subject'),
        parentThread: childAttribute(null, 'thread', 'parent'),
        subject: childText(null, 'subject'),
        thread: childText(null, 'thread'),
        type: attribute('type')
    }),
    extendPresence({
        alternateLanguageStatuses: childAlternateLanguageText(null, 'status'),
        priority: childInteger(null, 'priority', 0),
        show: childText(null, 'show'),
        status: childText(null, 'status'),
        type: attribute('type')
    }),
    {
        element: 'query',
        fields: {
            version: attribute('ver', undefined, { emitEmpty: true })
        },
        namespace: NS_ROSTER,
        path: 'iq.roster'
    },
    {
        aliases: [{ path: 'iq.roster.items', multiple: true }],
        element: 'item',
        fields: {
            groups: multipleChildText(null, 'group'),
            jid: JIDAttribute('jid'),
            name: attribute('name'),
            pending: attribute('ask'),
            preApproved: booleanAttribute('approved'),
            subscription: attribute('subscription')
        },
        namespace: NS_ROSTER
    }
];
export default Protocol;
