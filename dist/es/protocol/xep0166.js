// ====================================================================
// XEP-0166: Jingle
// --------------------------------------------------------------------
// Source: https://xmpp.org/extensions/xep-0166.html
// Version: 1.1.1 (2016-05-17)
//
// Additional:
// - Added unknown-content error
// ====================================================================
import { JingleErrorCondition, JingleReasonCondition } from '../Constants';
import { attribute, childEnum, childText, extendStanzaError, JIDAttribute } from '../jxt';
import { NS_JINGLE_1, NS_JINGLE_ERRORS_1 } from '../Namespaces';
const Protocol = [
    extendStanzaError({
        jingleError: childEnum(NS_JINGLE_ERRORS_1, Object.values(JingleErrorCondition))
    }),
    {
        element: 'jingle',
        fields: {
            action: attribute('action'),
            initiator: JIDAttribute('initiator'),
            responder: JIDAttribute('responder'),
            sid: attribute('sid')
        },
        namespace: NS_JINGLE_1,
        path: 'iq.jingle'
    },
    {
        aliases: [
            {
                multiple: true,
                path: 'iq.jingle.contents'
            }
        ],
        element: 'content',
        fields: {
            creator: attribute('creator'),
            disposition: attribute('disposition', 'session'),
            name: attribute('name'),
            senders: attribute('senders', 'both')
        },
        namespace: NS_JINGLE_1
    },
    {
        element: 'reason',
        fields: {
            alternativeSession: childText(null, 'alternative-session'),
            condition: childEnum(null, Object.values(JingleReasonCondition)),
            text: childText(null, 'text')
        },
        namespace: NS_JINGLE_1,
        path: 'iq.jingle.reason'
    }
];
export default Protocol;
