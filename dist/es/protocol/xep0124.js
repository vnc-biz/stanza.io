// ====================================================================
// XEP-0124: Bidirectional-streams Over Synchronous HTTP (BOSH)
// --------------------------------------------------------------------
// Source: https://xmpp.org/extensions/xep-0124.html
// Version: 1.11.1 (2016-11-16)
//
// Additional:
// --------------------------------------------------------------------
// XEP-0206: XMPP over BOSH
// --------------------------------------------------------------------
// Source: https://xmpp.org/extensions/xep-0206.html
// Version: 1.4 (2014-04-09)
// ====================================================================
import { attribute, childText, integerAttribute, JIDAttribute, languageAttribute, namespacedAttribute, namespacedBooleanAttribute } from '../jxt';
import { NS_BOSH, NS_BOSH_XMPP } from '../Namespaces';
const Protocol = {
    element: 'body',
    fields: {
        acceptMediaTypes: attribute('accept'),
        ack: integerAttribute('ack'),
        authId: attribute('authid'),
        characterSets: attribute('charsets'),
        condition: attribute('condition'),
        from: JIDAttribute('from'),
        key: attribute('key'),
        lang: languageAttribute(),
        maxClientRequests: integerAttribute('requests'),
        maxHoldOpen: integerAttribute('hold'),
        maxInactivityTime: integerAttribute('inactivity'),
        maxSessionPause: integerAttribute('maxpause'),
        maxWaitTime: integerAttribute('wait'),
        mediaType: attribute('content'),
        minPollingInterval: integerAttribute('polling'),
        newKey: attribute('newkey'),
        pauseSession: integerAttribute('pause'),
        report: integerAttribute('report'),
        rid: integerAttribute('rid'),
        route: attribute('string'),
        seeOtherURI: childText(null, 'uri'),
        sid: attribute('sid'),
        stream: attribute('stream'),
        time: integerAttribute('time'),
        to: JIDAttribute('to'),
        type: attribute('type'),
        version: attribute('ver'),
        // XEP-0206
        xmppRestart: namespacedBooleanAttribute('xmpp', NS_BOSH_XMPP, 'restart', undefined, {
            writeValue: (value) => {
                return value ? 'true' : 'false';
            }
        }),
        xmppRestartLogic: namespacedBooleanAttribute('xmpp', NS_BOSH_XMPP, 'restartlogic', undefined, {
            writeValue: (value) => {
                return value ? 'true' : 'false';
            }
        }),
        xmppVersion: namespacedAttribute('xmpp', NS_BOSH_XMPP, 'version')
    },
    namespace: NS_BOSH,
    path: 'bosh'
};
export default Protocol;
