// ====================================================================
// XEP-0203: Delayed Delivery
// --------------------------------------------------------------------
// Source: https://xmpp.org/extensions/xep-0203.html
// Version: 2.0 (2009-09-15)
// ====================================================================
import { dateAttribute, JIDAttribute, text } from '../jxt';
import { NS_DELAY } from '../Namespaces';
const Protocol = {
    aliases: ['message.delay', 'presence.delay'],
    element: 'delay',
    fields: {
        from: JIDAttribute('from'),
        reason: text(),
        timestamp: dateAttribute('stamp')
    },
    namespace: NS_DELAY
};
export default Protocol;
