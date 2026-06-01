// ====================================================================
// XEP-0059: Result Set Management
// --------------------------------------------------------------------
// Source: https://xmpp.org/extensions/xep-0059.html
// Version: 1.0.0 (2006-09-20)
// ====================================================================
import { childInteger, childIntegerAttribute, childText } from '../jxt';
import { NS_RSM } from '../Namespaces';
const Protocol = {
    aliases: ['iq.pubsub.paging'],
    element: 'set',
    fields: {
        after: childText(null, 'after'),
        before: childText(null, 'before'),
        count: childInteger(null, 'count'),
        first: childText(null, 'first'),
        firstIndex: childIntegerAttribute(null, 'first', 'index'),
        index: childInteger(null, 'index'),
        last: childText(null, 'last'),
        max: childInteger(null, 'max')
    },
    namespace: NS_RSM,
    path: 'paging'
};
export default Protocol;
