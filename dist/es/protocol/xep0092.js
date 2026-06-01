// ====================================================================
// XEP-0092: Software Version
// --------------------------------------------------------------------
// Source: https://xmpp.org/extensions/xep-0092.html
// Version: 1.1 (2007-02-15)
// ====================================================================
import { childText } from '../jxt';
import { NS_VERSION } from '../Namespaces';
const Protocol = {
    element: 'query',
    fields: {
        name: childText(null, 'name'),
        os: childText(null, 'os'),
        version: childText(null, 'version')
    },
    namespace: NS_VERSION,
    path: 'iq.softwareVersion'
};
export default Protocol;
