// ====================================================================
// XEP-0380: Explicit Message Encryption
// --------------------------------------------------------------------
// Source: https://xmpp.org/extensions/xep-0380.html
// Version: 0.2.0 (2018-01-25)
// ====================================================================
import { attribute } from '../jxt';
import { NS_EME_0 } from '../Namespaces';
const Protocol = {
    element: 'encryption',
    fields: {
        id: attribute('namespace'),
        name: attribute('name')
    },
    namespace: NS_EME_0,
    path: 'message.encryptionMethod'
};
export default Protocol;
