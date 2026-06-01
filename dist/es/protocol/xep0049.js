// ====================================================================
// XEP-0049: Private XML Storage
// --------------------------------------------------------------------
// Source: https://xmpp.org/extensions/xep-0049.html
// Version: 1.2 (2004-03-01)
// ====================================================================
import { NS_PRIVATE } from '../Namespaces';
// tslint:enable
const Protocol = {
    element: 'query',
    namespace: NS_PRIVATE,
    path: 'iq.privateStorage'
};
export default Protocol;
