// ====================================================================
// XEP-0158: CAPTCHA Forms
// --------------------------------------------------------------------
// Source: https://xmpp.org/extensions/xep-0158.html
// Version: 1.0 (2008-09-03)
// ====================================================================
import { extendIQ, extendMessage, splicePath } from '../jxt';
import { NS_CAPTCHA } from '../Namespaces';
const Protocol = [
    extendMessage({
        captcha: splicePath(NS_CAPTCHA, 'captcha', 'dataform')
    }),
    extendIQ({
        captcha: splicePath(NS_CAPTCHA, 'captcha', 'dataform')
    })
];
export default Protocol;
