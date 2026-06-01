// ====================================================================
// XEP-0071: XHTML-IM
// --------------------------------------------------------------------
// Source: https://xmpp.org/extensions/xep-0071.html
// Version: 1.5.4 (2018-03-08)
// ====================================================================
import { childAlternateLanguageRawElement, childLanguageRawElement } from '../jxt';
import { NS_XHTML, NS_XHTML_IM } from '../Namespaces';
const Protocol = {
    element: 'html',
    fields: {
        alternateLanguageBodies: childAlternateLanguageRawElement(NS_XHTML, 'body', 'xhtmlim'),
        body: childLanguageRawElement(NS_XHTML, 'body', 'xhtmlim')
    },
    namespace: NS_XHTML_IM,
    path: 'message.html'
};
export default Protocol;
