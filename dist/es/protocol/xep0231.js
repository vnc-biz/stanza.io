// ====================================================================
// XEP-0231: Bits of Binary
// --------------------------------------------------------------------
// Source: https://xmpp.org/extensions/xep-0231.html
// Version: Version 1.0 (2008-09-03)
// ====================================================================
import { attribute, integerAttribute, textBuffer } from '../jxt';
import { NS_BOB } from '../Namespaces';
const Protocol = {
    aliases: [
        'iq.bits',
        { path: 'message.bits', multiple: true },
        { path: 'presence.bits', multiple: true },
        { path: 'iq.jingle.bits', multiple: true }
    ],
    element: 'data',
    fields: {
        cid: attribute('cid'),
        data: textBuffer('base64'),
        maxAge: integerAttribute('max-age'),
        mediaType: attribute('type')
    },
    namespace: NS_BOB
};
export default Protocol;
