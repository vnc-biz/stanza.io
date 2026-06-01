// ====================================================================
// XEP-0224: Attention
// --------------------------------------------------------------------
// Source: https://xmpp.org/extensions/xep-0224.html
// Version: Version 1.0 (2008-11-13)
// ====================================================================
import { addAlias, attribute, integerAttribute } from '../jxt';
import { NS_BOB, NS_THUMBS_1 } from '../Namespaces';
const Protocol = [
    addAlias(NS_BOB, 'data', [{ path: 'iq.jingle.bits', multiple: true }]),
    {
        element: 'thumbnail',
        fields: {
            height: integerAttribute('height'),
            mediaType: attribute('media-type'),
            uri: attribute('uri'),
            width: integerAttribute('width')
        },
        namespace: NS_THUMBS_1,
        path: 'thumbnail'
    }
];
export default Protocol;
