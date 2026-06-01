// ====================================================================
// XEP-0108: User Tune
// --------------------------------------------------------------------
// Source: https://xmpp.org/extensions/xep-0118.html
// Version: 1.2 (2008-01-30)
// ====================================================================
import { childInteger, childText, pubsubItemContentAliases } from '../jxt';
import { NS_TUNE } from '../Namespaces';
const Protocol = {
    aliases: [
        {
            impliedType: true,
            path: 'tune'
        },
        ...pubsubItemContentAliases()
    ],
    element: 'tune',
    fields: {
        artist: childText(null, 'artist'),
        length: childInteger(null, 'length'),
        rating: childInteger(null, 'rating'),
        source: childText(null, 'source'),
        title: childText(null, 'title'),
        track: childText(null, 'track'),
        uri: childText(null, 'uri')
    },
    namespace: NS_TUNE,
    type: NS_TUNE
};
export default Protocol;
