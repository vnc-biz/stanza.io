// ====================================================================
// XEP-0221: Data Forms Media Element
// --------------------------------------------------------------------
// Source: https://xmpp.org/extensions/xep-0221.html
// Version: 1.0 (2008-09-03)
// ====================================================================
import { attribute, integerAttribute, text } from '../jxt';
import { NS_DATAFORM_MEDIA } from '../Namespaces';
const Protocol = [
    {
        element: 'media',
        fields: {
            height: integerAttribute('height'),
            width: integerAttribute('width')
        },
        namespace: NS_DATAFORM_MEDIA,
        path: 'dataform.fields.media'
    },
    {
        aliases: [{ multiple: true, path: 'dataform.fields.media.sources' }],
        element: 'uri',
        fields: {
            mediaType: attribute('type'),
            uri: text()
        },
        namespace: NS_DATAFORM_MEDIA
    }
];
export default Protocol;
