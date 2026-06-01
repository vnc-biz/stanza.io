// ====================================================================
// Extensible Resource Descriptor (XRD)
// --------------------------------------------------------------------
// Source: http://docs.oasis-open.org/xri/xrd/v1.0/xrd-1.0.html
// Version: 1.0
// ====================================================================
import { attribute, childText } from '../jxt';
import { NS_XRD } from '../Namespaces';
const Protocol = [
    {
        element: 'XRD',
        fields: {
            subject: childText(null, 'Subject')
        },
        namespace: NS_XRD,
        path: 'xrd'
    },
    {
        aliases: [{ path: 'xrd.links', multiple: true }],
        element: 'Link',
        fields: {
            href: attribute('href'),
            rel: attribute('rel'),
            type: attribute('type')
        },
        namespace: NS_XRD
    }
];
export default Protocol;
