// ====================================================================
// XEP-0141: Data Forms Layout
// --------------------------------------------------------------------
// Source: https://xmpp.org/extensions/xep-0141.html
// Version: 1.0 (2005-05-12)
// ====================================================================
import { attribute, text } from '../jxt';
import { NS_DATAFORM_LAYOUT } from '../Namespaces';
const aliases = [
    'dataformLayout',
    {
        multiple: true,
        path: 'dataformLayout.contents'
    },
    {
        multiple: true,
        path: 'dataform.layout.contents'
    }
];
const Protocol = [
    {
        aliases: [
            {
                multiple: true,
                path: 'dataform.layout'
            }
        ],
        element: 'page',
        fields: {
            label: attribute('label')
        },
        namespace: NS_DATAFORM_LAYOUT
    },
    {
        aliases,
        element: 'section',
        fields: {
            label: attribute('label')
        },
        namespace: NS_DATAFORM_LAYOUT,
        type: 'section',
        typeField: 'type'
    },
    {
        aliases,
        element: 'text',
        fields: {
            value: text()
        },
        namespace: NS_DATAFORM_LAYOUT,
        type: 'text',
        typeField: 'type'
    },
    {
        aliases,
        element: 'fieldref',
        fields: {
            field: attribute('var')
        },
        namespace: NS_DATAFORM_LAYOUT,
        type: 'fieldref',
        typeField: 'type'
    },
    {
        aliases,
        element: 'reportedref',
        namespace: NS_DATAFORM_LAYOUT,
        type: 'reportedref',
        typeField: 'type'
    }
];
export default Protocol;
