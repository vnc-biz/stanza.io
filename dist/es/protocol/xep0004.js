// ====================================================================
// XEP-0004: Data Forms
// --------------------------------------------------------------------
// Source: https://xmpp.org/extensions/xep-0004.html
// Version: 2.9 (2007-08-13)
//
// Additional:
// --------------------------------------------------------------------
// XEP-0122: Data Forms Validation
// --------------------------------------------------------------------
// Source: https://xmpp.org/extensions/xep-0122.html
// Version: 1.0.1 (2018-03-05)
// ====================================================================
import { DataFormFieldType } from '../Constants';
import { attribute, childAttribute, childBoolean, childEnum, childIntegerAttribute, childText, multipleChildText, splicePath } from '../jxt';
import { NS_DATAFORM, NS_DATAFORM_VALIDATION } from '../Namespaces';
const Protocol = [
    {
        aliases: [{ path: 'message.forms', multiple: true }],
        element: 'x',
        fields: {
            instructions: Object.assign(Object.assign({}, multipleChildText(null, 'instructions')), { exportOrder: 2 }),
            reported: Object.assign(Object.assign({}, splicePath(null, 'reported', 'dataformField', true)), { exportOrder: 3 }),
            title: Object.assign(Object.assign({}, childText(null, 'title')), { exportOrder: 1 }),
            type: attribute('type')
        },
        namespace: NS_DATAFORM,
        optionalNamespaces: {
            xdv: NS_DATAFORM_VALIDATION
        },
        path: 'dataform'
    },
    {
        aliases: [
            { path: 'dataform.fields', multiple: true },
            { path: 'dataform.items.fields', multiple: true }
        ],
        element: 'field',
        fields: {
            description: childText(null, 'desc'),
            label: attribute('label'),
            name: attribute('var'),
            rawValues: Object.assign(Object.assign({}, multipleChildText(null, 'value')), { exporter: () => null }),
            required: childBoolean(null, 'required'),
            type: attribute('type'),
            value: {
                importer(xml, context) {
                    const fieldType = xml.getAttribute('type');
                    const converter = multipleChildText(NS_DATAFORM, 'value');
                    const rawValues = converter.importer(xml, context);
                    const singleValue = rawValues[0];
                    switch (fieldType) {
                        case DataFormFieldType.TextMultiple:
                        case DataFormFieldType.ListMultiple:
                        case DataFormFieldType.JIDMultiple:
                            return rawValues;
                        case DataFormFieldType.Hidden:
                        case DataFormFieldType.Fixed:
                            if (rawValues.length === 1) {
                                return singleValue;
                            }
                            return rawValues;
                        case DataFormFieldType.Boolean:
                            if (singleValue) {
                                return singleValue === '1' || singleValue === 'true';
                            }
                            break;
                        default:
                            return singleValue;
                    }
                },
                exporter(xml, data, context) {
                    const converter = multipleChildText(null, 'value');
                    let outputData = [];
                    const rawData = context.data && context.data.rawValues
                        ? context.data.rawValues[0]
                        : undefined;
                    if (typeof data === 'boolean') {
                        if (rawData === 'true' || rawData === 'false') {
                            outputData = [rawData];
                        }
                        else {
                            outputData = [data ? '1' : '0'];
                        }
                    }
                    else if (!Array.isArray(data)) {
                        outputData = [data.toString()];
                    }
                    else {
                        for (const value of data) {
                            outputData.push(value.toString());
                        }
                    }
                    converter.exporter(xml, outputData, Object.assign({}, context, {
                        namespace: NS_DATAFORM
                    }));
                }
            }
        },
        namespace: NS_DATAFORM,
        path: 'dataformField'
    },
    {
        aliases: [{ path: 'dataform.fields.options', multiple: true }],
        element: 'option',
        fields: {
            label: attribute('label'),
            value: childText(null, 'value')
        },
        namespace: NS_DATAFORM
    },
    {
        aliases: [{ path: 'dataform.items', multiple: true }],
        element: 'item',
        namespace: NS_DATAFORM
    },
    // ----------------------------------------------------------------
    // XEP-0122: Data Forms Validation
    // ----------------------------------------------------------------
    {
        element: 'validate',
        fields: {
            listMax: childIntegerAttribute(null, 'list-range', 'max'),
            listMin: childIntegerAttribute(null, 'list-range', 'min'),
            method: childEnum(null, ['basic', 'open', 'range', 'regex'], 'basic'),
            rangeMax: childAttribute(null, 'range', 'max'),
            rangeMin: childAttribute(null, 'range', 'min'),
            regex: childText(null, 'regex'),
            type: attribute('datatype', 'xs:string')
        },
        namespace: NS_DATAFORM_VALIDATION,
        path: 'dataform.fields.validation'
    }
];
export default Protocol;
