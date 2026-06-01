// ====================================================================
// XEP-0313: Message Archive Management
// --------------------------------------------------------------------
// Source: https://xmpp.org/extensions/xep-0313.html
// Version: 0.6.1 (2017-02-22)
// ====================================================================
import { addAlias, attribute, booleanAttribute, deepMultipleChildText } from '../jxt';
import { NS_DATAFORM, NS_FORWARD_0, NS_MAM_2, NS_MAM_1, NS_RSM } from '../Namespaces';
const versions = {
    '2': NS_MAM_2,
    '1': NS_MAM_1
};
const Protocol = [
    addAlias(NS_DATAFORM, 'x', ['iq.archive.form']),
    addAlias(NS_FORWARD_0, 'forwarded', ['message.archive.item']),
    addAlias(NS_RSM, 'set', ['iq.archive.paging'])
];
for (const [version, namespace] of Object.entries(versions)) {
    Protocol.push({
        defaultType: 'query',
        defaultVersion: '2',
        element: 'query',
        fields: {
            node: attribute('node'),
            queryId: attribute('queryid')
        },
        namespace,
        path: 'iq.archive',
        type: 'query',
        typeField: 'type',
        version,
        versionField: 'version'
    }, {
        element: 'fin',
        fields: {
            complete: booleanAttribute('complete'),
            stable: booleanAttribute('stable')
        },
        namespace,
        path: 'iq.archive',
        type: 'result',
        version
    }, {
        element: 'prefs',
        fields: {
            default: attribute('default'),
            always: deepMultipleChildText([
                { namespace: null, element: 'always' },
                { namespace: null, element: 'jid' }
            ]),
            never: deepMultipleChildText([
                { namespace: null, element: 'never' },
                { namespace: null, element: 'jid' }
            ])
        },
        namespace,
        path: 'iq.archive',
        type: 'preferences',
        version
    }, {
        element: 'result',
        defaultType: '2',
        fields: {
            id: attribute('id'),
            queryId: attribute('queryid')
        },
        namespace,
        path: 'message.archive',
        type: version,
        typeField: 'version'
    });
}
export default Protocol;
