// ====================================================================
// XEP-0060: Publish-Subscribe
// --------------------------------------------------------------------
// Source: https://xmpp.org/extensions/xep-0060.html
// Version: 1.15.1 (2018-02-02)
// ====================================================================
import { PubsubErrorCondition } from '../Constants';
import { addAlias, attribute, booleanAttribute, childAttribute, childBoolean, childEnum, deepChildBoolean, extendStanzaError, integerAttribute, JIDAttribute, multipleChildAttribute, splicePath } from '../jxt';
import { NS_DATAFORM, NS_PUBSUB, NS_PUBSUB_ERRORS, NS_PUBSUB_EVENT, NS_PUBSUB_OWNER, NS_RSM } from '../Namespaces';
const dateOrPresenceAttribute = (name) => ({
    importer(xml) {
        const data = xml.getAttribute(name);
        if (data === 'presence') {
            return data;
        }
        if (data) {
            return new Date(data);
        }
    },
    exporter(xml, value) {
        let data;
        if (typeof value === 'string') {
            data = value;
        }
        else {
            data = value.toISOString();
        }
        xml.setAttribute(name, data);
    }
});
const SubscriptionFields = {
    configurable: childBoolean(null, 'subscribe-options'),
    configurationRequired: deepChildBoolean([
        { namespace: null, element: 'subscribe-options' },
        { namespace: null, element: 'required' }
    ]),
    jid: JIDAttribute('jid'),
    node: attribute('node'),
    state: attribute('subscription'),
    subid: attribute('subid')
};
const NodeOnlyField = {
    node: attribute('node')
};
const Protocol = [
    {
        aliases: ['pubsub', 'iq.pubsub', 'message.pubsub'],
        childrenExportOrder: {
            configure: 0,
            create: 100,
            publish: 100,
            subscribe: 100,
            subscriptionOptions: 0
        },
        defaultType: 'user',
        element: 'pubsub',
        fields: {
            publishOptions: splicePath(null, 'publish-options', 'dataform')
        },
        namespace: NS_PUBSUB,
        type: 'user',
        typeField: 'context'
    },
    {
        aliases: ['pubsub', 'iq.pubsub', 'message.pubsub'],
        defaultType: 'user',
        element: 'pubsub',
        fields: {
            purge: childAttribute(null, 'purge', 'node')
        },
        namespace: NS_PUBSUB_OWNER,
        type: 'owner',
        typeField: 'context'
    },
    addAlias(NS_DATAFORM, 'x', [
        'iq.pubsub.configure.form',
        'iq.pubsub.defaultConfiguration.form',
        'iq.pubsub.defaultSubscriptionOptions.form',
        'iq.pubsub.subscriptionOptions.form',
        'message.pubsub.configuration.form'
    ]),
    addAlias(NS_RSM, 'set', ['iq.pubsub.fetch.paging']),
    extendStanzaError({
        pubsubError: childEnum(NS_PUBSUB_ERRORS, Object.values(PubsubErrorCondition)),
        pubsubUnsupportedFeature: childAttribute(NS_PUBSUB_ERRORS, 'unsupported', 'feature')
    }),
    {
        element: 'subscribe',
        fields: {
            jid: JIDAttribute('jid'),
            node: attribute('node')
        },
        namespace: NS_PUBSUB,
        path: 'iq.pubsub.subscribe'
    },
    {
        element: 'unsubscribe',
        fields: {
            jid: JIDAttribute('jid'),
            node: attribute('node'),
            subid: attribute('subid')
        },
        namespace: NS_PUBSUB,
        path: 'iq.pubsub.unsubscribe'
    },
    {
        element: 'options',
        fields: {
            jid: JIDAttribute('jid'),
            node: attribute('node'),
            subid: attribute('subid')
        },
        namespace: NS_PUBSUB,
        path: 'iq.pubsub.subscriptionOptions'
    },
    {
        aliases: [{ path: 'iq.pubsub.subscriptions', selector: 'user', impliedType: true }],
        element: 'subscriptions',
        fields: {
            jid: JIDAttribute('jid'),
            node: attribute('node')
        },
        namespace: NS_PUBSUB,
        type: 'user'
    },
    {
        aliases: [{ path: 'iq.pubsub.subscriptions', selector: 'owner', impliedType: true }],
        element: 'subscriptions',
        fields: {
            jid: JIDAttribute('jid'),
            node: attribute('node')
        },
        namespace: NS_PUBSUB_OWNER,
        type: 'owner'
    },
    {
        aliases: [
            { path: 'iq.pubsub.subscription', selector: 'owner' },
            {
                impliedType: true,
                multiple: true,
                path: 'iq.pubsub.subscriptions.items',
                selector: 'owner'
            }
        ],
        element: 'subscription',
        fields: SubscriptionFields,
        namespace: NS_PUBSUB
    },
    {
        aliases: [
            { path: 'iq.pubsub.subscription', selector: 'user' },
            {
                impliedType: true,
                multiple: true,
                path: 'iq.pubsub.subscriptions.items',
                selector: 'user'
            }
        ],
        element: 'subscription',
        fields: SubscriptionFields,
        namespace: NS_PUBSUB,
        type: 'user'
    },
    {
        aliases: [
            {
                impliedType: true,
                multiple: true,
                path: 'iq.pubsub.subscriptions.items',
                selector: 'owner'
            }
        ],
        element: 'subscription',
        fields: SubscriptionFields,
        namespace: NS_PUBSUB_OWNER,
        type: 'owner'
    },
    {
        aliases: [
            { path: 'iq.pubsub.affiliations', selector: 'user', impliedType: true },
            { path: 'message.pubsub.affiliations', selector: 'user', impliedType: true }
        ],
        element: 'affiliations',
        fields: NodeOnlyField,
        namespace: NS_PUBSUB,
        type: 'user'
    },
    {
        aliases: [{ path: 'iq.pubsub.affiliations', selector: 'owner', impliedType: true }],
        element: 'affiliations',
        fields: NodeOnlyField,
        namespace: NS_PUBSUB_OWNER,
        type: 'owner'
    },
    {
        aliases: [
            {
                impliedType: true,
                multiple: true,
                path: 'iq.pubsub.affiliations.items',
                selector: 'user'
            },
            {
                impliedType: true,
                multiple: true,
                path: 'message.pubsub.affiliations.items',
                selector: 'user'
            }
        ],
        element: 'affiliation',
        fields: {
            affiliation: attribute('affiliation'),
            jid: JIDAttribute('jid'),
            node: attribute('node')
        },
        namespace: NS_PUBSUB,
        type: 'user'
    },
    {
        aliases: [
            {
                impliedType: true,
                multiple: true,
                path: 'iq.pubsub.affiliations.items',
                selector: 'owner'
            }
        ],
        element: 'affiliation',
        fields: {
            affiliation: attribute('affiliation'),
            jid: JIDAttribute('jid'),
            node: attribute('node')
        },
        namespace: NS_PUBSUB_OWNER,
        type: 'owner'
    },
    {
        element: 'create',
        fields: NodeOnlyField,
        namespace: NS_PUBSUB,
        path: 'iq.pubsub.create'
    },
    {
        aliases: [{ path: 'iq.pubsub.destroy', selector: 'owner' }],
        element: 'delete',
        fields: {
            node: attribute('node'),
            redirect: childAttribute(null, 'redirect', 'uri')
        },
        namespace: NS_PUBSUB_OWNER
    },
    {
        aliases: [{ path: 'iq.pubsub.configure', selector: 'owner', impliedType: true }],
        element: 'configure',
        fields: NodeOnlyField,
        namespace: NS_PUBSUB_OWNER,
        type: 'owner'
    },
    {
        aliases: [{ path: 'iq.pubsub.configure', selector: 'user', impliedType: true }],
        element: 'configure',
        fields: NodeOnlyField,
        namespace: NS_PUBSUB,
        type: 'user'
    },
    {
        element: 'default',
        fields: {
            node: attribute('node')
        },
        namespace: NS_PUBSUB,
        path: 'iq.pubsub.defaultSubscriptionOptions'
    },
    {
        element: 'default',
        fields: {},
        namespace: NS_PUBSUB_OWNER,
        path: 'iq.pubsub.defaultConfiguration'
    },
    {
        element: 'publish',
        fields: NodeOnlyField,
        namespace: NS_PUBSUB,
        path: 'iq.pubsub.publish'
    },
    {
        element: 'retract',
        fields: {
            id: childAttribute(null, 'item', 'id'),
            node: attribute('node'),
            notify: booleanAttribute('notify')
        },
        namespace: NS_PUBSUB,
        path: 'iq.pubsub.retract'
    },
    {
        element: 'items',
        fields: {
            max: integerAttribute('max_items'),
            node: attribute('node')
        },
        namespace: NS_PUBSUB,
        path: 'iq.pubsub.fetch'
    },
    {
        aliases: [
            'pubsubitem',
            'iq.pubsub.publish.item',
            { multiple: true, path: 'iq.pubsub.fetch.items' }
        ],
        element: 'item',
        fields: {
            id: attribute('id'),
            publisher: JIDAttribute('publisher')
        },
        namespace: NS_PUBSUB
    },
    {
        element: 'event',
        fields: {
            eventType: childEnum(null, [
                'purge',
                'delete',
                'subscription',
                'configuration',
                'items'
            ])
        },
        namespace: NS_PUBSUB_EVENT,
        path: 'message.pubsub',
        type: 'event',
        typeField: 'context'
    },
    {
        aliases: [{ path: 'message.pubsub.items.published', multiple: true }],
        element: 'item',
        fields: {
            id: attribute('id'),
            publisher: JIDAttribute('publisher')
        },
        namespace: NS_PUBSUB_EVENT,
        path: 'pubsubeventitem'
    },
    {
        element: 'purge',
        fields: NodeOnlyField,
        namespace: NS_PUBSUB_EVENT,
        path: 'message.pubsub.purge'
    },
    {
        element: 'delete',
        fields: {
            node: attribute('node'),
            redirect: childAttribute(null, 'redirect', 'uri')
        },
        namespace: NS_PUBSUB_EVENT,
        path: 'message.pubsub.delete'
    },
    {
        aliases: [{ path: 'message.pubsub.subscription', selector: 'event', impliedType: true }],
        element: 'subscription',
        fields: {
            expires: dateOrPresenceAttribute('expiry'),
            jid: JIDAttribute('jid'),
            node: attribute('node'),
            subid: attribute('subid'),
            type: attribute('subscription')
        },
        namespace: NS_PUBSUB_EVENT,
        type: 'event'
    },
    {
        element: 'configuration',
        fields: NodeOnlyField,
        namespace: NS_PUBSUB_EVENT,
        path: 'message.pubsub.configuration'
    },
    {
        element: 'items',
        fields: {
            node: attribute('node'),
            retracted: multipleChildAttribute(null, 'retract', 'id')
        },
        namespace: NS_PUBSUB_EVENT,
        path: 'message.pubsub.items'
    }
];
export default Protocol;
