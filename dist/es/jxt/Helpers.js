import { NS_CLIENT, NS_STANZAS, NS_STREAM } from '../Namespaces';
import { attribute, childAttribute, childText } from './Types';
// ====================================================================
// Useful XMPP Aliases
// ====================================================================
export const JIDAttribute = attribute;
export const childJIDAttribute = childAttribute;
export const childJID = childText;
// ====================================================================
// XMPP Definition Shortcuts
// ====================================================================
export function addAlias(namespace, element, aliases) {
    return {
        aliases: Array.isArray(aliases) ? aliases : [aliases],
        element,
        fields: {},
        namespace
    };
}
export function extendMessage(fields) {
    return { element: 'message', fields, namespace: NS_CLIENT };
}
export function extendPresence(fields) {
    return { element: 'presence', fields, namespace: NS_CLIENT };
}
export function extendIQ(fields) {
    return { element: 'iq', fields, namespace: NS_CLIENT };
}
export function extendStreamFeatures(fields) {
    return {
        element: 'features',
        fields,
        namespace: NS_STREAM
    };
}
export function extendStanzaError(fields) {
    return {
        element: 'error',
        fields,
        namespace: NS_STANZAS,
        path: 'stanzaError'
    };
}
export function pubsubItemContentAliases() {
    return [
        { path: 'pubsubcontent', contextField: 'itemType' },
        { path: 'pubsubitem.content', contextField: 'itemType' },
        { path: 'pubsubeventitem.content', contextField: 'itemType' },
        { path: 'iq.pubsub.publish.items', contextField: 'itemType' }
    ];
}
