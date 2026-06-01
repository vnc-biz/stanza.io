// ====================================================================
// XEP-0115: Entity Capabilities
// --------------------------------------------------------------------
// Source: https://xmpp.org/extensions/xep-0115.html
// Version: 1.5.1 (2016-10-06)
// ====================================================================
import { attribute, staticValue } from '../jxt';
import { NS_DISCO_LEGACY_CAPS } from '../Namespaces';
const Protocol = {
    aliases: [
        { path: 'presence.legacyCapabilities', multiple: true },
        { path: 'features.legacyCapabilities', multiple: true }
    ],
    element: 'c',
    fields: {
        algorithm: attribute('hash'),
        legacy: staticValue(true),
        node: attribute('node'),
        value: attribute('ver')
    },
    namespace: NS_DISCO_LEGACY_CAPS
};
export default Protocol;
