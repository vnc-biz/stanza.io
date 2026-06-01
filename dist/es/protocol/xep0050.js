// ====================================================================
// XEP-0050: Ad-Hoc Commands
// --------------------------------------------------------------------
// Source: https://xmpp.org/extensions/xep-0050.html
// Version: 1.2.2 (2016-12-03)
// ====================================================================
import { addAlias, attribute, childBoolean, childEnum, extendStanzaError, text } from '../jxt';
import { NS_ADHOC_COMMANDS, NS_DATAFORM } from '../Namespaces';
const Protocol = [
    addAlias(NS_DATAFORM, 'x', ['iq.command.form']),
    extendStanzaError({
        commandError: childEnum(NS_ADHOC_COMMANDS, [
            'bad-action',
            'bad-locale',
            'bad-payload',
            'bad-sessionid',
            'malformed-action',
            'session-expired'
        ])
    }),
    {
        element: 'command',
        fields: {
            action: attribute('action'),
            node: attribute('node'),
            sid: attribute('sessionid'),
            status: attribute('status')
        },
        namespace: NS_ADHOC_COMMANDS,
        path: 'iq.command'
    },
    {
        element: 'actions',
        fields: {
            complete: childBoolean(null, 'complete'),
            execute: attribute('execute'),
            next: childBoolean(null, 'next'),
            prev: childBoolean(null, 'prev')
        },
        namespace: NS_ADHOC_COMMANDS,
        path: 'iq.command.availableActions'
    },
    {
        aliases: [{ path: 'iq.command.notes', multiple: true }],
        element: 'note',
        fields: {
            type: attribute('type'),
            value: text()
        },
        namespace: NS_ADHOC_COMMANDS
    }
];
export default Protocol;
