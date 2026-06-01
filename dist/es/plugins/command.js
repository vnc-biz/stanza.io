import { NS_ADHOC_COMMANDS } from '../Namespaces';
export default function (client) {
    client.disco.addFeature(NS_ADHOC_COMMANDS);
    client.disco.addItem({
        name: 'Ad-Hoc Commands',
        node: NS_ADHOC_COMMANDS
    });
    client.getCommands = (jid) => {
        return client.getDiscoItems(jid, NS_ADHOC_COMMANDS);
    };
}
