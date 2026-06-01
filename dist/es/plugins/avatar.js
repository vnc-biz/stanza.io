import { NS_AVATAR_DATA, NS_AVATAR_METADATA, NS_PEP_NOTIFY } from '../Namespaces';
export default function (client) {
    client.disco.addFeature(NS_PEP_NOTIFY(NS_AVATAR_METADATA));
    client.on('pubsub:published', msg => {
        if (msg.pubsub.items.node !== NS_AVATAR_METADATA) {
            return;
        }
        const info = msg.pubsub.items.published[0].content;
        client.emit('avatar', {
            avatars: info.versions || [],
            jid: msg.from,
            source: 'pubsub'
        });
    });
    client.on('presence', pres => {
        if (pres.type !== 'error' && pres.vcardAvatar && typeof pres.vcardAvatar === 'string') {
            client.emit('avatar', {
                avatars: [
                    {
                        id: pres.vcardAvatar
                    }
                ],
                jid: pres.from,
                source: 'vcard'
            });
        }
    });
    client.publishAvatar = (id, data) => {
        return client.publish('', NS_AVATAR_DATA, {
            data,
            itemType: NS_AVATAR_DATA
        }, id);
    };
    client.useAvatars = (versions, pointers = []) => {
        return client.publish('', NS_AVATAR_METADATA, {
            itemType: NS_AVATAR_METADATA,
            pointers,
            versions
        }, 'current');
    };
    client.getAvatar = (jid, id) => {
        return client.getItem(jid, NS_AVATAR_DATA, id);
    };
}
