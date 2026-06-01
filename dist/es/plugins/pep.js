import { NS_ACTIVITY, NS_GEOLOC, NS_MOOD, NS_NICK, NS_PEP_NOTIFY, NS_TUNE } from '../Namespaces';
export default function (client) {
    client.disco.addFeature(NS_ACTIVITY);
    client.disco.addFeature(NS_GEOLOC);
    client.disco.addFeature(NS_MOOD);
    client.disco.addFeature(NS_NICK);
    client.disco.addFeature(NS_TUNE);
    client.disco.addFeature(NS_PEP_NOTIFY(NS_ACTIVITY));
    client.disco.addFeature(NS_PEP_NOTIFY(NS_GEOLOC));
    client.disco.addFeature(NS_PEP_NOTIFY(NS_MOOD));
    client.disco.addFeature(NS_PEP_NOTIFY(NS_NICK));
    client.disco.addFeature(NS_PEP_NOTIFY(NS_TUNE));
    client.publishActivity = (data) => {
        return client.publish('', NS_ACTIVITY, Object.assign({ itemType: NS_ACTIVITY }, data));
    };
    client.publishGeoLoc = (data) => {
        return client.publish('', NS_GEOLOC, Object.assign({ itemType: NS_GEOLOC }, data));
    };
    client.publishMood = (mood) => {
        return client.publish('', NS_MOOD, Object.assign({ itemType: NS_MOOD }, mood));
    };
    client.publishNick = (nick) => {
        return client.publish('', NS_NICK, {
            itemType: NS_NICK,
            nick
        });
    };
    client.publishTune = (tune) => {
        return client.publish('', NS_TUNE, Object.assign({ itemType: NS_TUNE }, tune));
    };
    client.on('pubsub:published', msg => {
        const content = msg.pubsub.items.published[0].content;
        switch (msg.pubsub.items.node) {
            case NS_ACTIVITY:
                return client.emit('activity', {
                    activity: content,
                    jid: msg.from
                });
            case NS_GEOLOC:
                return client.emit('geoloc', {
                    geoloc: content,
                    jid: msg.from
                });
            case NS_MOOD:
                return client.emit('mood', {
                    jid: msg.from,
                    mood: content
                });
            case NS_NICK:
                return client.emit('nick', {
                    jid: msg.from,
                    nick: content.nick
                });
            case NS_TUNE:
                return client.emit('tune', {
                    jid: msg.from,
                    tune: msg.pubsub.items.published[0].content
                });
        }
    });
}
