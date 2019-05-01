'use strict';

module.exports = function (client) {

    client.disco.addFeature('jabber:iq:batch');

    client.on('jabber:iq:last', function (iq) {
        client.emit('block', {
            results: iq.query.results || []
        });
    });

    client.getLastActivity = function (jids, cb) {
        return client.sendIq({
            type: 'get',
            query: jids
        }, cb);
    };


};
