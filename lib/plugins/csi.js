'use strict';


module.exports = function (client, stanzas) {

    var Active = stanzas.getDefinition('active', 'urn:xmpp:csi:0');
    var Inactive = stanzas.getDefinition('inactive', 'urn:xmpp:csi:0');


    client.registerFeature('clientStateIndication', 400, function (features, cb) {
        this.features.negotiated.clientStateIndication = true;
        cb();
    });

    client.markActive = function () {
        if (this.features.negotiated.clientStateIndication) {
            this.send(new Active());
        }
    };

    client.markInactive = function () {
        if (this.features.negotiated.clientStateIndication) {
            this.send(new Inactive());
        }
    };
};
