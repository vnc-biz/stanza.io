var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
export default function (client) {
    client.registerFeature('bind', 300, (features, cb) => __awaiter(this, void 0, void 0, function* () {
        try {
            const resp = yield client.sendIQ({
                bind: {
                    resource: client.config.resource
                },
                type: 'set'
            });
            client.features.negotiated.bind = true;
            client.emit('session:prebind', resp.bind.jid);
            const canStartSession = !features.legacySession ||
                (features.legacySession && features.legacySession.optional);
            if (!client.sessionStarted && canStartSession) {
                client.emit('session:started', client.jid);
            }
            return cb();
        }
        catch (err) {
            console.error(err);
            return cb('disconnect', 'JID binding failed');
        }
    }));
    client.registerFeature('legacySession', 1000, (features, cb) => __awaiter(this, void 0, void 0, function* () {
        if (client.sessionStarted || (features.legacySession && features.legacySession.optional)) {
            client.features.negotiated.session = true;
            return cb();
        }
        try {
            yield client.sendIQ({
                legacySession: true,
                type: 'set'
            });
            client.features.negotiated.session = true;
            if (!client.sessionStarted) {
                client.sessionStarted = true;
                client.emit('session:started', client.jid);
            }
            return cb();
        }
        catch (err) {
            return cb('disconnect', 'Session requeset failed');
        }
    }));
    client.on('session:started', () => {
        client.sessionStarted = true;
    });
    client.on('session:prebind', boundJID => {
        client.jid = boundJID;
        client.emit('session:bound', client.jid);
    });
    client.on('--reset-stream-features', () => {
        client.sessionStarted = false;
        client.features.negotiated.bind = false;
        client.features.negotiated.session = false;
    });
}
