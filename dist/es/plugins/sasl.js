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
    client.registerFeature('sasl', 100, (features, done) => __awaiter(this, void 0, void 0, function* () {
        const mech = client.sasl.createMechanism(features.sasl.mechanisms);
        const saslHandler = (sasl) => __awaiter(this, void 0, void 0, function* () {
            if (!mech) {
                return;
            }
            switch (sasl.type) {
                case 'success': {
                    client.features.negotiated.sasl = true;
                    client.off('sasl', saslHandler);
                    client.emit('auth:success', client.config.credentials);
                    if (client.transport) {
                        client.transport.authenticated = true;
                    }
                    done('restart');
                    return;
                }
                case 'challenge': {
                    mech.processChallenge(sasl.value);
                    try {
                        const credentials = (yield client.getCredentials());
                        const resp = mech.createResponse(credentials);
                        if (resp || resp === '') {
                            client.send('sasl', {
                                type: 'response',
                                value: resp
                            });
                        }
                        else {
                            client.send('sasl', {
                                type: 'response'
                            });
                        }
                        const cacheable = mech.getCacheableCredentials();
                        if (cacheable) {
                            if (!client.config.credentials) {
                                client.config.credentials = {};
                            }
                            client.config.credentials = Object.assign(Object.assign({}, client.config.credentials), cacheable);
                            client.emit('credentials:update', client.config.credentials);
                        }
                    }
                    catch (err) {
                        console.error(err);
                        client.send('sasl', {
                            type: 'abort'
                        });
                    }
                    return;
                }
                case 'failure':
                case 'abort': {
                    client.off('sasl', saslHandler);
                    client.emit('auth:failed');
                    done('disconnect', 'authentication failed');
                    return;
                }
            }
        });
        if (!mech) {
            client.off('sasl', saslHandler);
            client.emit('auth:failed');
            return done('disconnect', 'authentication failed');
        }
        client.on('sasl', saslHandler);
        client.once('--reset-stream-features', () => {
            client.features.negotiated.sasl = false;
            client.off('sasl', saslHandler);
        });
        try {
            const credentials = (yield client.getCredentials());
            client.send('sasl', {
                mechanism: mech.name,
                type: 'auth',
                value: mech.createResponse(credentials)
            });
        }
        catch (err) {
            console.error(err);
            client.send('sasl', {
                type: 'abort'
            });
        }
    }));
}
