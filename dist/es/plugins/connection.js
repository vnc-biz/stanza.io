var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { NS_PING } from '../Namespaces';
import { timeoutPromise } from '../Utils';
function checkConnection(client) {
    return __awaiter(this, void 0, void 0, function* () {
        if (client.sm.started) {
            return new Promise(resolve => {
                client.once('stream:management:ack', () => resolve());
                client.sm.request();
            });
        }
        try {
            yield client.ping();
        }
        catch (err) {
            if (err.error && err.error.condition !== 'timeout') {
                return;
            }
            else {
                throw err;
            }
        }
    });
}
function sendCSI(client, type) {
    if (client.features.negotiated.clientStateIndication) {
        client.send('csi', {
            type
        });
    }
}
export default function (client) {
    client.disco.addFeature(NS_PING);
    client.on('iq:get:ping', iq => {
        client.sendIQResult(iq);
    });
    client.on('--reset-stream-features', () => {
        client._stopKeepAliveInterval();
        client.features.negotiated.streamManagement = false;
        client.features.negotiated.clientStateIndication = false;
    });
    client.markActive = () => sendCSI(client, 'active');
    client.markInactive = () => sendCSI(client, 'inactive');
    client.ping = (jid) => __awaiter(this, void 0, void 0, function* () {
        yield client.sendIQ({
            ping: true,
            to: jid,
            type: 'get'
        });
    });
    client.enableKeepAlive = (opts = {}) => {
        client._keepAliveOptions = opts;
        // Ping every 5 minutes
        const interval = opts.interval || 300;
        // Disconnect if no response in 15 seconds
        const timeout = opts.timeout || client.config.timeout || 15;
        function keepalive() {
            return __awaiter(this, void 0, void 0, function* () {
                if (client.sessionStarted) {
                    try {
                        yield timeoutPromise(checkConnection(client), timeout * 1000);
                    }
                    catch (err) {
                        // Kill the apparently dead connection without closing
                        // the stream itself so we can reconnect and potentially
                        // resume the session.
                        client.emit('stream:error', {
                            condition: 'connection-timeout',
                            text: 'Server did not respond in ' + timeout + ' seconds'
                        });
                        if (client.transport) {
                            client.transport.hasStream = false;
                            client.transport.disconnect(false);
                        }
                    }
                }
            });
        }
        clearInterval(client._keepAliveInterval);
        client._keepAliveInterval = setInterval(keepalive, interval * 1000);
    };
    client._stopKeepAliveInterval = () => {
        if (client._keepAliveInterval) {
            clearInterval(client._keepAliveInterval);
            delete client._keepAliveInterval;
        }
    };
    client.disableKeepAlive = () => {
        delete client._keepAliveOptions;
        client._stopKeepAliveInterval();
    };
    client.on('stream:management:resumed', () => {
        client._keepAliveOptions && client.enableKeepAlive(client._keepAliveOptions);
    });
    client.on('stream:start', () => {
        client._keepAliveOptions && client.enableKeepAlive(client._keepAliveOptions);
    });
    const smacks = (features, done) => __awaiter(this, void 0, void 0, function* () {
        if (!client.config.useStreamManagement) {
            return done();
        }
        const smHandler = (sm) => __awaiter(this, void 0, void 0, function* () {
            switch (sm.type) {
                case 'enabled':
                    yield client.sm.enabled(sm);
                    client.features.negotiated.streamManagement = true;
                    client.off('sm', smHandler);
                    return done();
                case 'resumed':
                    yield client.sm.resumed(sm);
                    client.features.negotiated.streamManagement = true;
                    client.features.negotiated.bind = true;
                    client.sessionStarted = true;
                    client.sessionStarting = false;
                    client.off('sm', smHandler);
                    client.emit('stream:management:resumed', sm);
                    return done('break'); // Halt further processing of stream features
                case 'failed':
                    yield client.sm.failed(sm);
                    client.off('sm', smHandler);
                    client.emit('session:end');
                    done();
            }
        });
        client.on('sm', smHandler);
        if (!client.sm.id) {
            if (client.features.negotiated.bind) {
                yield client.sm.enable();
            }
            else {
                client.off('sm', smHandler);
                done();
            }
        }
        else if (client.sm.id && client.sm.allowResume) {
            yield client.sm.resume();
        }
        else {
            client.off('sm', smHandler);
            done();
        }
    });
    client.registerFeature('streamManagement', 200, smacks);
    client.registerFeature('streamManagement', 500, smacks);
    client.registerFeature('clientStateIndication', 400, (features, cb) => {
        client.features.negotiated.clientStateIndication = true;
        cb();
    });
}
