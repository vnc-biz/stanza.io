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
    client.features = {
        handlers: Object.create(null),
        negotiated: Object.create(null),
        order: []
    };
    client.registerFeature = function (name, priority, handler) {
        this.features.order.push({
            name,
            priority
        });
        // We want the features with smallest priority values at the start of the list
        this.features.order.sort((a, b) => a.priority - b.priority);
        this.features.handlers[name] = handler.bind(client);
    };
    client.on('features', (features) => __awaiter(this, void 0, void 0, function* () {
        const negotiated = client.features.negotiated;
        const handlers = client.features.handlers;
        const processingOrder = [];
        for (const { name } of client.features.order) {
            if (features[name] && handlers[name] && !negotiated[name]) {
                processingOrder.push(name);
            }
        }
        function processFeature(featureName) {
            return new Promise(resolve => {
                handlers[featureName](features, (command, message) => {
                    if (command) {
                        resolve({ command, message });
                    }
                    else {
                        resolve(null);
                    }
                });
            });
        }
        for (const item of processingOrder) {
            if (negotiated[item]) {
                continue;
            }
            let cmd = '';
            let msg = '';
            try {
                const res = yield processFeature(item);
                if (res) {
                    cmd = res.command;
                    msg = res.message || '';
                }
            }
            catch (err) {
                cmd = 'disconnect';
                msg = err.message;
                console.error(err);
            }
            if (!cmd) {
                continue;
            }
            if (cmd === 'restart' && client.transport) {
                client.transport.restart();
            }
            if (cmd === 'disconnect') {
                client.emit('stream:error', {
                    condition: 'policy-violation',
                    text: 'Failed to negotiate stream features: ' + msg
                });
                client.disconnect();
            }
            return;
        }
    }));
}
