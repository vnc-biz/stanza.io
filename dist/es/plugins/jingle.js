var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { RTCPeerConnection } from '../platform';
import * as Jingle from '../jingle';
import { NS_JINGLE_1, NS_JINGLE_DTLS_0, NS_JINGLE_DTLS_SCTP_1, NS_JINGLE_FILE_TRANSFER_4, NS_JINGLE_FILE_TRANSFER_5, NS_JINGLE_ICE_0, NS_JINGLE_ICE_UDP_1, NS_JINGLE_RTP_1, NS_JINGLE_RTP_AUDIO, NS_JINGLE_RTP_HDREXT_0, NS_JINGLE_RTP_RTCP_FB_0, NS_JINGLE_RTP_VIDEO } from '../Namespaces';
export default function (client) {
    const hasNativePeerConnection = !!RTCPeerConnection;
    const defaultConfig = {
        advertiseAudio: hasNativePeerConnection,
        advertiseFileTransfer: hasNativePeerConnection,
        advertiseVideo: hasNativePeerConnection,
        bundlePolicy: 'balanced',
        hasRTCPeerConnection: hasNativePeerConnection,
        iceServers: [{ urls: 'stun:stun.l.google.com:19302' }],
        iceTransportPolicy: 'all',
        rtcpMuxPolicy: 'require',
        trickleIce: true
    };
    const providedConfig = client.config.jingle;
    const config = Object.assign(Object.assign({}, defaultConfig), providedConfig);
    const jingle = (client.jingle = new Jingle.SessionManager(config));
    const caps = [NS_JINGLE_1];
    if (config.hasRTCPeerConnection) {
        caps.push(NS_JINGLE_ICE_0, NS_JINGLE_ICE_UDP_1, NS_JINGLE_DTLS_SCTP_1, NS_JINGLE_DTLS_0, 'urn:ietf:rfc:5888' // Jingle Grouping Framework
        );
        if (config.trickleIce === false) {
            caps.push('urn:ietf:rfc:3264'); // ICE prefer batched candidates
        }
        if (config.advertiseAudio || config.advertiseVideo) {
            caps.push(NS_JINGLE_RTP_1, NS_JINGLE_RTP_RTCP_FB_0, NS_JINGLE_RTP_HDREXT_0, 'urn:ietf:rfc:5576' // Jingle Source Specific Media Attributes
            );
        }
        if (config.advertiseAudio) {
            caps.push(NS_JINGLE_RTP_AUDIO);
        }
        if (config.advertiseVideo) {
            caps.push(NS_JINGLE_RTP_VIDEO);
        }
        if (config.advertiseFileTransfer) {
            caps.push(NS_JINGLE_FILE_TRANSFER_4, NS_JINGLE_FILE_TRANSFER_5);
        }
    }
    for (const cap of caps) {
        client.disco.addFeature(cap);
    }
    const mappedEvents = [
        'outgoing',
        'incoming',
        'accepted',
        'terminated',
        'ringing',
        'mute',
        'unmute',
        'hold',
        'resumed'
    ];
    for (const event of mappedEvents) {
        jingle.on(event, (session, data) => {
            client.emit(('jingle:' + event), session, data);
        });
    }
    jingle.on('createdSession', data => {
        client.emit('jingle:created', data);
    });
    jingle.on('send', (data) => __awaiter(this, void 0, void 0, function* () {
        try {
            if (data.type === 'set') {
                const resp = yield client.sendIQ(data);
                if (!resp.jingle) {
                    resp.jingle = {};
                }
                resp.jingle.sid = data.jingle.sid;
                jingle.process(resp);
            }
            if (data.type === 'result') {
                client.sendIQResult({ type: 'set', id: data.id, from: data.to }, data);
            }
            if (data.type === 'error') {
                client.sendIQError({ type: 'set', id: data.id, from: data.to }, data);
            }
        }
        catch (err) {
            if (!err.jingle) {
                err.jingle = data.jingle;
            }
            err.jingle.sid = data.jingle.sid;
            jingle.process(err);
        }
    }));
    client.on('session:bound', (jid) => {
        jingle.selfID = jid;
    });
    client.on('iq:set:jingle', (data) => {
        jingle.process(data);
    });
    client.on('unavailable', (pres) => {
        jingle.endPeerSessions(pres.from, undefined, true);
    });
    client.getServices = (jid, type, version) => __awaiter(this, void 0, void 0, function* () {
        const resp = yield client.sendIQ({
            externalServices: {
                type,
                version
            },
            to: jid,
            type: 'get'
        });
        const services = resp.externalServices;
        services.services = services.services || [];
        return services;
    });
    client.getServiceCredentials = (jid, host, type, port, version) => __awaiter(this, void 0, void 0, function* () {
        const resp = yield client.sendIQ({
            externalServiceCredentials: {
                host,
                port,
                type,
                version
            },
            to: jid,
            type: 'get'
        });
        return resp.externalServiceCredentials;
    });
    client.discoverICEServers = (...args_1) => __awaiter(this, [...args_1], void 0, function* (opts = {}) {
        try {
            const resp = yield client.getServices(client.config.server, undefined, opts.version);
            const services = resp.services || [];
            const discovered = [];
            for (const service of services) {
                client.jingle.addICEServer(service);
            }
            return discovered;
        }
        catch (err) {
            return [];
        }
    });
}
