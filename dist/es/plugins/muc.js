var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { MUCStatusCode } from '../Constants';
import * as JID from '../JID';
import { NS_HATS_0, NS_MUC, NS_MUC_DIRECT_INVITE } from '../Namespaces';
import { uuid } from '../Utils';
function isMUCPresence(pres) {
    return !!pres.muc;
}
export default function (client) {
    client.disco.addFeature(NS_MUC);
    client.disco.addFeature(NS_MUC_DIRECT_INVITE);
    client.disco.addFeature(NS_HATS_0);
    client.joinedRooms = new Map();
    client.joiningRooms = new Map();
    client.leavingRooms = new Map();
    function rejoinRooms() {
        const oldJoiningRooms = client.joiningRooms;
        client.joiningRooms = new Map();
        for (const [room, nick] of oldJoiningRooms) {
            client.joinRoom(room, nick);
        }
        const oldJoinedRooms = client.joinedRooms;
        client.joinedRooms = new Map();
        for (const [room, nick] of oldJoinedRooms) {
            client.joinRoom(room, nick);
        }
    }
    client.on('session:started', rejoinRooms);
    client.on('message', msg => {
        if (msg.type === 'groupchat' && msg.hasSubject && !msg.body) {
            client.emit('muc:topic', {
                from: msg.from,
                room: JID.toBare(msg.from),
                topic: msg.subject || ''
            });
            return;
        }
        if (!msg.muc) {
            return;
        }
        if (msg.muc.type === 'direct-invite' || (!msg.muc.invite && msg.legacyMUC)) {
            const invite = msg.muc.type === 'direct-invite' ? msg.muc : msg.legacyMUC;
            client.emit('muc:invite', {
                from: msg.from,
                password: invite.password,
                reason: invite.reason,
                room: invite.jid,
                thread: invite.thread,
                type: 'direct'
            });
            return;
        }
        if (msg.muc.invite) {
            client.emit('muc:invite', {
                from: msg.muc.invite[0].from,
                password: msg.muc.password,
                reason: msg.muc.invite[0].reason,
                room: msg.from,
                thread: msg.muc.invite[0].thread,
                type: 'mediated'
            });
            return;
        }
        if (msg.muc.decline) {
            client.emit('muc:declined', {
                from: msg.muc.decline.from,
                reason: msg.muc.decline.reason,
                room: msg.from
            });
            return;
        }
        client.emit('muc:other', msg);
    });
    client.on('presence', pres => {
        const room = JID.toBare(pres.from);
        if (client.joiningRooms.has(room) && pres.type === 'error') {
            client.joiningRooms.delete(room);
            client.emit('muc:failed', pres);
            client.emit('muc:error', pres);
            return;
        }
        if (!isMUCPresence(pres)) {
            return;
        }
        const isSelf = pres.muc.statusCodes && pres.muc.statusCodes.indexOf(MUCStatusCode.SelfPresence) >= 0;
        const isNickChange = pres.muc.statusCodes && pres.muc.statusCodes.indexOf(MUCStatusCode.NickChanged) >= 0;
        if (pres.type === 'error') {
            client.emit('muc:error', pres);
            return;
        }
        if (pres.type === 'unavailable') {
            client.emit('muc:unavailable', pres);
            if (isSelf) {
                if (isNickChange) {
                    client.joinedRooms.set(room, pres.muc.nick);
                }
                else {
                    client.emit('muc:leave', pres);
                    client.joinedRooms.delete(room);
                    client.leavingRooms.delete(room);
                }
            }
            if (pres.muc.destroy) {
                client.emit('muc:destroyed', {
                    newRoom: pres.muc.destroy.jid,
                    password: pres.muc.destroy.password,
                    reason: pres.muc.destroy.reason,
                    room
                });
            }
            return;
        }
        client.emit('muc:available', pres);
        const isJoin = client.joiningRooms.has(room) || !client.joinedRooms.has(room);
        if (isSelf) {
            client.joinedRooms.set(room, JID.getResource(pres.from));
            if (isJoin) {
                client.joiningRooms.delete(room);
                client.emit('muc:join', pres);
            }
        }
    });
    client.joinRoom = (room_1, nick_1, ...args_1) => __awaiter(this, [room_1, nick_1, ...args_1], void 0, function* (room, nick, opts = {}) {
        room = JID.toBare(room);
        client.joiningRooms.set(room, nick || '');
        if (!nick) {
            try {
                nick = yield client.getReservedNick(room);
                client.joiningRooms.set(room, nick);
            }
            catch (err) {
                throw new Error('Room nick required');
            }
        }
        return new Promise((resolve, reject) => {
            function joined(pres) {
                if (JID.equalBare(pres.from, room)) {
                    client.off('muc:join', joined);
                    client.off('muc:failed', failed);
                    resolve(pres);
                }
            }
            function failed(pres) {
                if (JID.equalBare(pres.from, room)) {
                    client.off('muc:join', joined);
                    client.off('muc:failed', failed);
                    reject(pres);
                }
            }
            client.on('muc:join', joined);
            client.on('muc:failed', failed);
            client.sendPresence(Object.assign(Object.assign({}, opts), { muc: Object.assign(Object.assign({}, opts.muc), { type: 'join' }), to: JID.createFull(room, nick) }));
        });
    });
    client.leaveRoom = (room, nick, opts = {}) => {
        room = JID.toBare(room);
        nick = nick || client.joinedRooms.get(room);
        client.leavingRooms.set(room, nick);
        return new Promise((resolve, reject) => {
            const id = opts.id || uuid();
            const allowed = JID.allowedResponders(room);
            function leave(pres) {
                if (JID.equalBare(pres.from, room)) {
                    client.off('muc:leave', leave);
                    client.off('presence:error', leaveError);
                    resolve(pres);
                }
            }
            function leaveError(pres) {
                if (pres.id === id && allowed.has(pres.from)) {
                    if (!client.joinedRooms.has(room)) {
                        client.leavingRooms.delete(room);
                    }
                    client.off('muc:leave', leave);
                    client.off('presence:error', leaveError);
                    reject(pres);
                }
            }
            client.on('muc:leave', leave);
            client.on('presence:error', leaveError);
            client.sendPresence(Object.assign(Object.assign({}, opts), { id, to: JID.createFull(room, nick), type: 'unavailable' }));
        });
    };
    client.ban = (room, occupantRealJID, reason) => {
        return client.setRoomAffiliation(room, occupantRealJID, 'outcast', reason);
    };
    client.kick = (room, nick, reason) => {
        return client.setRoomRole(room, nick, 'none', reason);
    };
    client.invite = (room, opts = []) => {
        if (!Array.isArray(opts)) {
            opts = [opts];
        }
        client.sendMessage({
            muc: {
                invite: opts,
                type: 'info'
            },
            to: room
        });
    };
    client.directInvite = (room, to, opts = {}) => {
        client.sendMessage({
            muc: Object.assign(Object.assign({}, opts), { jid: room, type: 'direct-invite' }),
            to
        });
    };
    client.declineInvite = (room, sender, reason) => {
        client.sendMessage({
            muc: {
                decline: {
                    reason,
                    to: sender
                },
                type: 'info'
            },
            to: room
        });
    };
    client.changeNick = (room, nick) => {
        const id = uuid();
        const newJID = JID.createFull(room, nick);
        const allowed = JID.allowedResponders(room);
        return new Promise((resolve, reject) => {
            function success(pres) {
                if (!allowed.has(JID.toBare(pres.from))) {
                    return;
                }
                if (!pres.muc.statusCodes ||
                    !pres.muc.statusCodes.includes(MUCStatusCode.SelfPresence)) {
                    return;
                }
                client.off('muc:available', success);
                client.off(`presence:id:${id}`, errorOrNoChange);
                resolve(pres);
            }
            function errorOrNoChange(pres) {
                if (!allowed.has(JID.toBare(pres.from)) || pres.id !== id) {
                    return;
                }
                client.off('muc:available', success);
                client.off(`presence:id:${id}`, errorOrNoChange);
                if (pres.type === 'error') {
                    reject(pres);
                }
                else {
                    resolve(pres);
                }
            }
            client.on('muc:available', success);
            client.on(`presence:id:${id}`, errorOrNoChange);
            client.sendPresence({
                id,
                to: newJID
            });
        });
    };
    client.setSubject = (room, subject) => {
        client.sendMessage({
            subject,
            to: room,
            type: 'groupchat'
        });
    };
    client.getReservedNick = (room) => __awaiter(this, void 0, void 0, function* () {
        try {
            const info = yield client.getDiscoInfo(room, 'x-roomuser-item');
            const identity = info.identities[0];
            if (identity.name) {
                return identity.name;
            }
            else {
                throw new Error('No nickname reserved');
            }
        }
        catch (err) {
            throw new Error('No nickname reserved');
        }
    });
    client.requestRoomVoice = (room) => {
        client.sendMessage({
            forms: [
                {
                    fields: [
                        {
                            name: 'FORM_TYPE',
                            type: 'hidden',
                            value: 'http://jabber.org/protocol/muc#request'
                        },
                        {
                            name: 'muc#role',
                            type: 'text-single',
                            value: 'participant'
                        }
                    ],
                    type: 'submit'
                }
            ],
            to: room
        });
    };
    client.setRoomAffiliation = (room, occupantRealJID, affiliation, reason) => {
        return client.sendIQ({
            muc: {
                type: 'user-list',
                users: [
                    {
                        affiliation,
                        jid: occupantRealJID,
                        reason
                    }
                ]
            },
            to: room,
            type: 'set'
        });
    };
    client.setRoomRole = (room, nick, role, reason) => {
        return client.sendIQ({
            muc: {
                type: 'user-list',
                users: [
                    {
                        nick,
                        reason,
                        role
                    }
                ]
            },
            to: room,
            type: 'set'
        });
    };
    client.getRoomMembers = (room, opts = { affiliation: 'member' }) => {
        return client.sendIQ({
            muc: {
                type: 'user-list',
                users: [opts]
            },
            to: room,
            type: 'get'
        });
    };
    client.getRoomConfig = (room) => __awaiter(this, void 0, void 0, function* () {
        const result = yield client.sendIQ({
            muc: {
                type: 'configure'
            },
            to: room,
            type: 'get'
        });
        if (!result.muc.form) {
            throw new Error('No configuration form returned');
        }
        return result.muc.form;
    });
    client.configureRoom = (room, form = {}) => {
        return client.sendIQ({
            muc: {
                form: Object.assign(Object.assign({}, form), { type: 'submit' }),
                type: 'configure'
            },
            to: room,
            type: 'set'
        });
    };
    client.destroyRoom = (room, opts = {}) => {
        return client.sendIQ({
            muc: {
                destroy: opts,
                type: 'configure'
            },
            to: room,
            type: 'set'
        });
    };
    client.getUniqueRoomName = function (mucHost) {
        return __awaiter(this, void 0, void 0, function* () {
            const result = yield this.sendIQ({
                muc: {
                    type: 'unique'
                },
                to: mucHost,
                type: 'get'
            });
            if (!result.muc.name) {
                throw new Error('No unique name returned');
            }
            return result.muc.name;
        });
    };
    client.getBookmarks = () => __awaiter(this, void 0, void 0, function* () {
        const res = yield client.getPrivateData('bookmarks');
        if (!res || !res.rooms) {
            return [];
        }
        return res.rooms;
    });
    client.setBookmarks = (bookmarks) => {
        return client.setPrivateData('bookmarks', {
            rooms: bookmarks
        });
    };
    client.addBookmark = (bookmark) => __awaiter(this, void 0, void 0, function* () {
        const mucs = yield client.getBookmarks();
        const updated = [];
        let updatedExisting = false;
        for (const muc of mucs) {
            if (JID.equalBare(muc.jid, bookmark.jid)) {
                updated.push(Object.assign(Object.assign({}, muc), bookmark));
                updatedExisting = true;
            }
            else {
                updated.push(muc);
            }
        }
        if (!updatedExisting) {
            updated.push(bookmark);
        }
        return client.setBookmarks(updated);
    });
    client.removeBookmark = (jid) => __awaiter(this, void 0, void 0, function* () {
        const existingMucs = yield client.getBookmarks();
        const updated = existingMucs.filter(muc => {
            return !JID.equalBare(muc.jid, jid);
        });
        return client.setBookmarks(updated);
    });
}
