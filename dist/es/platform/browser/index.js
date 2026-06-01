/* istanbul ignore file */
import { Buffer } from './buffer';
import createHash, { Hash } from './crypto/createHash';
import Hmac from './crypto/Hmac';
import { Readable, Writable, Transform, PassThrough, Duplex } from './stream';
export function randomBytes(size) {
    const rawBytes = new Uint8Array(size);
    if (size > 0) {
        (globalThis.crypto || globalThis.msCrypto).getRandomValues(rawBytes);
    }
    return Buffer.from(rawBytes.buffer);
}
export function getHashes() {
    return ['sha-1', 'sha-256', 'sha-512', 'md5'];
}
export function createHmac(alg, key) {
    return new Hmac(alg.toLowerCase(), key);
}
export function createResolver() {
    return undefined;
}
const nativeFetch = globalThis.fetch.bind(globalThis);
const nativeWS = globalThis.WebSocket;
const nativeRTCPeerConnection = globalThis
    .RTCPeerConnection;
export const name = 'browser';
export { Buffer, createHash, Hash, Hmac, nativeFetch as fetch, nativeRTCPeerConnection as RTCPeerConnection, nativeWS as WebSocket, Readable, Writable, Transform, Duplex, PassThrough };
