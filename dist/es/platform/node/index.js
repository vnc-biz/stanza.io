/* istanbul ignore file */
import WebSocket from 'ws';
import { createHash as nodeCreateHash, createHmac as nodeCreateHmac, randomBytes as nodeRandomBytes, Hash, Hmac } from 'crypto';
import * as dns from 'dns';
import { Buffer } from 'buffer';
import { Readable, Writable, Transform, PassThrough, Duplex } from 'stream';
const ianaNames = new Map([
    ['md2', 'md2'],
    ['md5', 'md5'],
    ['sha-1', 'sha1'],
    ['sha-224', 'sha224'],
    ['sha-256', 'sha256'],
    ['sha-384', 'sha384'],
    ['sha-512', 'sha512']
]);
export function getHashes() {
    return ['sha-1', 'sha-256', 'sha-384', 'sha-512', 'md5'];
}
export function createHash(alg) {
    return nodeCreateHash(ianaNames.get(alg.toLowerCase()) || alg);
}
export function createHmac(alg, key) {
    return nodeCreateHmac(ianaNames.get(alg.toLowerCase()) || alg, key);
}
export function randomBytes(size) {
    return nodeRandomBytes(size);
}
export function createResolver(opts) {
    return new dns.promises.Resolver(opts);
}
const nativeRTCPeerConnection = undefined;
const nativeFetch = globalThis.fetch.bind(globalThis);
export const name = 'node';
export { Buffer, nativeFetch as fetch, Hash, Hmac, nativeRTCPeerConnection as RTCPeerConnection, WebSocket, Readable, Writable, Transform, Duplex, PassThrough };
