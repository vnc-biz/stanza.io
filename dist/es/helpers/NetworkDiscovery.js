var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { createResolver, fetch } from '../platform';
import { shuffle, promiseAny } from '../Utils';
import { Registry, parse } from '../jxt';
import XRDSchema from '../protocol/xrd';
export default class NetworkDiscovery {
    constructor() {
        this.hostMetaCache = new Map();
        this.hostMetaTTL = 30000;
        this.resolver = createResolver();
        this.registry = new Registry();
        this.registry.define(XRDSchema);
    }
    getHostMeta(domain) {
        return __awaiter(this, void 0, void 0, function* () {
            const cached = this.hostMetaCache.get(domain);
            if (cached) {
                if (cached.created + this.hostMetaTTL < Date.now()) {
                    return cached.hostmeta;
                }
                else {
                    this.hostMetaCache.delete(domain);
                }
            }
            const hostmeta = promiseAny([
                fetch(`https://${domain}/.well-known/host-meta.json`).then((res) => __awaiter(this, void 0, void 0, function* () {
                    if (!res.ok) {
                        throw new Error('could-not-fetch-json');
                    }
                    return res.json();
                })),
                fetch(`https://${domain}/.well-known/host-meta`).then((res) => __awaiter(this, void 0, void 0, function* () {
                    if (!res.ok) {
                        throw new Error('could-not-fetch-xml');
                    }
                    const data = yield res.text();
                    const xml = parse(data);
                    if (xml) {
                        return this.registry.import(xml);
                    }
                    else {
                        throw new Error('could-not-import-xml');
                    }
                }))
            ]);
            this.hostMetaCache.set(domain, { created: Date.now(), hostmeta });
            hostmeta.catch(() => {
                this.hostMetaCache.delete(domain);
            });
            return hostmeta;
        });
    }
    resolveTXT(domain) {
        return __awaiter(this, void 0, void 0, function* () {
            var _a, _b;
            return (_b = (_a = this.resolver) === null || _a === void 0 ? void 0 : _a.resolveTxt(domain)) !== null && _b !== void 0 ? _b : [];
        });
    }
    resolve(domain_1, defaultPort_1) {
        return __awaiter(this, arguments, void 0, function* (domain, defaultPort, opts = {}) {
            if (!this.resolver) {
                return [];
            }
            let candidates = [];
            let allowFallback = true;
            if (opts.srvType) {
                const srvResults = yield this.resolveWeightedSRV(domain, opts.srvType, opts.srvTypeSecure);
                allowFallback = srvResults.allowFallback;
                candidates = srvResults.records.map(record => ({
                    host: record.name,
                    port: record.port,
                    secure: record.secure
                }));
            }
            if (allowFallback) {
                candidates.push({ host: domain, port: defaultPort });
            }
            return candidates;
        });
    }
    resolveWeightedSRV(domain, srvType, srvTypeSecure) {
        return __awaiter(this, void 0, void 0, function* () {
            const [records, secureRecords] = yield Promise.all([
                this.resolveSRV(domain, srvType),
                srvTypeSecure
                    ? this.resolveSRV(domain, srvTypeSecure, true)
                    : Promise.resolve({ records: [], allowFallback: false })
            ]);
            const allRecords = [...records.records, ...secureRecords.records];
            const priorities = new Map();
            let id = 0;
            for (const record of allRecords) {
                record.id = id++;
                record.runningSum = 0;
                if (!priorities.has(record.priority)) {
                    priorities.set(record.priority, []);
                }
                const priorityGroup = priorities.get(record.priority);
                priorityGroup.push(record);
            }
            const weightRecords = (unweightedRecords) => {
                const sorted = [];
                while (sorted.length < unweightedRecords.length) {
                    const ordered = shuffle(unweightedRecords.filter(record => record.weight === 0 && !record.used));
                    const unordered = shuffle(unweightedRecords.filter(record => {
                        return record.weight !== 0 && !record.used;
                    }));
                    let weightSum = 0;
                    for (const record of unordered) {
                        weightSum += record.weight;
                        record.runningSum = weightSum;
                        ordered.push(record);
                    }
                    const selector = Math.floor(Math.random() * (weightSum + 1));
                    for (const record of ordered) {
                        if (record.runningSum >= selector) {
                            record.used = true;
                            sorted.push(record);
                            break;
                        }
                    }
                }
                return sorted;
            };
            let sortedRecords = [];
            for (const priority of Array.from(priorities.keys()).sort((a, b) => a < b ? -1 : a > b ? 1 : 0)) {
                const priorityGroup = priorities.get(priority);
                sortedRecords = sortedRecords.concat(weightRecords(priorityGroup));
            }
            return {
                records: sortedRecords,
                allowFallback: records.allowFallback
            };
        });
    }
    resolveSRV(domain, srvType, secure) {
        return __awaiter(this, void 0, void 0, function* () {
            var _a, _b;
            try {
                const records = (_b = (yield ((_a = this.resolver) === null || _a === void 0 ? void 0 : _a.resolveSrv(`${srvType}.${domain}`)))) !== null && _b !== void 0 ? _b : [];
                if (records.length === 1 && (records[0].name === '.' || records[0].name === '')) {
                    return { records: [], allowFallback: false };
                }
                return {
                    records: records
                        .map(record => (Object.assign({ secure }, record)))
                        .filter(record => record.name !== '' && record.name !== '.'),
                    allowFallback: false
                };
            }
            catch (_c) {
                return {
                    records: [],
                    allowFallback: true
                };
            }
        });
    }
}
