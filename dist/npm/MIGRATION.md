# stanza.io Migration Guide
## omemo-fix-subscription (v9) → upstream-v12-with-omemo (v12)

Complete reference for migrating a consumer project. Every entry is verified against
actual source code of both branches.

---

## 1. Package Identity

| | v9 (`omemo-fix-subscription`) | v12 (`upstream-v12-with-omemo`) |
|---|---|---|
| npm name | `stanza.io` | `stanza` |
| version | `9.1.0` | `12.22.1` |
| main entry | `index.js` (raw JS source) | `dist/cjs/index.js` (compiled) |
| language | JavaScript | TypeScript (type declarations included) |

```ts
// OLD
import * as Stanza from 'stanza.io';
const { OmemoClient, OmemoStorage, OmemoUtils } = require('stanza.io/lib/plugins/omemo');

// NEW
import * as Stanza from 'stanza';
import { OmemoClient, OmemoStorage, OmemoUtils } from 'stanza/dist/cjs/plugins/omemo';
```

---

## 2. Top-Level Exports

### Kept
| Export | Notes |
|---|---|
| `createClient(opts)` | Same call signature |
| `Client` | Now a class, same name |
| `VERSION` | Now a real semver string, not `'__STANZAIO_VERSION__'` |

### Changed
| v9 | v12 | Notes |
|---|---|---|
| `Stanza.JID` — a **class constructor** | `Stanza.JID` — a **utility module** | `new JID(str)` is gone — see §8 |
| `Stanza.Omemo` | Not top-level exported | Import from `stanza/dist/cjs/plugins/omemo` |
| `Stanza.Hints` | Not top-level exported | Plugin loaded automatically |

### New in v12
| Export | Purpose |
|---|---|
| `Stanza.Constants` | Error codes, stream conditions |
| `Stanza.Namespaces` | All namespace strings (`NS_OMEMO_1`, `NS_PUBSUB`, etc.) |
| `Stanza.Stanzas` | All protocol types (Message, IQ, Presence, …) |
| `Stanza.JXT` | jxt registry and parser |
| `Stanza.Utils` | Internal utilities |
| `Stanza.Platform` | Browser vs Node detection |
| `Stanza.RSM` | Result Set Management helpers |
| `Stanza.RTT` | Real-Time Text helpers |
| `Stanza.DataForms` | Data forms helpers |
| `Stanza.Jingle` | Jingle session management |
| `Stanza.SASL` | SASL mechanism factory |

---

## 3. Configuration

```ts
// v9 config keys
{
    jid: 'user@domain',           // jid was parsed to JID object internally
    password: 'secret',
    wsURL: 'wss://...',           // WebSocket URL
    boshURL: 'https://...',       // BOSH URL
    transports: ['websocket'],    // array of strings
    sasl: ['scram-sha-1', 'plain'],
    timeout: 15,                  // IQ timeout in seconds
    useStreamManagement: true,
}

// v12 config keys
{
    jid: 'user@domain',           // stays a plain string throughout
    password: 'secret',
    transports: {                 // NOW an object, not array
        websocket: 'wss://...',   // string = explicit URL
        bosh: false,              // false = disable transport
    },
    // OR: pass true to let library auto-discover endpoints
    transports: { websocket: true },
    transportPreferenceOrder: ['websocket', 'bosh'],  // NEW
    sasl: ['SCRAM-SHA-1', 'PLAIN'],  // mechanism names may differ
    timeout: 15,                  // IQ timeout in seconds — same
    useStreamManagement: true,    // same
    allowResumption: true,        // NEW — enable SM resume on reconnect (default: true)
    autoReconnect: false,         // NEW — built-in reconnect (default: false)
    maxReconnectBackoff: 32,      // NEW — max backoff seconds (default: 32)
    lang: 'en',                   // NEW
    acceptLanguages: ['en'],      // NEW
    server: 'domain.com',         // NEW — override server domain
    resource: 'myapp',            // NEW — request specific resource
}
```

> ⚠️ `wsURL` and `boshURL` are **gone**. Pass URLs via the `transports` object:
> ```ts
> transports: { websocket: 'wss://domain:5443/ws', bosh: false }
> ```

---

## 4. Client Methods

### `connect()`

```ts
// v9 — pass opts each time
client.connect(opts);
client.connect(opts, { name: 'websocket', url: 'wss://...' });

// v12 — opts stored at createClient time; connect() uses stored config
client.connect();
// Can also pass additional opts to merge before connecting:
client.connect({ jid: 'other@domain' });
```

### `disconnect()`

```ts
// v9
client.disconnect();        // graceful (sends stream close)
client.disconnect(true);    // force (skips stream close — also emits 'disconnected' TWICE, a bug)

// v12
client.disconnect();        // always graceful + automatic 1-second hard-timeout fallback
                            // force parameter REMOVED — no longer needed
```

> ⚠️ Remove all `client.disconnect(true)` calls.

### `sendIq()` → `sendIQ()`

```ts
// v9 — lowercase 'q', supports callback
const result = await client.sendIq({ type: 'get', to: jid, ... });
client.sendIq({ ... }, (err, result) => { ... });   // callback form

// v12 — uppercase 'Q', promise only
const result = await client.sendIQ({ type: 'get', to: jid, ... });
// callback form REMOVED
```

### `sendMessage()` / `sendPresence()` — unchanged

```ts
// Both v9 and v12 — same signature, same return value (ID string)
const id = client.sendMessage({ to, body, type: 'chat' });
const id = client.sendPresence({ show: 'away' });
```

### `getCredentials()`

```ts
// v9 — callback
client.getCredentials((err, creds) => { ... });

// v12 — async
const creds = await client.getCredentials();
```

### New methods in v12

```ts
// Convenience IQ reply helpers — no equivalent in v9
client.sendIQResult(originalIQ, { ...replyData });
client.sendIQError(originalIQ, { error: { condition: 'item-not-found' } });

// Config update at runtime
client.updateConfig({ timeout: 30 });
```

### Removed in v12

| v9 method | Reason removed |
|---|---|
| `client.discoverBindings(server, cb)` | Internal to `connect()` now |
| `client.releaseGroup(group)` | WildEmitter concept — replaced by EventEmitter |

---

## 5. Events

### Core events — mapping

| v9 | v12 | Notes |
|---|---|---|
| `'disconnected'` | `'disconnected'` | ✅ Same name. In v12 fires **after** queue drain + SM hibernate, so slightly later but guaranteed single emit |
| `'auth:success'` | *(removed)* | Use `'session:started'` instead |
| `'session:started'` | `'session:started'` | ✅ Same |
| `'session:end'` | `'session:end'` | ✅ Same |
| `'stream:start'` | `'stream:start'` | ✅ Same |
| `'stream:end'` | `'stream:end'` | ✅ Same |
| `'stream:error'` | `'stream:error'` | ✅ Same |
| `'stream:data'` | `'stream:data'` | ✅ Same |
| `'stanza'` | `'stanza'` | ✅ Same |
| `'message'` | `'message'` | ✅ Same |
| `'chat'` | `'chat'` | ✅ Same |
| `'groupchat'` | `'groupchat'` | ✅ Same |
| `'message:error'` | `'message:error'` | ✅ Same |
| `'message:sent'` | `'message:sent'` | ✅ Same name — **payload changed** (see below) |
| `'presence'` | `'presence'` | ✅ Same |
| `'available'` | `'available'` | ✅ Same |
| `'unavailable'` | `'unavailable'` | ✅ Same |
| `'subscribe'` | `'subscribe'` | ✅ Same |
| `'subscribed'` | `'subscribed'` | ✅ Same |
| `'unsubscribe'` | `'unsubscribe'` | ✅ Same |
| `'unsubscribed'` | `'unsubscribed'` | ✅ Same |
| `'presence:error'` | `'presence:error'` | ✅ Same |
| `'raw:incoming'` | `'raw:incoming'` | ✅ Same |
| `'raw:outgoing'` | `'raw:outgoing'` | ✅ Same |
| `'iq:get:*'` / `'iq:set:*'` | `'iq:get:*'` / `'iq:set:*'` | ✅ Same pattern |
| `'id:*'` | *(removed)* | Use `'iq:id:*'` or `'message:id:*'` |
| *(not present)* | `'connected'` | NEW — TCP connected (before stream open) |
| *(not present)* | `'session:bound'` | NEW — resource bound |
| *(not present)* | `'session:prebind'` | NEW — pre-bind state |
| *(not present)* | `'stanza:acked'` | NEW — SM ack received for any stanza type |
| *(not present)* | `'stanza:failed'` | NEW — SM gave up on any stanza type |
| *(not present)* | `'stanza:hibernated'` | NEW — stanza buffered during disconnect |
| *(not present)* | `'message:acked'` | NEW — SM ack received for a message |
| *(not present)* | `'message:failed'` | NEW — SM gave up on a message |
| *(not present)* | `'message:hibernated'` | NEW — message buffered during disconnect |
| *(not present)* | `'message:retry'` | NEW — message being replayed after reconnect |

### `'message:sent'` payload change

```ts
// v9 — emitted with one argument: the message JSON object
client.on('message:sent', (msg) => {
    console.log(msg.id, msg.body);
});

// v12 — emitted with TWO arguments: message + viaCarbon boolean
client.on('message:sent', (msg, viaCarbon) => {
    console.log(msg.id, msg.body, viaCarbon);
});
```

### `'auth:success'` → `'session:started'`

```ts
// v9
client.on('auth:success', () => { /* authenticated */ });

// v12 — use session:started (was also available in v9)
client.on('session:started', () => { /* session ready */ });
```

### `'disconnected'` — same name, better timing

```ts
// Both v9 and v12 — same listener
client.on('disconnected', () => {
    scheduleReconnect();
});
// In v12 this fires after queue drain + SM hibernation, so it is safe
// to start reconnecting immediately in this handler.
```

> **Note:** `'--transport-disconnected'` is an **internal** event used inside Client.ts.
> Do not listen to it in application code.

---

## 6. PubSub Events

### Event names

| v9 | v12 | Notes |
|---|---|---|
| `'pubsub:event'` | `'pubsub:event'` | ✅ Same — **payload structure changed** (see below) |
| `'pubsubEvent'` | *(removed)* | Was an alias — use `'pubsub:event'` only |
| `'pubsub:published'` | `'pubsub:published'` | ✅ Same |
| `'pubsub:retracted'` | `'pubsub:retracted'` | ✅ Same |
| `'pubsub:purged'` | `'pubsub:purged'` | ✅ Same |
| `'pubsub:deleted'` | `'pubsub:deleted'` | ✅ Same |
| `'pubsub:subscription'` | `'pubsub:subscription'` | ✅ Same |
| `'pubsub:config'` | `'pubsub:config'` | ✅ Same |
| `'pubsub:affiliation'` | `'pubsub:affiliations'` | ⚠️ **Renamed** — added `'s'` |

### `'pubsub:event'` payload structure — BREAKING CHANGE

The message object structure changed completely because v12 uses a different XML parsing layer.

```ts
// v9 — payload lives under msg.event
client.on('pubsub:event', (msg) => {
    // Check if it is an items event
    if (msg.event.updated) {
        const node      = msg.event.updated.node;        // node name
        const published = msg.event.updated.published;   // array of items
        const retracted = msg.event.updated.retracted;   // array of retracted IDs
    }
    if (msg.event.purged)             { /* node purged */ }
    if (msg.event.deleted)            { /* node deleted */ }
    if (msg.event.subscriptionChanged){ /* subscription changed */ }
    if (msg.event.configurationChanged){ /* config changed */ }
});

// v12 — payload lives under msg.pubsub
client.on('pubsub:event', (msg) => {
    // Check if it is an items event
    if (msg.pubsub.items) {
        const node      = msg.pubsub.items.node;         // node name
        const published = msg.pubsub.items.published;    // array of items
        const retracted = msg.pubsub.items.retracted;    // array of retracted IDs
    }
    // eventType indicates other event kinds
    if (msg.pubsub.eventType === 'purge')        { /* node purged */ }
    if (msg.pubsub.eventType === 'delete')       { /* node deleted */ }
    if (msg.pubsub.eventType === 'subscription') { /* subscription changed */ }
    if (msg.pubsub.eventType === 'configuration'){ /* config changed */ }
});
```

### Full path comparison for OMEMO device list events

```ts
// v9 — path to OMEMO device list in pubsub:event
msg.event.updated.node                         // === 'urn:xmpp:omemo:1:devices'
msg.event.updated.published[0].deviceList.devices  // OmemoDeviceInfo[]
msg.from                                       // string (already bare in practice)

// v12 — path to OMEMO device list in pubsub:event
msg.pubsub.items.node                          // === 'urn:xmpp:omemo:1:devices'
msg.pubsub.items.published[0].deviceList.devices   // OmemoDeviceInfo[]
msg.from                                       // string (use JID.toBare() to ensure bare)
```

---

## 7. PubSub Methods

All methods are now **promise-only** — callback parameter removed.

| Method | v9 signature | v12 signature |
|---|---|---|
| `subscribeToNode` | `(jid, opts, cb?)` | `(jid, opts): Promise<PubsubSubscriptionWithOptions>` |
| `unsubscribeFromNode` | `(jid, opts, cb?)` | `(jid, opts): Promise<PubsubSubscription>` |
| `publish` | `(jid, node, item, cb?)` | `(jid, node, item, id?): Promise<IQ>` |
| `getItem` | `(jid, node, id, cb?)` | `(jid, node, id): Promise<PubsubItem<T>>` |
| `getItems` | `(jid, node, opts, cb?)` | `(jid, node, opts?): Promise<PubsubFetchResult<T>>` |
| `retract` | `(jid, node, id, notify, cb?)` | `(jid, node, id, notify): Promise<IQ>` |
| `purgeNode` | `(jid, node, cb?)` | `(jid, node): Promise<IQ>` |
| `deleteNode` | `(jid, node, cb?)` | `(jid, node): Promise<IQ>` |
| `createNode` | `(jid, node, config, cb?)` | `(jid, node?, config?): Promise<PubsubCreate>` |
| `getSubscriptions` | `(jid, opts, cb?)` | `(jid, opts?): Promise<PubsubSubscriptions>` |
| `getAffiliations` | `(jid, opts, cb?)` | `(jid, node?): Promise<IQ>` |
| `getNodeSubscribers` | `(jid, node, opts, cb?)` | `(jid, node, opts?): Promise<IQ>` |
| `updateNodeSubscriptions` | `(jid, node, delta, cb?)` | `(jid, node, delta): Promise<IQ>` |
| `getNodeAffiliations` | `(jid, node, cb?)` | `(jid, node): Promise<PubsubAffiliations>` |
| `updateNodeAffiliations` | `(jid, node, delta, cb?)` | `(jid, node, items): Promise<IQ>` |
| `publishOmemoDevice` | `(jid, node, item, cb?)` | `(jid, node, item): Promise<any>` |
| `publishOmemoBundle` | `(jid, node, item, cb?)` | `(jid, node, item): Promise<any>` |
| `getOmemoItems` | `(jid, node, opts, cb?)` | `(jid, node, opts?): Promise<any>` |

**New in v12 — no equivalent in v9:**

| Method | Signature |
|---|---|
| `getNodeConfig` | `(jid, node): Promise<DataForm>` |
| `getDefaultNodeConfig` | `(jid): Promise<DataForm>` |
| `configureNode` | `(jid, node, config): Promise<IQ>` |
| `getDefaultSubscriptionOptions` | `(jid): Promise<DataForm>` |

---

## 8. OMEMO

### 8.1 Import path

```ts
// v9
const { OmemoClient, OmemoStorage, OmemoUtils } = require('stanza.io/lib/plugins/omemo');

// v12
import { OmemoClient, OmemoStorage, OmemoUtils, OmemoDeviceInfo } from 'stanza/dist/cjs/plugins/omemo';
```

### 8.2 `client.createOmemo(store)` — unchanged

```ts
// Both v9 and v12
client.createOmemo(myStore);
// Result: client.omemo is now an OmemoClient instance
```

### 8.3 `OmemoStorage` — sync → async (BREAKING)

Every method that returned a value synchronously now returns a `Promise`.
Your concrete storage implementation **must** be updated to return Promises.

| Method | v9 return type | v12 return type |
|---|---|---|
| `storeDevices(jid, devices)` | `void` | `Promise<void>` |
| `getDevices(jid)` | `any[]` | `Promise<OmemoDeviceInfo[]>` |
| `hasDevices(jid)` | **did not exist** | `Promise<boolean>` ← **must add** |
| `storeWhisper(address, id, whisper)` | `void` | `Promise<void>` |
| `getWhisper(address, id)` | `any` | `Promise<ArrayBuffer \| null>` |
| `getLocalRegistrationId()` | `number` | `Promise<number>` |
| `storeLocalRegistration(device)` | `void` | `Promise<void>` |
| `getIdentityKeyPair()` | `object` | `Promise<{ pubKey: ArrayBuffer; privKey: ArrayBuffer } \| null>` |
| `storeIdentityKeyPair(keyPair)` | `void` | `Promise<void>` |
| `isTrustedIdentity(identity, identityKey, direction)` | `boolean` | `Promise<boolean>` |
| `loadIdentityKey(identity)` | `ArrayBuffer` | `Promise<ArrayBuffer \| null>` |
| `saveIdentity(identity, identityKey)` | `boolean` | `Promise<boolean>` |
| `loadPreKey(keyId)` | `object` | `Promise<{ pubKey: ArrayBuffer; privKey: ArrayBuffer } \| null>` |
| `storePreKey(keyId, preKey)` | `void` | `Promise<void>` |
| `removePreKey(keyId)` | `void` | `Promise<void>` |
| `loadSignedPreKey(keyId)` | `object` | `Promise<{ pubKey: ArrayBuffer; privKey: ArrayBuffer } \| null>` |
| `storeSignedPreKey(keyId, signedPreKey)` | `void` | `Promise<void>` |
| `removeSignedPreKey(keyId)` | `void` | `Promise<void>` |
| `loadSession(identifier)` | `string` | `Promise<string \| null>` |
| `storeSession(identifier, session)` | `void` | `Promise<void>` |
| `removeSession(identifier)` | `void` | `Promise<void>` |
| `removeAllSessions(prefix)` | `void` | `Promise<void>` |
| `wrapFunction(name, func)` | `void` | `void` (unchanged) |

`Direction` static — unchanged:
```ts
OmemoStorage.Direction.SENDING   // 1
OmemoStorage.Direction.RECEIVING // 2
```

### 8.4 `OmemoDeviceInfo` — now a typed interface

```ts
// v9 — plain object, no type definition
{ id: number, label?: string }

// v12 — exported TypeScript interface
export interface OmemoDeviceInfo {
    id: number;
    label?: string;
}
```

### 8.5 `OmemoUtils` — unchanged

```ts
OmemoUtils.arrayBufferToBase64String(arrayBuffer)  // same
OmemoUtils.base64StringToArrayBuffer(str)          // same
```

### 8.6 `OmemoClient` methods — changes

| Method | Change |
|---|---|
| `start(platform)` | ✅ Unchanged |
| `getAnnouncedDevices(jid?, force?)` | ✅ Unchanged. Return type now `Promise<OmemoDeviceInfo[]>` (was untyped) |
| `getDeviceKeyBundle(recipient, registrationId)` | ✅ Unchanged |
| `announceDevices(devices, newRegistrationId?)` | ✅ Unchanged |
| `announce(device, identityKeyPair, isNew, removePreKey?, isForceGet?)` | ✅ Unchanged |
| `refillPreKeys(keyBundle, removePreKey?)` | ✅ Unchanged |
| `getRecipientSessions(isMUC, recipient)` | ✅ Unchanged |
| `decryptMessage(message)` | ✅ Unchanged |
| `decryptWhisper(message, key)` | ✅ Unchanged |
| `decryptData(...)` | ⚠️ **Signature changed** — see below |
| `sendMessage(rawMessage, members?, hint?)` | ✅ Unchanged |
| `createMessage(isMUC, plaintext, recipients)` | ✅ Unchanged |
| `createHeader(isMUC, key, auth, iv, recipients)` | ✅ Unchanged |

### `decryptData` signature change

```ts
// v9 — 3 parameters, subtleCrypto taken from window.crypto.subtle internally
async decryptData(keyData, iv, data)

// v12 — 4 parameters, subtleCrypto passed explicitly
async decryptData(subtleCrypto, keyData, iv, data)
```

> If you call `decryptData` directly, add `window.crypto.subtle` as the first argument.
> `decryptMessage` handles this internally — no change needed there.

### 8.7 OMEMO node names and namespace — unchanged

```ts
'urn:xmpp:omemo:1'          // NS_OMEMO_1
'urn:xmpp:omemo:1:devices'  // NS_OMEMO_1_DEVICES
'urn:xmpp:omemo:1:bundles'  // NS_OMEMO_1_BUNDLES
```

---

## 9. JID — Class → Utility Module

```ts
// v9 — JID is a class from 'xmpp-jid'
const { JID } = require('stanza.io');
const jid = new JID('user@domain/resource');
jid.bare       // 'user@domain'
jid.local      // 'user'
jid.domain     // 'domain'
jid.resource   // 'resource'
jid.full       // 'user@domain/resource'

// v12 — JID is a module of utility functions (plain strings everywhere)
import { JID } from 'stanza';
JID.toBare('user@domain/resource')      // 'user@domain'
JID.getLocal('user@domain/resource')    // 'user'
JID.getDomain('user@domain/resource')   // 'domain'
JID.getResource('user@domain/resource') // 'resource'
JID.parse('user@domain/resource')       // { local, domain, resource }
JID.equal(jid1, jid2)                   // boolean

// client.jid is now a plain string (was a JID object in v9)
typeof client.jid === 'string'  // always true in v12
```

> ⚠️ Remove all `new JID(str)` usages. Replace `.bare`, `.local`, `.domain`, `.resource`
> property accesses with the corresponding utility functions.

---

## 10. Stream Management

| Behaviour | v9 | v12 |
|---|---|---|
| On disconnect | SM session cleared (stanzas lost) | SM hibernates — unacked stanzas buffered |
| On reconnect | Full re-auth, no replay | Attempts SM resume, replays buffered stanzas |
| Unacked stanza fate | Lost | Surfaced via `'stanza:hibernated'` / `'message:hibernated'` |
| Accessing SM | `client.sm` | `client.sm` (same) |
| Invalidating manually | `client.sm.failed()` | `client.sm.failed()` (same, rarely needed) |

---

## 11. Plugin Registration

```ts
// v9 — plugins loaded inside createClient automatically
const client = Stanza.createClient(opts);

// v12 — same, OMEMO plugin is now included automatically
const client = Stanza.createClient(opts);

// Manual registration (if using Client directly):
import { Client } from 'stanza';
import Plugins from 'stanza/dist/cjs/plugins';
const client = new Client(opts);
client.use(Plugins);
```

---

## 12. Namespace Constants

Import from `Stanza.Namespaces` instead of hardcoding strings:

```ts
import { Namespaces } from 'stanza';

Namespaces.NS_OMEMO_1          // 'urn:xmpp:omemo:1'
Namespaces.NS_OMEMO_1_DEVICES  // 'urn:xmpp:omemo:1:devices'
Namespaces.NS_OMEMO_1_BUNDLES  // 'urn:xmpp:omemo:1:bundles'
Namespaces.NS_EME_0            // 'urn:xmpp:eme:0'
Namespaces.NS_PUBSUB           // 'http://jabber.org/protocol/pubsub'
Namespaces.NS_CSI_0            // 'urn:xmpp:csi:0'
```

---

## 13. Migration Checklist

### Must fix (will break at runtime)

- [ ] Change package name `stanza.io` → `stanza` in all imports
- [ ] Remove `new JID(str)` — replace with `JID.parse()`, `JID.toBare()`, `JID.getLocal()`, `JID.getDomain()`, `JID.getResource()`
- [ ] `client.jid` is now a plain `string` — remove any `.bare`, `.local`, `.domain` property accesses on it, use `JID.toBare(client.jid)` etc.
- [ ] `sendIq` → `sendIQ` (capital Q) — remove all callbacks, convert to `await`
- [ ] Remove `client.disconnect(true)` — use `client.disconnect()` only
- [ ] Replace `wsURL`/`boshURL` config keys with `transports: { websocket: 'wss://...' }`
- [ ] `transports` config is now an **object** not an array — `['websocket']` → `{ websocket: true }`
- [ ] Replace `'auth:success'` listener with `'session:started'`
- [ ] Remove `'pubsubEvent'` alias listeners — use `'pubsub:event'` only
- [ ] Rename `'pubsub:affiliation'` → `'pubsub:affiliations'` (added `'s'`)
- [ ] Update all `'pubsub:event'` handlers: `msg.event.updated.*` → `msg.pubsub.items.*`
- [ ] Make every `OmemoStorage` method `async` / return `Promise<T>`
- [ ] Add `hasDevices(jid): Promise<boolean>` to your `OmemoStorage` implementation
- [ ] Update `'message:sent'` listener to accept two args: `(msg, viaCarbon)`
- [ ] Remove `client.discoverBindings()` calls — discovery is internal to `connect()` now

### Recommended

- [ ] Add `allowResumption: true` to config (already default, but make it explicit)
- [ ] Listen for `'message:hibernated'` / `'stanza:hibernated'` to track buffered messages
- [ ] Listen for `'message:acked'` / `'message:failed'` for delivery confirmation
- [ ] Use `Stanza.Namespaces.NS_OMEMO_1` etc. instead of hardcoded namespace strings
