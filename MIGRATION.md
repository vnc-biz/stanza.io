# stanza.io Migration Guide
## omemo-fix-subscription (v9) → upstream-v12-with-omemo (v12)

This document is a complete reference for migrating a consumer project from the old VNC
`omemo-fix-subscription` branch to the new `upstream-v12-with-omemo` branch. Every function,
parameter, event, and type that changes is listed here.

---

## 1. Package Identity

| | v9 (old) | v12 (new) |
|---|---|---|
| **npm name** | `stanza.io` | `stanza` |
| **version** | `9.1.0` | `12.22.1` |
| **main entry** | `index.js` (source) | `dist/cjs/index.js` (compiled) |
| **language** | JavaScript | TypeScript (types included) |

**Update your import alias** in the consumer project:

```ts
// OLD
import * as Stanza from 'stanza.io';
const { OmemoClient, OmemoStorage, OmemoUtils } = require('stanza.io/lib/plugins/omemo');

// NEW
import * as Stanza from 'stanza';
import { OmemoClient, OmemoStorage, OmemoUtils } from 'stanza/dist/cjs/plugins/omemo';
// or if using TypeScript source directly:
import { OmemoClient, OmemoStorage, OmemoUtils } from 'stanza/src/plugins/omemo';
```

---

## 2. Client Creation

```ts
// OLD
const client = Stanza.createClient({ jid, password, wsURL, ... });

// NEW — same API, different config type (now typed)
const client = Stanza.createClient({ jid, password, wsURL, ... });
```

No change to `createClient()` call signature. The config object gains more optional fields
(see §9 Configuration Reference).

---

## 3. Connection & Disconnection

### `connect()`

```ts
// OLD — synchronous, no return value
client.connect(opts);

// NEW — async, opts merged into existing config (or pass nothing to use stored config)
await client.connect();          // uses config from createClient()
await client.connect(extraOpts); // merges extra opts before connecting
```

### `disconnect()`

```ts
// OLD
client.disconnect();        // graceful
client.disconnect(true);    // force (emits 'disconnected' TWICE — bug)

// NEW
client.disconnect();        // always graceful + 1s hard-timeout fallback
                            // no force parameter — always single emit
```

> ⚠️ **Remove all `client.disconnect(true)` calls.** The `force` parameter no longer exists.
> The new transport handles forced close internally via a 1-second timeout.

---

## 4. Events — Full Mapping

### 4.1 Core Client Events

| v9 Event | v12 Event | Notes |
|---|---|---|
| `'disconnected'` | `'--transport-disconnected'` | **Critical rename.** The old `'disconnected'` is still emitted but only as a pass-through from SM layer; use `'--transport-disconnected'` for reconnect logic |
| `'session:started'` | `'session:started'` | ✅ Same |
| `'session:end'` | `'session:end'` | ✅ Same |
| `'stream:start'` | `'stream:start'` | ✅ Same |
| `'stream:end'` | `'stream:end'` | ✅ Same |
| `'stream:error'` | `'stream:error'` | ✅ Same |
| `'stream:data'` | `'stream:data'` | ✅ Same |
| `'auth:success'` | *(removed)* | Use `'session:started'` instead |
| `'message'` | `'message'` | ✅ Same |
| `'chat'` | `'chat'` | ✅ Same |
| `'groupchat'` | `'groupchat'` | ✅ Same |
| `'message:error'` | `'message:error'` | ✅ Same |
| `'presence'` | `'presence'` | ✅ Same |
| `'available'` | `'available'` | ✅ Same |
| `'unavailable'` | `'unavailable'` | ✅ Same |
| `'subscribe'` | `'subscribe'` | ✅ Same |
| `'subscribed'` | `'subscribed'` | ✅ Same |
| `'unsubscribe'` | `'unsubscribe'` | ✅ Same |
| `'unsubscribed'` | `'unsubscribed'` | ✅ Same |
| `'raw:incoming'` | `'raw:incoming'` | ✅ Same |
| `'raw:outgoing'` | `'raw:outgoing'` | ✅ Same |
| *(not present)* | `'message:sent'` | NEW — fires when message leaves the queue |
| *(not present)* | `'message:acked'` | NEW — SM ack received |
| *(not present)* | `'message:failed'` | NEW — SM gave up on stanza |
| *(not present)* | `'message:hibernated'` | NEW — stanza buffered during disconnect |
| *(not present)* | `'stanza:failed'` | NEW — any stanza type failed |
| *(not present)* | `'stanza:acked'` | NEW — any stanza type acked |
| *(not present)* | `'stanza:hibernated'` | NEW — any stanza type hibernated |
| *(not present)* | `'session:bound'` | NEW — resource bound |
| *(not present)* | `'session:prebind'` | NEW — pre-bind state |
| *(not present)* | `'connected'` | NEW — transport TCP connected (before stream open) |
| *(not present)* | `'bosh:terminate'` | NEW — BOSH session ended |

### 4.2 Disconnection Event — No Change for Consumer Code

```ts
// Both v9 and v12 — keep listening to 'disconnected'
client.on('disconnected', () => {
    scheduleReconnect();
});
```

> **How it works in v12:** The transport emits the internal `'--transport-disconnected'`
> signal when the socket closes. The Client listens to that internally, drains its queues,
> calls `sm.hibernate()`, runs auto-reconnect (if `autoReconnect: true` is configured),
> and *then* emits `'disconnected'` for consumer code. So `'disconnected'` is still the
> correct event to listen to — it now fires later (after queues drain) which is safer.
>
> `'--transport-disconnected'` is an internal event — do not listen to it in your app.

### 4.3 PubSub Events

| v9 Event | v12 Event | Payload change |
|---|---|---|
| `'pubsub:event'` | `'pubsub:event'` | Structure changed (see §7) |
| `'pubsubEvent'` | *(removed)* | Use `'pubsub:event'` only |
| `'pubsub:published'` | `'pubsub:published'` | ✅ Same name |
| `'pubsub:retracted'` | `'pubsub:retracted'` | ✅ Same name |
| `'pubsub:purged'` | `'pubsub:purged'` | ✅ Same name |
| `'pubsub:deleted'` | `'pubsub:deleted'` | ✅ Same name |
| `'pubsub:subscription'` | `'pubsub:subscription'` | ✅ Same name |
| `'pubsub:config'` | `'pubsub:config'` | ✅ Same name |
| `'pubsub:affiliation'` | `'pubsub:affiliations'` | **Renamed** (added 's') |

### 4.4 PubSub Event Payload Structure Change

The `'pubsub:event'` payload structure changed — critical for OMEMO device list handling:

```ts
// OLD — msg.event.updated.published[0].deviceList.devices
client.on('pubsub:event', (msg) => {
    if (msg.event.updated.node === 'urn:xmpp:omemo:1:devices') {
        const devices = msg.event.updated.published[0].deviceList.devices;
    }
});

// NEW — msg.pubsub.items.published[0].deviceList.devices
client.on('pubsub:event', (msg) => {
    if (msg.pubsub?.items?.node === 'urn:xmpp:omemo:1:devices') {
        const devices = msg.pubsub.items.published[0]?.deviceList?.devices;
    }
});
```

| Path | v9 | v12 |
|---|---|---|
| Node name | `msg.event.updated.node` | `msg.pubsub.items.node` |
| Published items | `msg.event.updated.published` | `msg.pubsub.items.published` |
| Sender JID | `msg.from` (string) | `msg.from` (string \| JID object) |

---

## 5. IQ / Send Methods

### `sendIq()` → `sendIQ()`

```ts
// OLD — callback or promise, lowercase 'q'
client.sendIq({ type: 'get', to: jid, ... }, (err, result) => { ... });
// or
const result = await client.sendIq({ ... });

// NEW — promise only, camelCase 'IQ'
const result = await client.sendIQ({ type: 'get', to: jid, ... });
```

> ⚠️ **Remove all callbacks from sendIq calls.** Callback form is gone. Convert to `await`.

### `sendMessage()` / `sendPresence()`

```ts
// Both unchanged in signature — return the stanza ID string
const id = client.sendMessage({ to, body, type: 'chat' });
const id = client.sendPresence({ show: 'away' });
```

### New IQ helpers

```ts
// NEW — convenience helpers for IQ responses (no equivalent in v9)
client.sendIQResult(originalIQ, { ... });
client.sendIQError(originalIQ, { condition: 'item-not-found' });
```

---

## 6. PubSub Methods — Signatures

All pubsub methods are now **promise-only** (no callback parameter).

| Method | v9 Signature | v12 Signature |
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
| `getNodeAffiliations` | `(jid, node, opts, cb?)` | `(jid, node): Promise<PubsubAffiliations>` |
| `updateNodeAffiliations` | `(jid, node, delta, cb?)` | `(jid, node, items): Promise<IQ>` |
| `publishOmemoDevice` | `(jid, node, item, cb?)` | `(jid, node, item): Promise<any>` |
| `publishOmemoBundle` | `(jid, node, item, cb?)` | `(jid, node, item): Promise<any>` |
| `getOmemoItems` | `(jid, node, opts, cb?)` | `(jid, node, opts?): Promise<any>` |

**New pubsub methods in v12 (no equivalent in v9):**

| Method | Signature |
|---|---|
| `getNodeConfig` | `(jid, node): Promise<DataForm>` |
| `getDefaultNodeConfig` | `(jid): Promise<DataForm>` |
| `configureNode` | `(jid, node, config): Promise<IQ>` |
| `getDefaultSubscriptionOptions` | `(jid): Promise<DataForm>` |

---

## 7. OMEMO — Detailed Diff

### 7.1 Imports

```ts
// OLD
const { OmemoClient, OmemoStorage, OmemoUtils } = require('stanza.io/lib/plugins/omemo');

// NEW
import { OmemoClient, OmemoStorage, OmemoUtils, OmemoDeviceInfo } from 'stanza/dist/cjs/plugins/omemo';
```

### 7.2 `client.createOmemo(store)` — unchanged

```ts
// Both v9 and v12 — same call
client.createOmemo(myStore);
// Result: client.omemo is now an OmemoClient instance
```

### 7.3 `OmemoStorage` — Sync → Async

**This is the most impactful breaking change for consumers.**

Every method in `OmemoStorage` was synchronous in v9 (threw `NotImplementedError`). In v12
they are all `async`/`Promise`-returning. Your concrete storage implementation must return
Promises for all methods.

| Method | v9 Return | v12 Return |
|---|---|---|
| `storeDevices(jid, devices)` | `void` | `Promise<void>` |
| `getDevices(jid)` | `any[]` | `Promise<OmemoDeviceInfo[]>` |
| `hasDevices(jid)` | *(did not exist)* | `Promise<boolean>` **NEW — must implement** |
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

**`Direction` static property — unchanged:**
```ts
OmemoStorage.Direction.SENDING  // = 1
OmemoStorage.Direction.RECEIVING // = 2
```

**Device type change:**

```ts
// OLD — devices were plain objects {id: number, label?: string}
// NEW — typed as OmemoDeviceInfo
export interface OmemoDeviceInfo {
    id: number;
    label?: string;
}
```

### 7.4 `OmemoClient` Methods — Signatures

All methods unchanged in name and logic. Key parameter type refinements:

| Method | v9 | v12 |
|---|---|---|
| `start(platform)` | `start(platform)` | ✅ Same |
| `getAnnouncedDevices(jid?, force?)` | returns `any[]` | returns `Promise<OmemoDeviceInfo[]>` |
| `getDeviceKeyBundle(recipient, registrationId)` | `recipient` is `JID\|string` | `recipient` is `string\|any` |
| `announceDevices(devices, newRegistrationId?)` | ✅ Same | ✅ Same |
| `announce(device, identityKeyPair, isNew, removePreKey?, isForceGet?)` | ✅ Same | ✅ Same |
| `refillPreKeys(keyBundle, removePreKey?)` | ✅ Same | ✅ Same |
| `getRecipientSessions(isMUC, recipient)` | ✅ Same | ✅ Same |
| `decryptMessage(message)` | returns `Promise<ArrayBuffer\|null>` | ✅ Same |
| `decryptWhisper(message, key)` | returns `Promise<ArrayBuffer>` | ✅ Same |
| `decryptData(keyData, iv, data)` | `decryptData(keyData, iv, data)` 3 args | `decryptData(subtleCrypto, keyData, iv, data)` **4 args — subtleCrypto added as first param** |
| `sendMessage(rawMessage, members?, encryptedMsgHint?)` | ✅ Same | ✅ Same |
| `createMessage(isMUC, plaintext, recipients)` | ✅ Same | ✅ Same |
| `createHeader(isMUC, key, auth, iv, recipients)` | ✅ Same | ✅ Same |

> ⚠️ **`decryptData` signature changed.** If your code calls this directly, add `window.crypto.subtle`
> as the first argument. Internal callers (`decryptMessage`) already pass it correctly.

### 7.5 OMEMO Stanza Namespace

Both v9 and v12 use `urn:xmpp:omemo:1` — no change required in protocol payloads.

### 7.6 OMEMO PubSub Node Names

Both versions use the same node names — no change required:
- `urn:xmpp:omemo:1:devices`
- `urn:xmpp:omemo:1:bundles`

---

## 8. JID Handling

```ts
// OLD — JID was from 'xmpp-jid' package, imported via Stanza
const { JID } = require('stanza.io');
const jid = new JID('user@domain/resource');
jid.bare    // 'user@domain'
jid.local   // 'user'
jid.domain  // 'domain'
jid.resource // 'resource'

// NEW — JID is a set of utility functions, not a class
import * as JID from 'stanza/dist/cjs/JID';
// or via top-level export:
import { JID } from 'stanza';

JID.toBare('user@domain/resource')     // 'user@domain'
JID.getLocal('user@domain/resource')   // 'user'
JID.getDomain('user@domain/resource')  // 'domain'
JID.getResource('user@domain/resource') // 'resource'
JID.equal(jid1, jid2)                  // boolean comparison
JID.parse('user@domain/resource')      // { local, domain, resource }
```

> ⚠️ **`new JID(...)` is gone.** JID is no longer a class. Replace all `new JID(str)` with
> `JID.parse(str)` and property access with the utility functions above.

**In OmemoClient internally**, `message.from.bare` and `message.from.resource` from v9 messages
should be replaced with `JID.toBare(message.from)` and `JID.getResource(message.from)`.

---

## 9. Configuration Reference

```ts
// v9 — example config
{
    jid: 'user@domain',
    password: 'secret',
    wsURL: 'wss://domain:5443/ws',
    sasl: ['SCRAM-SHA-1', 'PLAIN'],
    timeout: 15,            // IQ timeout in seconds
    useStreamManagement: true,
}

// v12 — same keys still work, plus new options
{
    jid: 'user@domain',
    password: 'secret',
    wsURL: 'wss://domain:5443/ws',
    sasl: ['SCRAM-SHA-1', 'PLAIN'],
    timeout: 15,            // IQ timeout in seconds (still works)
    useStreamManagement: true,
    allowResume: true,      // attempt SM resume on reconnect (new, recommended)
    transports: ['websocket'], // restrict to WS only (new)
    lang: 'en',             // stream xml:lang (new)
    acceptLanguages: ['en'], // accepted languages (new)
}
```

---

## 10. Stream Management (SM) Changes

| Behaviour | v9 | v12 |
|---|---|---|
| On disconnect | SM session cleared / `sm.failed()` called | SM hibernates — unacked stanzas buffered |
| On reconnect | Full re-auth + re-sync | Attempts SM resume, replays buffered stanzas |
| Unacked stanza fate | Lost | Replayed via `'stanza:hibernated'` events |
| Window size | 1 (stop-and-wait) | Configurable (default varies) |
| Access | `client.sm` | `client.sm` (same) |

```ts
// v9 — manually invalidate SM (do NOT port this pattern)
client.sm.failed();

// v12 — let the library handle it; only call if you know the server session expired
client.sm.failed();  // still exists but rarely needed manually
```

---

## 11. Plugin Registration

```ts
// OLD — plugins auto-loaded inside createClient
const client = Stanza.createClient(opts);
// All plugins including omemo loaded automatically

// NEW — same behaviour, plugins auto-loaded in createClient
const client = Stanza.createClient(opts);
// All plugins including OMEMO loaded automatically via plugins/index.ts

// If you create Client manually and need to load plugins:
import { Client } from 'stanza';
import Plugins from 'stanza/dist/cjs/plugins';
const client = new Client(opts);
client.use(Plugins);
```

---

## 12. Exports — Complete Diff

### Removed from v9 top-level exports

| Export | v9 | v12 |
|---|---|---|
| `Stanza.JID` (class constructor) | `new Stanza.JID(str)` | Use `Stanza.JID.parse(str)` — now utility module |
| `Stanza.Hints` | Direct export | Not top-level exported — plugin loaded internally |
| `Stanza.VERSION` | `'__STANZAIO_VERSION__'` placeholder | Actual version string from Constants |

### New in v12 top-level exports

| Export | Purpose |
|---|---|
| `Stanza.Constants` | All XMPP constants (error codes, conditions, stream features) |
| `Stanza.Namespaces` | All namespace strings including `NS_OMEMO_1`, `NS_OMEMO_1_DEVICES`, etc. |
| `Stanza.Stanzas` | All protocol types (Message, IQ, Presence, PubsubItem, etc.) |
| `Stanza.JXT` | jxt registry and parser utilities |
| `Stanza.Utils` | Internal utilities |
| `Stanza.Platform` | Platform detection (browser vs node) |
| `Stanza.RSM` | Result Set Management helpers |
| `Stanza.RTT` | Real-Time Text helpers |
| `Stanza.DataForms` | Data forms helpers |
| `Stanza.Jingle` | Jingle session management |
| `Stanza.SASL` | SASL mechanism factory |

---

## 13. WebSocket Transport — Reconnect Logic Changes

If your `xmpp.service.ts` or equivalent directly interacts with the transport, these changed:

```ts
// OLD — check transport state
client.transport.conn          // raw WebSocket object
client.transport.hasStream     // boolean
client.transport.closing       // boolean

// NEW — same properties, different class
client.transport?.stream       // Stream | undefined (typed)
client.transport?.hasStream    // boolean | undefined
// client.transport.conn is gone — now private socket
```

```ts
// OLD — listen on transport directly
client.transport.on('disconnected', handler);

// NEW — listen on client as before
client.on('disconnected', handler);  // same event, fires after queue drain + SM hibernate
```

---

## 14. Migration Checklist

### Critical (must fix before running)

- [ ] Change package name: `stanza.io` → `stanza` in all imports
- [ ] Replace `new JID(str)` with `JID.parse(str)` / `JID.toBare()` / `JID.getLocal()` etc.
- [ ] Keep `'disconnected'` listener as-is — it still fires in v12 (after queue drain + SM hibernate)
- [ ] Remove `client.disconnect(true)` — pass no argument or call `client.disconnect()`
- [ ] Convert `client.sendIq(...)` → `client.sendIQ(...)` (capital Q)
- [ ] Remove all pubsub callbacks — convert to `await`
- [ ] Make all `OmemoStorage` methods return `Promise<T>` instead of `T` synchronously
- [ ] Add `hasDevices(jid): Promise<boolean>` to your `OmemoStorage` implementation
- [ ] Replace `auth:success` listener with `session:started`

### PubSub / OMEMO event payload paths

- [ ] Update `'pubsub:event'` handler: `msg.event.updated.node` → `msg.pubsub?.items?.node`
- [ ] Update `'pubsub:event'` handler: `msg.event.updated.published` → `msg.pubsub.items.published`
- [ ] Update affiliation event: `'pubsub:affiliation'` → `'pubsub:affiliations'`
- [ ] Remove `'pubsubEvent'` alias listeners (use `'pubsub:event'` only)

### Recommended (improves reliability)

- [ ] Add `allowResume: true` to connection config
- [ ] Listen for `'stanza:hibernated'` to track messages buffered during disconnect
- [ ] Listen for `'message:acked'` / `'message:failed'` for delivery confirmation
- [ ] Replace dual-driver reconnect logic with single state machine (see XMPP Architecture Review §7)
- [ ] Add `'--transport-disconnected'` based watchdog instead of polling `reconnectionTimer$`

---

## 15. Namespace Constants

All namespace strings are exported from `Stanza.Namespaces`. Use these instead of hardcoded strings:

```ts
import { Namespaces } from 'stanza';

Namespaces.NS_OMEMO_1          // 'urn:xmpp:omemo:1'
Namespaces.NS_OMEMO_1_DEVICES  // 'urn:xmpp:omemo:1:devices'
Namespaces.NS_OMEMO_1_BUNDLES  // 'urn:xmpp:omemo:1:bundles'
Namespaces.NS_EME_0            // 'urn:xmpp:eme:0'
Namespaces.NS_PUBSUB           // 'http://jabber.org/protocol/pubsub'
Namespaces.NS_CSI_0            // 'urn:xmpp:csi:0'
```
