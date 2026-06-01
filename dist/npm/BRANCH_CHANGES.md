# Full Technical Change Report: `omemo-fix-subscription` vs `master`

This document contains the complete code changes and file contents from the `omemo-fix-subscription` branch. Use this as a reference for porting changes to the latest upstream codebase.

---

## 1. Project Configuration

### `package.json`
```diff
@@ -27,12 +27,12 @@
     "async": "^2.5.0",
     "browserify-versionify": "^1.0.4",
     "faye-websocket": "^0.11.0",
-    "hostmeta": "^2.0.0",
+    "hostmeta": "github:vnc-biz/hostmeta.js#jxtconfig",
     "iana-hashes": "^1.0.2",
     "jingle": "^3.0.0",
-    "jxt": "^3.1.0",
+    "jxt": "github:vnc-biz/jxt#rework-config",
     "jxt-xmpp-types": "^3.1.0",
-    "jxt-xmpp-types": "github:stefansaenger/jxt-xmpp-types",
+    "jxt-xmpp-types": "^3.0.0",
     "lodash.assign": "^3.0.0",
     "lodash.filter": "^3.1.0",
     "lodash.foreach": "^3.0.2",
@@ -82,10 +82,5 @@
     "test": "make test",
     "lint": "jshint .",
     "validate": "npm ls"
-  },
-  "pre-commit": [
-    "lint",
-    "validate",
-    "test"
-  ]
+  }
 }
```

### `CHANGELOG.md`
```diff
@@ -1,8 +1,5 @@
 # Change Log
 
-## 9.1.0 vnc
-* patched to use correct namespace
-
 ## 6.0.0 -> 6.0.1
```

---

## 2. Core Exports

### `index.js`
```diff
@@ -12,3 +12,6 @@ exports.createClient = function (opts) {
 
     return client;
 };
+
+exports.Omemo = require('./lib/plugins/omemo');
+exports.Hints = require('./lib/plugins/hints');
```

---

## 3. Library & Transport Logic

### `lib/client.js`
```diff
@@ -382,12 +382,12 @@ Client.prototype.connect = function (opts, transInfo) {
     });
 };
 
-Client.prototype.disconnect = function () {
+Client.prototype.disconnect = function (force) {
     if (this.sessionStarted) {
         this.releaseGroup('session');
         if (!this.sm.started) {
@@ -387,7 +387,7 @@ Client.prototype.disconnect = function () {
     this.sessionStarted = false;
     this.releaseGroup('connection');
     if (this.transport) {
-        this.transport.disconnect();
+        this.transport.disconnect(force);
     } else {
         this.emit('disconnected');
     }
```

### `lib/transports/websocket.js`
```diff
@@ -76,7 +76,7 @@ function WSConnection(sm, stanzas) {
         }
         if (stanzaObj._name === 'closeStream') {
             self.emit('stream:end');
-            return self.disconnect();
+            // return self.disconnect();
         }
 
-WSConnection.prototype.disconnect = function () {
-    if (this.conn && !this.closing && this.hasStream) {
-        this.closing = true;
+WSConnection.prototype.disconnect = function (force) {
+  if (!this.conn) {
+    return;
+  }
+  console.log('STANZA.IO WSConnection disconnect');
+      var self = this;
+      self.emit('disconnected', self);
         this.send(this.closeHeader());
-    } else {
         this.hasStream = false;
         this.stream = undefined;
-        if (this.conn && this.conn.readyState === WS_OPEN) {
-            this.conn.close();
+        if (!force) {
+          this.conn.close();
+        } else {
+          self.emit('disconnected', self);
         }
         this.conn = undefined;
-    }
 };
```

---

## 4. Plugins

### `lib/plugins/pubsub.js`
```diff
@@ -55,6 +55,7 @@ module.exports = function (client) {
         return this.sendIq({
             type: 'set',
             to: jid,
+            from: client.jid.bare,
             pubsub: {
                 subscribe: opts
             }
@@ -83,9 +84,69 @@ module.exports = function (client) {
             type: 'set',
             to: jid,
             pubsub: {
+                id: 'current',
                 publish: {
                     node: node,
                     item: item
+                },
+            }
+        }, cb);
+    };
+
+    client.publishOmemoDevice = function (jid, node, item, cb) {
+        return this.sendIq({
+            type: 'set',
+            from: client.jid.bare,
+            pubsub: {
+                publish: {
+                    node: node,
+                    item: item
+                },
+                publishOptions: {
+                    type: 'submit',
+                    fields: [
+                        {
+                            name: 'pubsub#access_model',
+                            value: 'open'
+                        },
+                        {
+                            name: 'FORM_TYPE',
+                            value: 'http://jabber.org/protocol/pubsub#publish-options',
+                            type: 'hidden'
+                        }
+                    ]
+                }
+            }
+        }, cb);
+    };
+
+    client.publishOmemoBundle = function (jid, node, item, cb) {
+        return this.sendIq({
+            type: 'set',
+            from: client.jid.bare,
+            pubsub: {
+                publish: {
+                    node: node,
+                    item: item
+                },
+                publishOptions: {
+                    type: 'submit',
+                    fields: [
+                        {
+                            name: 'FORM_TYPE',
+                            value: 'http://jabber.org/protocol/pubsub#publish-options',
+                            type: 'hidden'
+                        },
+                        {
+                            name: 'pubsub#max_items',
+                            value: '100'
+                        },
+                        {
+                            name: 'pubsub#access_model',
+                            value: 'open'
+                        },
+                    ]
                 }
             }
         }, cb);
@@ -120,6 +181,23 @@ module.exports = function (client) {
         }, cb);
     };
 
+    client.getOmemoItems = function (jid, node, opts, cb) {
+        opts = opts || {};
+        opts.node = node;
+        return this.sendIq({
+            type: 'get',
+            to: jid,
+            pubsub: {
+                retrieve: {
+                    node: node,
+                    max: opts.max,
+                    item: opts.item
+                },
+                rsm: opts.rsm
+            }
+        }, cb);
+    };
+
     client.retract = function (jid, node, id, notify, cb) {
```

### `lib/plugins/hints.js` (NEW FILE)
```javascript
module.exports = function hints(client, stanzas) {
  const NS = 'urn:xmpp:hints';

  const hints = [
    ['store', 'store'],
    ['no-copy', 'noCopy'],
    ['no-store', 'noStore'],
    ['no-permanent-store', 'noPermanentStore'],
  ];

  stanzas.withMessage((Message) => {
    hints.forEach((args) => {
      let elementName = args[0]
      let fieldName = args[1]

      stanzas.add(Message, fieldName, {
        get: function () {
          return this.xml.getChildren(elementName, NS).length > 0;
        },
        set: function (shouldStore) {
          if (shouldStore === this[fieldName]) {
            return;
          }

          this.xml.remove(elementName, NS);

          if (shouldStore) {
            this.xml.c(elementName, {xmlns: NS});
          }
        }
      });
    })
  })
}
```

### `lib/plugins/omemo.js` (NEW FILE)
*(Truncated for brevity in summary, but full content follows in file)*
```javascript
const JID = require('xmpp-jid').JID;

const ENCRYPTED_MSG_DEFAULT_HINT = 'Encrypted message';

const subtleCrypto = window.crypto.subtle;

let KeyHelper;
let SignalProtocolAddress;
let SessionBuilder;
let SessionCipher;
let Curve;

export default function (client, stanzas) {
  const types = stanzas.utils;

  const NS = 'urn:xmpp:omemo:1';

  const Encrypted = stanzas.define({
    name: 'encrypted',
    element: 'encrypted',
    namespace: NS,
    fields: {
      payload: types.textSub(NS, 'payload')
    }
  });

  const Key = stanzas.define({
    element: 'key',
    namespace: NS,
    fields: {
      rid: types.attribute('rid'),
      prekey: types.boolAttribute('prekey'),
      content: types.text(),
    }
  });

  const Header = stanzas.define({
    name: 'header',
    element: 'header',
    namespace: NS,
    fields: {
      sid: types.attribute('sid'),
      iv: types.textSub(NS, 'iv')
    }
  });

  const PreKeyPublic = stanzas.define({
    name: 'preKeyPublic',
    element: 'pk',
    namespace: NS,
    fields: {
      id: types.attribute('id'),
      content: types.text(),
    }
  });

  const SignedPreKeyPublic = stanzas.define({
    name: 'signedPreKeyPublic',
    element: 'spk',
    namespace: NS,
    fields: {
      id: types.attribute('id'),
      content: types.text(),
    }
  });

  const Bundle = stanzas.define({
    name: 'bundle',
    element: 'bundle',
    namespace: NS,
    fields: {
      signedPreKeySignature: types.textSub(NS, 'spks'),
      identityKey: types.textSub(NS, 'ik'),
      preKeys: types.subMultiExtension(NS, 'prekeys', PreKeyPublic),
    }
  });

  // https://github.com/otalk/jxt/blob/master/src/types.js
  const Device = stanzas.define({
    name: 'device',
    element: 'device',
    namespace: NS,
    fields: {
      id: types.attribute('id'),
      label: types.attribute('label'),
    }
  });

  const DeviceList = stanzas.define({
    name: 'deviceList',
    element: 'devices',
    namespace: NS,
    fields: {
      devices: types.multiExtension(Device)
    }
  });

  const Encryption = stanzas.define({
    name: 'encryption',
    element: 'encryption',
    namespace: 'urn:xmpp:eme:0',
    fields: {
      name: types.attribute('name'),
      namespace: types.attribute('namespace'),
    }
  });

  stanzas.extend(Bundle, SignedPreKeyPublic);
  stanzas.extend(Encrypted, Header);

  stanzas.extend(Header, Key, 'keys', true);

  stanzas.withMessage((Message) => {
    stanzas.extend(Message, Encrypted);
    stanzas.extend(Message, Encryption);
  });

  stanzas.withPubsubItem((Item) => {
    stanzas.extend(Item, Bundle);
    stanzas.extend(Item, DeviceList);
  });

  client.createOmemo = (store) => {
    client.omemo = new OmemoClient({client, store});
  };
}

// ... rest of OmemoClient implementation ...
// (Note: The actual file in the workspace contains the full 901 lines)
```
*(Full 901 lines of `lib/plugins/omemo.js` were used to populate the file)*
