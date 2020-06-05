const JID = require('xmpp-jid').JID;

const ENCRYPTED_MSG_DEFAULT_HINT = '[This message is OMEMO encrypted]';

const libsignal = window.libsignal;
const {KeyHelper, SignalProtocolAddress, SessionBuilder, SessionCipher, Curve} = libsignal;
const subtleCrypto = window.crypto.subtle;

export default function (client, stanzas) {
  const types = stanzas.utils;

  const NS = 'eu.siacs.conversations.axolotl';

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
    element: 'preKeyPublic',
    namespace: NS,
    fields: {
      id: types.attribute('preKeyId'),
      content: types.text(),
    }
  });

  const SignedPreKeyPublic = stanzas.define({
    name: 'signedPreKeyPublic',
    element: 'signedPreKeyPublic',
    namespace: NS,
    fields: {
      id: types.attribute('signedPreKeyId'),
      content: types.text(),
    }
  });

  const Bundle = stanzas.define({
    name: 'bundle',
    element: 'bundle',
    namespace: NS,
    fields: {
      signedPreKeySignature: types.textSub(NS, 'signedPreKeySignature'),
      identityKey: types.textSub(NS, 'identityKey'),
      preKeys: types.subMultiExtension(NS, 'prekeys', PreKeyPublic),
    }
  });

  const DeviceList = stanzas.define({
    name: 'deviceList',
    element: 'list',
    namespace: NS,
    fields: {
      devices: types.multiSubAttribute(NS, 'device', 'id')
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

function notImplemented() {
  class NotImplementedError extends Error {
  }

  throw new NotImplementedError('Function is not Implemented');
}

export class OmemoStorage {
  storeDeviceIds(jid, deviceIds) {
    notImplemented();
  }

  getDeviceIds(jid) {
    notImplemented();
  }

  storeWhisper(address, id, whisper) {
    notImplemented();
  }

  getWhisper(address, id) {
    notImplemented()
  }

  getLocalRegistrationId() {
    notImplemented();
  };

  storeLocalRegistrationId(id) {
    notImplemented();
  }

  getIdentityKeyPair() {
    notImplemented();
  };

  storeIdentityKeyPair(keyPair) {
    notImplemented();
  }

  isTrustedIdentity(identity, identityKey, direction) {
    notImplemented();
  };

  loadIdentityKey(identity) {
    notImplemented();
  };

  saveIdentity(identity, identityKey) {
    notImplemented();
  };

  loadPreKey(keyId) {
    notImplemented();
  };

  storePreKey(keyId, preKey) {
    notImplemented();
  };

  removePreKey(keyId) {
    notImplemented();
  };

  loadSignedPreKey(keyId) {
    notImplemented();
  };

  storeSignedPreKey(keyId, signedPreKey) {
    notImplemented();
  };

  removeSignedPreKey(keyId) {
    notImplemented();
  };

  loadSession(identifier) {
    notImplemented();
  };

  storeSession(identifier, session) {
    notImplemented();
  };

  removeSession(identifier) {
    notImplemented();
  };

  removeAllSessions(prefix) {
    notImplemented();
  };

  wrapFunction(name, func) {
    const orig = this[name];
    this[name] = (...args) => func(orig, ...args);
  }
}

OmemoStorage.prototype.Direction = OmemoStorage.Direction = {
  SENDING: 1,
  RECEIVING: 2,
};


export class OmemoAddress extends SignalProtocolAddress {
  constructor(name, deviceId) {
    super(typeof(name) === 'string' ? name : name.bare, deviceId);
  }
}

export class OmemoUtils {
  static arrayBufferToBase64String(arrayBuffer) {
    const charArray = new Uint8Array(arrayBuffer);
    return btoa(charArray.reduce((carry, x) => carry + String.fromCharCode(x), ""));
  }

  static base64StringToArrayBuffer(str) {
    const byteStr = atob(str);
    const arrayBuffer = new ArrayBuffer(byteStr.length);
    const byteArray = new Uint8Array(arrayBuffer);

    for (let i = 0; i < byteStr.length; i++) {
      byteArray[i] = byteStr.charCodeAt(i);
    }

    return arrayBuffer;
  }
}

export class OmemoClient {

  constructor({client, store = new OmemoStorage()}) {
    this.client = client;
    this.store = store;
    this.subscriptions = new Set();

    this.client.on('pubsub:event', (event) => this.handleDeviceList(event));
  }

  async handleDeviceList(msg) {
    console.log('[OmemoClient][handleDeviceList]', msg);
    if (!msg.event.updated) {
      // Ignore node purge/deletion/etc events.
      console.log("[OmemoClient][handleDeviceList] Ignore node purge/deletion/etc events.");
      return;
    }

    if (msg.event.updated.node !== 'eu.siacs.conversations.axolotl.devicelist') {
      // We only want the event for a specific node.
      console.log("[OmemoClient][handleDeviceList] We only want the event for a specific node.");
      return;
    }

    const devices = new Set(msg.event.updated.published[0].deviceList.devices);
    await this.store.storeDeviceIds(new JID(msg.from).bare, devices);
  }

  async start() {
    let identityKeyPair = await this.store.getIdentityKeyPair();
    let registrationId = await this.store.getLocalRegistrationId();
    let isNew = false;

    this.store.wrapFunction('removePreKey', async (next, id) => {
      await this.announce(await this.store.getLocalRegistrationId(), await this.store.getIdentityKeyPair(), false, id);
      await next(id);
    });

    if (identityKeyPair === undefined || registrationId === undefined) {
      registrationId = KeyHelper.generateRegistrationId();
      identityKeyPair = await KeyHelper.generateIdentityKeyPair();
      isNew = true;

      await this.store.storeIdentityKeyPair(identityKeyPair);
      await this.store.storeLocalRegistrationId(registrationId);
    }

    await this.announce(registrationId, identityKeyPair, isNew);
  }

  async getAnnouncedDeviceIds(jid, force = false) {
    if (!jid) {
      jid = this.client.jid;
    }

    if (typeof jid !== 'string') {
      jid = jid.bare;
    }

    if (force || !this.subscriptions.has(jid)) {
      try {
        await this.client.subscribeToNode(jid, 'eu.siacs.conversations.axolotl.devicelist');
        this.subscriptions.add(jid);
      } catch (e) {
        console.log(`[OmemoClient][getAnnouncedDeviceIds] subscribe to user ${jid} node error`, e);
      }
    }

    if (!force && await this.store.hasDeviceIds(jid)) {
      console.log('[OmemoClient][getAnnouncedDeviceIds] return from store');
      return await this.store.getDeviceIds(jid);
    }

    let deviceList;
    try {
      deviceList = await this.client.getItems(jid, 'eu.siacs.conversations.axolotl.devicelist');
    } catch (e) {
      console.error(`[OmemoClient][getAnnouncedDeviceIds] get items for ${jid} error`, e);
      console.log('[OmemoClient][getAnnouncedDeviceIds]returm empty list');
      return new Set();
    }

    let deviceIds = [];

    try {
      deviceIds = deviceList.pubsub.retrieve.item.deviceList.devices;
    } catch (e) {
      console.error('[OmemoClient][getAnnouncedDeviceIds] error occurs during parse devices list', e);
    }

    const ids = new Set(deviceIds.map((a) => parseInt(a, 10)));

    await this.store.storeDeviceIds(jid, ids);
    console.log('[OmemoClient][getAnnouncedDeviceIds] return updated list');
    return ids;
  }

  async getDeviceKeyBundle(recipient, registrationId) {
    let keyBundle;
    try {
      keyBundle = await this.client.getItems(typeof(recipient) === 'string' ? recipient : recipient.bare, 'eu.siacs.conversations.axolotl.bundles:' + registrationId);
    } catch (e) {
      return null;
    }
    let bundle = null;

    try {
      bundle = keyBundle.pubsub.retrieve.item.bundle;
    } catch (e) {
      console.log('[OmemoClient][getDeviceKeyBundle]', keyBundle)
    }

    return bundle;
  }

  async announceDeviceIds(deviceIds) {
    await this.client.publish(this.client.jid.bare, 'eu.siacs.conversations.axolotl.devicelist', {
      deviceList: {
        devices: Array.from(deviceIds)
      }
    });
  }

  async announce(registrationId, identityKeyPair, isNew, removePreKey = null) {
    console.log('[OmemoClient][Announcing]', {registrationId, identityKeyPair, isNew});
    const deviceIds = await this.getAnnouncedDeviceIds();

    if (deviceIds.has(registrationId) && isNew) {
      console.log('[OmemoClient][announce] deviceId already found, even tho new');
      registrationId = KeyHelper.generateRegistrationId();
      await this.store.storeLocalRegistrationId(registrationId);
      await this.announce(registrationId, identityKeyPair, true);
      return;
    }

    if (!deviceIds.has(registrationId)) {
      deviceIds.add(registrationId);
      await this.announceDeviceIds(deviceIds);
    }

    const keyBundle = await this.getDeviceKeyBundle(this.client.jid, registrationId);

    if (keyBundle && (OmemoUtils.arrayBufferToBase64String(identityKeyPair.pubKey) !== keyBundle.identityKey)) {
      console.log('[OmemoClient][announce] Different identityKey on same deviceId', {
        ownKey: OmemoUtils.arrayBufferToBase64String(identityKeyPair.pubKey),
        announcedKey: keyBundle.identityKey
      });
      registrationId = KeyHelper.generateRegistrationId();
      await this.store.storeLocalRegistrationId(registrationId);
      await this.announce(registrationId, identityKeyPair, true);
      return;
    }

    const bundle = await this.refillPreKeys(keyBundle, removePreKey);
    try {
      await this.client.publish(this.client.jid.bare, 'eu.siacs.conversations.axolotl.bundles:' + registrationId, {
        bundle,
      });
    } catch (e) {
      console.log('[OmemoClient][announce] publish error', e);
    }
  }

  async refillPreKeys(keyBundle, removePreKey = null) {
    const identityPair = await this.store.getIdentityKeyPair();

    if (!keyBundle) {
      keyBundle = {
        preKeys: [],
        signedPreKeyPublic: {
          id: ""
        },
      }
    }

    keyBundle.identityKey = OmemoUtils.arrayBufferToBase64String(identityPair.pubKey);

    let highestPreKeyId = keyBundle.preKeys.reduce((a, b) => Math.max(a, b), 1);

    // Remove used keys
    keyBundle.preKeys = keyBundle.preKeys.filter((key) => this.store.loadPreKey(key.id) !== undefined || `${removePreKey}` === `${key.id}`);

    while (keyBundle.preKeys.length < 100) {
      const {keyPair, keyId} = await KeyHelper.generatePreKey(++highestPreKeyId);
      await this.store.storePreKey(keyId, keyPair);
      keyBundle.preKeys.push({
        id: keyId,
        content: OmemoUtils.arrayBufferToBase64String(keyPair.pubKey)
      });
    }

    if (!keyBundle.signedPreKeyPublic.id) {
      const {keyPair, signature, keyId} = await KeyHelper.generateSignedPreKey(identityPair, Math.floor(Math.random() * 235234));
      await this.store.storeSignedPreKey(keyId, keyPair);

      keyBundle.signedPreKeySignature = OmemoUtils.arrayBufferToBase64String(signature);
      keyBundle.signedPreKeyPublic = {
        content: OmemoUtils.arrayBufferToBase64String(keyPair.pubKey),
        id: `${keyId}`
      };


      console.log('[OmemoClient][refillPreKeys] Verification', window.globalShit = [identityPair.pubKey, keyPair.pubKey, signature]);
      console.log('[OmemoClient][refillPreKeys] Result', Curve.verifySignature(identityPair.pubKey, keyPair.pubKey, signature));
    }

    return keyBundle;
  }

  async getRecipientSessions(isMUC, recipient) {
    console.log('[OmemoClient][getRecipientSessions] recipient ', recipient);
    const recipientBareJid = (new JID(recipient)).bare;
    const deviceIds = await this.getAnnouncedDeviceIds(recipient);

    if (deviceIds.length === 0){
      deviceIds = await this.getAnnouncedDeviceIds(recipient, true);
    }

    const sessions = [];
    const ownDeviceId = await this.store.getLocalRegistrationId();

    for (const deviceId of deviceIds) {
      console.log('[OmemoClient][getRecipientSessions] selected deviceId ', deviceId);
      if (!isMUC && `${ownDeviceId}` === `${deviceId}`) {
        console.log('[OmemoClient][getRecipientSessions] skeep deviceId ', deviceId);
        continue;
      }

      const address = new OmemoAddress(recipientBareJid, deviceId);
      const session = await this.store.loadSession(address.toString());
      if (session === undefined) {
        const keyBundle = await this.getDeviceKeyBundle(recipientBareJid, deviceId);
        if (!keyBundle) {
          continue;
        }

        const sessionBuilder = new SessionBuilder(this.store, address);

        const preKey = keyBundle.preKeys[Math.floor(Math.random() * keyBundle.preKeys.length)];

        console.info(`[OmemoClient][getRecipientSessions] Trying to process PreKey[${recipientBareJid}:${preKey.id}]`);

        try {
          await sessionBuilder.processPreKey({
            registrationId: deviceId,
            identityKey: OmemoUtils.base64StringToArrayBuffer(keyBundle.identityKey),
            signedPreKey: {
              keyId: parseInt(keyBundle.signedPreKeyPublic.id, 10),
              publicKey: OmemoUtils.base64StringToArrayBuffer(keyBundle.signedPreKeyPublic.content),
              signature: OmemoUtils.base64StringToArrayBuffer(keyBundle.signedPreKeySignature)
            },
            preKey: {
              keyId: parseInt(preKey.id, 10),
              publicKey: OmemoUtils.base64StringToArrayBuffer(preKey.content),
            }
          });
        } catch (e) {
          console.log(`[OmemoClient][getRecipientSessions] Failed processing PreKey[${recipientBareJid}:${preKey.id}]`)
          // Don't add failed session cipher to sessions
          continue;
        }
      }

      sessions.push(new SessionCipher(this.store, address));
    }

    return sessions;
  }

  async decryptMessage(message) {
    const header = message.encrypted.header;

    const localDeviceId = await this.store.getLocalRegistrationId();
    const keys = header.keys.filter(key => `${key.rid}` === `${localDeviceId}`);

    if (keys.length === 0){
      console.warn("[OmemoClient][decryptMessage] didn't found key for ", localDeviceId);
      if(message.type === 'chat'){
        await this.getAnnouncedDeviceIds(message.from, true);
      }

      this.forceAnnounceDevice();
      return null;
    }

    const iv = OmemoUtils.base64StringToArrayBuffer(header.iv);
    const payload = OmemoUtils.base64StringToArrayBuffer(message.encrypted.payload);

    for (const key of keys) {
      try {
        const whipser = await this.decryptWhisper(message, key);
        return await this.decryptData(whipser, iv, payload);
      } catch (e) {
        console.warn(`[OmemoClient][decryptMessage] Failed decrypting`, e);
      }
    }

    return null;
  }

  async forceAnnounceDevice(generateNew = false){
    console.log("[OmemoClient][forceAnnounceDevice] generateNew", generateNew);

    let identityKeyPair;
    let registrationId;
    
    if (!generateNew){
        identityKeyPair = await this.store.getIdentityKeyPair();
        registrationId = await this.store.getLocalRegistrationId();
    }

    if (generateNew || identityKeyPair === undefined || registrationId === undefined) {
      registrationId = KeyHelper.generateRegistrationId();
      identityKeyPair = await KeyHelper.generateIdentityKeyPair();

      await this.store.storeIdentityKeyPair(identityKeyPair);
      await this.store.storeLocalRegistrationId(registrationId);
    }

    await this.announce(registrationId, identityKeyPair, true);
  }

  async decryptWhisper(message, key) {
    const isMUC = message.type === "groupchat";

    let whipser;
    if(isMUC) {
      whipser  = await this.store.getWhisper(message.from.bare, message.id);
    } else {
      whipser  = await this.store.getWhisper(message.from.resource, message.id);
    }

    if (whipser !== undefined) {
      return whipser;
    }

    const address = new OmemoAddress(isMUC ? message.from.resource : message.from.bare, message.encrypted.header.sid);
    const session = new SessionCipher(this.store, address);

    let plaintext = null;
    const keyData = OmemoUtils.base64StringToArrayBuffer(key.content);
    if (key.prekey) {
      plaintext = await session.decryptPreKeyWhisperMessage(keyData, 'binary');
    } else {
      plaintext = await session.decryptWhisperMessage(keyData, 'binary');
    }

    await this.store.storeWhisper(isMUC ? message.from.resource : message.from.bare, message.id, plaintext);
    return plaintext;
  }

  async decryptData(keyData, iv, data) {
    const gcmKey = keyData.slice(0, 16);
    const authTag = new Uint8Array(keyData.byteLength - 16);
    authTag.set(new Uint8Array(keyData.slice(16)));

    const subtleKey = await subtleCrypto.importKey("raw", gcmKey, {name: "AES-GCM"}, false, ['decrypt', 'encrypt']);
    const decryptData = new Uint8Array(data.byteLength + authTag.byteLength);

    decryptData.set(new Uint8Array(data));
    decryptData.set(authTag, data.byteLength);

    console.info('[OmemoClient][decryptData] Decrypting', {
      iv: OmemoUtils.arrayBufferToBase64String(iv),
      authTag: OmemoUtils.arrayBufferToBase64String(authTag),
      tagLength: authTag.byteLength * 8,
      payload: OmemoUtils.arrayBufferToBase64String(data),
      key: OmemoUtils.arrayBufferToBase64String(gcmKey),
      whisperMessage: OmemoUtils.arrayBufferToBase64String(keyData),
    });

    try {
      return await subtleCrypto.decrypt(
        {
          name: "AES-GCM",
          iv: iv,
          tagLength: authTag.byteLength === 0 ? 128 : authTag.byteLength * 8,
        },
        subtleKey,
        decryptData
      );
    } catch (e) {
      console.error('[OmemoClient][decryptData] Failed decrypting data');
      console.error(e.stack);
    }
  };

  async sendMessage(rawMessage, members = [rawMessage.to, rawMessage.from], encryptedMsgHint = ENCRYPTED_MSG_DEFAULT_HINT) {
    console.log("[OmemoClient][sendMessage]", rawMessage, members);

    const isMUC = rawMessage.type === "groupchat";
    //TODO VT add UTF-8 support
    const omemoMsg = {
      ...rawMessage,
      body: encryptedMsgHint,
      store: true,
      encrypted: await this.createMessage(isMUC, rawMessage.body, members),
      encryption: {
        namespace: 'eu.siacs.conversations.axolotl',
        name: 'OMEMO',
      }
    };

    console.log("[OmemoClient][sendMessage] omemoMsg = ", omemoMsg);
    return await this.client.sendMessage(omemoMsg);
  }

  async createMessage(isMUC, plaintext, recipients) {
    const randomSource = new Uint8Array(32);

    await window.crypto.getRandomValues(randomSource);
    const gcmKey = randomSource.slice(0, 16);
    const iv = randomSource.slice(16);

    const subtleKey = await subtleCrypto.importKey("raw", gcmKey, {name: "AES-GCM"}, false, ['decrypt', 'encrypt']);
    const payload = new TextEncoder().encode(plaintext);

    const ciphertextWithAuth = await subtleCrypto.encrypt(
      {
        name: 'AES-GCM',
        iv: iv,
        tagLength: 128,
      },
      subtleKey,
      payload.buffer
    );

    const ciphertext = ciphertextWithAuth.slice(0, ciphertextWithAuth.byteLength - 16);
    const authTag = ciphertextWithAuth.slice(ciphertextWithAuth.byteLength - 16);

    return {
      header: await this.createHeader(isMUC, gcmKey, authTag, iv, recipients),
      payload: OmemoUtils.arrayBufferToBase64String(ciphertext)
    }
  }

  /**
   * @param {ArrayBuffer} key
   * @param {ArrayBuffer} auth
   * @param {ArrayBuffer} iv
   * @param {Array<string|JID>} recipients
   * @returns {Promise<{iv: string, keys: Array<{ rid: number, content: string }>}>}
   */
  async createHeader(isMUC, key, auth, iv, recipients) {
    const uniqueRecipients = new Set(recipients.map((jid) => typeof(jid) === 'string' ? jid : jid.bare));

    const encryptedKeys = [];
    const payload = new ArrayBuffer(key.byteLength + auth.byteLength);
    const payloadArr = new Uint8Array(payload);

    const keyByteArr = new Uint8Array(key);
    const authArr = new Uint8Array(auth);

    payloadArr.set(keyByteArr);
    payloadArr.set(authArr, keyByteArr.byteLength);

    for (const recipient of uniqueRecipients) {
      const recipientSessions = await this.getRecipientSessions(isMUC, recipient);

      for (const recipientSession of recipientSessions) {

        const {type, body} = await recipientSession.encrypt(payload);
        const keyObj = {
          rid: await recipientSession.getRemoteRegistrationId(),
          content: btoa(body),
        };

        if (type === 3) {
          keyObj.prekey = true;
        }

        encryptedKeys.push(keyObj);
      }
    }

    return {
      iv: OmemoUtils.arrayBufferToBase64String(iv),
      keys: encryptedKeys,
      sid: await this.store.getLocalRegistrationId()
    };
  }
}
