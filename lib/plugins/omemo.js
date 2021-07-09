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

function notImplemented() {
  class NotImplementedError extends Error {
  }

  throw new NotImplementedError('Function is not Implemented');
}

export class OmemoStorage {
  storeDevices(jid, devices) {
    notImplemented();
  }

  getDevices(jid) {
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

  storeLocalRegistration(device) {
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

    this.actualizedOpponentDevices = new Set();
    this.getAnnouncedDeviceIdsRequests = {};
    this.getAnnouncedDeviceIdsRequests2 = {};

    this.client.on('pubsub:event', (event) => this.handleDeviceList(event));
  }

  async handleDeviceList(msg) {
    console.log('[OmemoClient][handleDeviceList]', msg);
    if (!msg.event.updated) {
      // Ignore node purge/deletion/etc events.
      console.log("[OmemoClient][handleDeviceList] Ignore node purge/deletion/etc events.");
      return;
    }

    if (msg.event.updated.node !== 'urn:xmpp:omemo:1:devices') {
      // We only want the event for a specific node.
      console.log("[OmemoClient][handleDeviceList] We only want the event for a specific node.");
      return;
    }

    let devices = msg.event.updated.published[0].deviceList.devices || [];
    devices = this.processDevices(devices);

    await this.storeDevices(new JID(msg.from).bare, devices);
  }

  processDevices(devices) {
    const ids = {};
    let processedDevices = [];

    // remove duplictes and make sure id is a number
    devices = devices.map(d => {
      d.id = +d.id;
      return d;
    });

    devices.forEach(d => {
      if (!ids[d.id]) {
        processedDevices.push(d);
        ids[d.id] = true;
      }
    });

    return processedDevices;
  }

  async storeDevices(jidBare, devices) {
    console.log("[OmemoClient][storeDevices]", jidBare, devices);

    await this.store.storeDevices(jidBare, devices);
  }

  async start(platform) {
    this.platform = `${platform} ${new Date().toISOString().split('T')[0]}`;

    console.log("[OmemoClient][start]", this.platform);

    const libsignal = window.libsignal;

    KeyHelper = libsignal.KeyHelper;
    SignalProtocolAddress  = libsignal.SignalProtocolAddress;
    SessionBuilder = libsignal.SessionBuilder;
    SessionCipher = libsignal.SessionCipher;
    Curve = libsignal.Curve;

    let identityKeyPair = await this.store.getIdentityKeyPair();
    let registrationId = await this.store.getLocalRegistrationId();
    let isNew = false;

    this.store.wrapFunction('removePreKey', async (next, id) => {
      await this.announce(this.buildDeviceInfo(await this.store.getLocalRegistrationId()),
                          await this.store.getIdentityKeyPair(),
                          false,
                          id);
      await next(id);
    });

    if (!identityKeyPair || !registrationId) {
      registrationId = KeyHelper.generateRegistrationId();
      identityKeyPair = await KeyHelper.generateIdentityKeyPair();
      isNew = true;

      await this.store.storeIdentityKeyPair(identityKeyPair);
      await this.store.storeLocalRegistration(this.buildDeviceInfo(registrationId));
    }

    await this.announce(this.buildDeviceInfo(registrationId), identityKeyPair, isNew, null, true);
  }

  buildDeviceInfo(deviceId) {
    const device = {id: deviceId, label: this.platform};

    console.log('[OmemoClient][buildDeviceInfo]', device);

    return device;
  }

  async getAnnouncedDevices(jid, force = false) {
    let localUserJid = this.client.jid;
    if (typeof localUserJid !== 'string') {
      localUserJid = localUserJid.bare;
    }

    let isLocalUser = false;
    if (!jid || jid === localUserJid) {
      isLocalUser = true;
    }

    if (!jid) {
      jid = localUserJid;
    }

    if (force || !this.subscriptions.has(jid)) {
      try {
        await this.client.subscribeToNode(jid, 'urn:xmpp:omemo:1:devices');
      } catch (e) {
        console.error(`[OmemoClient][getAnnouncedDevices] subscribe to user ${jid}`, e);
      }
      this.subscriptions.add(jid);
    }

    if (!force && await this.store.hasDevices(jid)) {
      console.log('[OmemoClient][getAnnouncedDevices]', jid, 'return from store');
      return await this.store.getDevices(jid);
    }

    let deviceList;
    try {
      deviceList = await this.client.getOmemoItems(jid, 'urn:xmpp:omemo:1:devices');
      this.actualizedOpponentDevices.add(jid);
      console.log('[OmemoClient][getAnnouncedDevices] deviceList from server', jid, deviceList);
    } catch (e) {
      console.error(`[OmemoClient][getAnnouncedDevices] get items for ${jid} error`, e);
      console.log('[OmemoClient][getAnnouncedDevices] returm empty list');
      return [];
    }

    let devices = [];
    try {
      devices = deviceList.pubsub.retrieve.item.deviceList.devices || [];
      console.log('[OmemoClient][getAnnouncedDevices] devices', devices);
    } catch (e) {
      console.error('[OmemoClient][getAnnouncedDevices] error occurs during parse devices list', e);
    }

    devices = this.processDevices(devices);

    await this.storeDevices(jid, devices);

    return devices;
  }

  async getDeviceKeyBundle(recipient, registrationId) {
    console.log(`[OmemoClient][getDeviceKeyBundle] ${recipient}, ${registrationId}`);
    let keyBundle;
    try {
      keyBundle = await this.client.getOmemoItems(typeof(recipient) === 'string' ? recipient : recipient.bare, 'urn:xmpp:omemo:1:bundles', {
        item: {
          id: registrationId
        }
      });
    } catch (e) {
      console.error('[OmemoClient][getDeviceKeyBundle] error occurs during getting bundles', e);
      return null;
    }
    let bundle = null;

    try {
      bundle = keyBundle.pubsub.retrieve.item.bundle;
    } catch (e) {
      console.warn('[OmemoClient][getDeviceKeyBundle] error parsing bundle', keyBundle)
    }

    return bundle;
  }

  async announceDevices(devices) {
    // sort by device creation date
    try {
      const maxDevices = 5;

      devices.sort((d1, d2) => {
        let d1CreationTs = 0;
        if (d1.label) {
          const d1LabelSplit = d1.label.split(" ");
          const createdAt = d1LabelSplit[d1LabelSplit.length - 1];
          d1CreationTs = Date.parse(createdAt);
        }

        let d2CreationTs = 0;
        if (d2.label) {
          const d2LabelSplit = d2.label.split(" ");
          const createdAt = d2LabelSplit[d2LabelSplit.length - 1];
          d2CreationTs = Date.parse(createdAt);
        }

        return d2CreationTs - d1CreationTs;
      });

      let devicesMap = {};
      let devicesIdsToRemove = [];
      devices.forEach(d => { // devices is already sorted
        if (d.label && d.label.includes(",")) { // if device label contains device name
          const d1LabelSplit = d.label.split(" ");
          const createdAt = d1LabelSplit[d1LabelSplit.length - 1];
          const deviceName = d.label.replace(` ${createdAt}`, '');

          if (devicesMap[deviceName]) {
            devicesIdsToRemove.push(devicesMap[deviceName].id);
          }
          devicesMap[deviceName] = {createdAt, id: d.id};
        }
      });

      console.log('[OmemoClient][announceDevices] devices: ', devices);
      console.log('[OmemoClient][announceDevices] devicesMap: ', devicesMap);
      console.log('[OmemoClient][announceDevices] devicesIdsToRemove: ', devicesIdsToRemove);

      // remove old devices with same name
      if (devicesIdsToRemove.length > 0) {
        devices = devices.filter(d => !devicesIdsToRemove.includes(d.id));
        console.log('[OmemoClient][announceDevices] removed old devices. devices: ', devices);
      }

      if (devices.length > maxDevices) {
        devices = devices.slice(0, maxDevices);
        console.log('[OmemoClient][announceDevices] removed old devices (by max). devices: ', devices);
      }
    } catch(e) {
      console.log('[OmemoClient][announceDevices] devices: ', devices);
      console.error('[OmemoClient][announceDevices] error while removig old devices: ', e);
    }

    const localDeviceId = await this.store.getLocalRegistrationId();

    await this.client.publishOmemoDevice(this.client.jid.bare, 'urn:xmpp:omemo:1:devices', {
      id: `${localDeviceId}`,
      deviceList: {
        devices: devices
      }
    });
  }

  async announce(device, identityKeyPair, isNew, removePreKey = null, isForceGetAnnouncedDevices = false) {
    console.log('[OmemoClient][announce]', {device, isNew});

    let registrationId = device.id;

    const announcedDevices = await this.getAnnouncedDevices(null, isForceGetAnnouncedDevices);
    const announcedDeviceIds = announcedDevices.map(d => d.id);

    console.log('[OmemoClient][announce] announcedDevices', announcedDevices);

    if (announcedDeviceIds.includes(registrationId) && isNew) {
      console.log('[OmemoClient][announce] deviceId already found, even the new');
      registrationId = KeyHelper.generateRegistrationId();
      await this.store.storeLocalRegistration(this.buildDeviceInfo(registrationId));
      await this.announce(this.buildDeviceInfo(registrationId), identityKeyPair, true);
      return;
    }

    if (!announcedDeviceIds.includes(registrationId)) {
      announcedDevices.push(this.buildDeviceInfo(registrationId));
      await this.announceDevices(announcedDevices);
    } else {
      console.log('[OmemoClient][announce] deviceId already found, no need to re-announce');
    }

    const keyBundle = await this.getDeviceKeyBundle(this.client.jid, registrationId);

    if (keyBundle && (OmemoUtils.arrayBufferToBase64String(identityKeyPair.pubKey) !== keyBundle.identityKey)) {
      console.log('[OmemoClient][announce] Different identityKey on same deviceId', {
        ownKey: OmemoUtils.arrayBufferToBase64String(identityKeyPair.pubKey),
        announcedKey: keyBundle.identityKey
      });
      registrationId = KeyHelper.generateRegistrationId();
      await this.store.storeLocalRegistration(this.buildDeviceInfo(registrationId));
      await this.announce(this.buildDeviceInfo(registrationId), identityKeyPair, true);
      return;
    }

    const bundle = await this.refillPreKeys(keyBundle, removePreKey);
    try {
      await this.client.publishOmemoBundle(this.client.jid.bare, 'urn:xmpp:omemo:1:bundles', {
        id: registrationId,
        bundle,
      });
    } catch (e) {
      console.log('[OmemoClient][announce] publishOmemoBundle error', e);
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
    keyBundle.preKeys = keyBundle.preKeys.filter((key) => !!this.store.loadPreKey(key.id) || `${removePreKey}` === `${key.id}`);

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
    const recipientBareJid = (new JID(recipient)).bare;

    let devices = await this.getAnnouncedDevices(recipient, !this.actualizedOpponentDevices.has(recipientBareJid)); //TODO VT temp force request devices from server (before fix on server)
    const deviceIds = devices.map(d => d.id);

    const sessions = [];
    const ownDeviceId = await this.store.getLocalRegistrationId();

    console.log('[OmemoClient][getRecipientSessions]', recipient, ', devices: ', devices);

    if (recipientBareJid === this.client.jid.bare && !deviceIds.includes(ownDeviceId)){
      console.log('[OmemoClient][getRecipientSessions] add current device id', devices);
      deviceIds.push(ownDeviceId);
    }

    for (const deviceId of deviceIds) {
      const address = new SignalProtocolAddress(recipientBareJid, deviceId);
      const session = await this.store.loadSession(address.toString());
      if (!session) {
        const keyBundle = await this.getDeviceKeyBundle(recipientBareJid, deviceId);
        if (!keyBundle) {
          console.log(`[OmemoClient][getRecipientSessions] don\'t have keyBundle for ${deviceId}`);
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

    // TODO: this is to mitigate the server issue with subscription to node,
    // so if we got a message from some user and do not have all its devices,
    // then we just request it.
    //
    // For future, need to remove this logic once a server side is fixed
    const senderJid = message.type === "groupchat" ? message.from.resource : message.from.bare;
    const currentSenderDevice = parseInt(header.sid, 10);

    // reuse promises, e.g. if call the 'decryptMessage' for array of messages
    let req = this.getAnnouncedDeviceIdsRequests[senderJid];
    if (!req) {
      req = this.getAnnouncedDevices(senderJid);
      this.getAnnouncedDeviceIdsRequests[senderJid] = req;
    }
    const localSenderDevicesMap = await req;
    delete this.getAnnouncedDeviceIdsRequests[senderJid];
    //

    if (!localSenderDevicesMap.map(d => d.id).includes(currentSenderDevice)){
      // reuse promises, e.g. if call the 'decryptMessage' for array of messages
      let req = this.getAnnouncedDeviceIdsRequests2[senderJid];
      if (!req) {
        console.warn("[OmemoClient][decryptMessage] force request devices for ", senderJid, currentSenderDevice);
        req = this.getAnnouncedDevices(senderJid, true);
        this.getAnnouncedDeviceIdsRequests2[senderJid] = req;
      }
      await req;
      delete this.getAnnouncedDeviceIdsRequests2[senderJid];
      //
    }

    if (keys.length === 0){
      console.warn("[OmemoClient][decryptMessage] ignore message: not encrypted for current device", localDeviceId);
      return null;
    }

    const iv = OmemoUtils.base64StringToArrayBuffer(header.iv);
    const payload = OmemoUtils.base64StringToArrayBuffer(message.encrypted.payload);

    for (const key of keys) {
      // try {
        const whipser = await this.decryptWhisper(message, key);
        return await this.decryptData(whipser, iv, payload);
      // } catch (e) {
      //   console.error(`[OmemoClient][decryptMessage] Failed decrypting`, e);
      // }
    }

    return null;
  }

  async decryptWhisper(message, key) {
    const isMUC = message.type === "groupchat";

    let whipser;
    if(isMUC) {
      whipser = await this.store.getWhisper(message.from.resource, message.id);
    } else {
      whipser = await this.store.getWhisper(message.from.bare, message.id);
    }

    if (whipser) {
      return whipser;
    }

    const address = new SignalProtocolAddress(isMUC ? message.from.resource : message.from.bare, message.encrypted.header.sid);
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
    // console.log("[OmemoClient][sendMessage]", rawMessage, members);

    const isMUC = rawMessage.type === "groupchat";
    //TODO VT add UTF-8 support
    const omemoMsg = {
      ...rawMessage,
      body: encryptedMsgHint,
      store: true,
      encrypted: await this.createMessage(isMUC, rawMessage.body, members),
      encryption: {
        namespace: 'urn:xmpp:omemo:1',
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
