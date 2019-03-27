'use strict';

var util = require('util');
var WildEmitter = require('wildemitter');
var async = require('async');


var WS;

if (!CordovaWebsocketPlugin) {
  console.log("[stanza.io] use standard WS implementation");

  WS = (require('faye-websocket') && require('faye-websocket').Client) ?
    require('faye-websocket').Client :
    window.WebSocket;
} else {
  console.log("[stanza.io] use custom CordovaWebsocketPlugin WS implementation");
}

var WS_OPEN = 1;



function WSConnection(sm, stanzas) {
    var self = this;

    WildEmitter.call(this);

    self.sm = sm;
    self.closing = false;

    self.stanzas = {
        Open: stanzas.getDefinition('open', 'urn:ietf:params:xml:ns:xmpp-framing', true),
        Close: stanzas.getDefinition('close', 'urn:ietf:params:xml:ns:xmpp-framing', true),
        StreamError: stanzas.getStreamError()
    };

    self.sendQueue = async.queue(function (data, cb) {
        if (self.conn || self.webSocketId) {
            if (typeof data !== 'string') {
                data = data.toString();
            }

            data = new Buffer(data, 'utf8').toString();

            self.emit('raw:outgoing', data);


            if (self.conn) {
                if (self.conn.readyState === WS_OPEN) {
                    self.conn.send(data);
                }
            } else if (self.webSocketId) {
                CordovaWebsocketPlugin.wsSend(self.webSocketId, data);
            }
        }
        cb();
    }, 1);

    self.on('connected', function () {
        self.send(self.startHeader());
    });

    self.on('raw:incoming', function (data) {
        var stanzaObj, err;

        data = data.trim();
        if (data === '') {
            return;
        }

        try {
            stanzaObj = stanzas.parse(data);
        } catch (e) {
            err = new self.stanzas.StreamError({
                condition: 'invalid-xml'
            });
            self.emit('stream:error', err, e);
            self.send(err);
            return self.disconnect();
        }

        if (!stanzaObj) {
            return;
        }

        if (stanzaObj._name === 'openStream') {
            self.hasStream = true;
            self.stream = stanzaObj;
            return self.emit('stream:start', stanzaObj.toJSON());
        }
        if (stanzaObj._name === 'closeStream') {
            self.emit('stream:end');
            // return self.disconnect();
        }

        if (!stanzaObj.lang && self.stream) {
            stanzaObj.lang = self.stream.lang;
        }

        self.emit('stream:data', stanzaObj);
    });
}

util.inherits(WSConnection, WildEmitter);

WSConnection.prototype.connect = function (opts) {
    var self = this;

    self.config = opts;

    self.hasStream = false;
    self.closing = false;

    if (CordovaWebsocketPlugin) {
      var accessToken = "abcdefghiklmnopqrstuvwxyz";

      var providedHeaders = opts.headers || {};
      providedHeaders['Sec-WebSocket-Protocol'] = 'xmpp';

      var wsOptions = {
          url: opts.wsURL,
          timeout: 5000,
          pingInterval: 10000,
          headers: providedHeaders,
          acceptAllCerts: false
      }

      CordovaWebsocketPlugin.wsConnect(wsOptions,
          function(recvEvent) {
              var callbackMethod = recvEvent["callbackMethod"];
              console.log("[stanza.io] Received callback from WebSocket: " + callbackMethod);

              if (callbackMethod === 'onMessage') {
                  var message = recvEvent["message"];
                  console.log("[stanza.io] Received message: ", message);

                  self.emit('raw:incoming', new Buffer(message, 'utf8').toString());
              } else if (callbackMethod === 'onClose') {
                  console.log("[stanza.io] onClose: ", recvEvent["code"], recvEvent["reason"]);

                  self.emit('disconnected', self);
              } else if (callbackMethod === 'onFail') {
                  console.log("[stanza.io] onFail: ", recvEvent["code"], recvEvent["exception"]);

                  self.emit('disconnected', self);
              }
          },
          function(success) {
              self.webSocketId = success.webSocketId;
              console.log("[stanza.io] Connected to WebSocket with id: " + success.webSocketId);

              self.sm.started = false;
              self.emit('connected', self);
          },
          function(error) {
              console.error("[stanza.io] Failed to connect to WebSocket: "+
                          "code: "+error["code"]+
                          ", reason: "+error["reason"]+
                          ", exception: "+error["exception"]);

              self.emit('disconnected', self);
          }
      );
    } else {
      self.conn = new WS(opts.wsURL, 'xmpp', opts.wsOptions);
      self.conn.onerror = function (e) {
          e.preventDefault();
          self.emit('disconnected', self);
      };

      self.conn.onclose = function () {
          self.emit('disconnected', self);
      };

      self.conn.onopen = function () {
          self.sm.started = false;
          self.emit('connected', self);
      };

      self.conn.onmessage = function (wsMsg) {
          self.emit('raw:incoming', new Buffer(wsMsg.data, 'utf8').toString());
      };
    }
};

WSConnection.prototype.startHeader = function () {
    return new this.stanzas.Open({
        version: this.config.version || '1.0',
        lang: this.config.lang || 'en',
        to: this.config.server
    });
};

WSConnection.prototype.closeHeader = function () {
    return new this.stanzas.Close();
};

WSConnection.prototype.disconnect = function () {
  this.send(this.closeHeader());

  this.hasStream = false;
  this.stream = undefined;

  if (CordovaWebsocketPlugin) {
    CordovaWebsocketPlugin.wsClose(this.webSocketId, 1000, "I'm done!");
    this.webSocketId = null;
  } else {
    this.conn.close();
    this.conn = undefined;
  }
};

WSConnection.prototype.restart = function () {
    var self = this;
    self.hasStream = false;
    self.send(this.startHeader());
};

WSConnection.prototype.send = function (data) {
    this.sendQueue.push(data);
};


module.exports = WSConnection;
