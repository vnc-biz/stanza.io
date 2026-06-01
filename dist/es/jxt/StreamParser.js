/**
 * This file is derived from prior work.
 *
 * See NOTICE.md for full license text.
 *
 * Derived from: ltx, Copyright © 2010 Stephan Maka
 */
import { Transform } from '../platform';
import XMLElement from './Element';
import JXTError from './Error';
import Parser from './Parser';
export default class StreamParser extends Transform {
    constructor(opts) {
        super({ objectMode: true });
        this.closedStream = false;
        this.wrappedStream = false;
        this.registry = opts.registry;
        this.acceptLanguages = opts.acceptLanguages || [];
        if (opts.wrappedStream) {
            this.wrappedStream = true;
            this.rootImportKey = opts.rootKey;
        }
        this.parser = new Parser({
            allowComments: opts.allowComments
        });
        this.parser.on('error', err => {
            this.destroy(err);
        });
        this.parser.on('startElement', (name, attributes) => {
            if (this.destroyed) {
                return;
            }
            if (this.closedStream) {
                return this.destroy(JXTError.alreadyClosed());
            }
            const el = new XMLElement(name, attributes);
            const key = this.registry.getImportKey(el);
            if (this.wrappedStream && !this.rootElement) {
                if (this.rootImportKey && key !== this.rootImportKey) {
                    return this.destroy(JXTError.unknownRoot());
                }
                const root = this.registry.import(el, {
                    acceptLanguages: this.acceptLanguages,
                    lang: this.lang
                });
                if (root) {
                    this.rootElement = el;
                    this.push({
                        event: 'stream-start',
                        kind: key,
                        stanza: root,
                        xml: el
                    });
                    return;
                }
                else {
                    return this.destroy(JXTError.notWellFormed());
                }
            }
            if (!this.currentElement) {
                this.currentElement = el;
            }
            else {
                this.currentElement = this.currentElement.appendChild(el);
            }
        });
        this.parser.on('endElement', (name) => {
            if (this.destroyed) {
                return;
            }
            if (this.wrappedStream && !this.currentElement) {
                if (!this.rootElement || name !== this.rootElement.name) {
                    this.closedStream = true;
                    return this.destroy(JXTError.notWellFormed());
                }
                this.closedStream = true;
                this.push({
                    event: 'stream-end',
                    kind: this.rootImportKey,
                    stanza: {},
                    xml: this.rootElement
                });
                return this.end();
            }
            if (!this.currentElement || name !== this.currentElement.name) {
                this.closedStream = true;
                return this.destroy(JXTError.notWellFormed());
            }
            if (this.currentElement.parent) {
                this.currentElement = this.currentElement.parent;
            }
            else {
                if (this.wrappedStream) {
                    this.currentElement.parent = this.rootElement;
                }
                const key = this.registry.getImportKey(this.currentElement);
                const stanza = this.registry.import(this.currentElement, {
                    acceptLanguages: this.acceptLanguages,
                    lang: this.lang
                });
                if (stanza) {
                    this.push({
                        kind: key,
                        stanza,
                        xml: this.currentElement
                    });
                }
                this.currentElement = undefined;
            }
        });
        this.parser.on('text', (text) => {
            if (this.currentElement) {
                this.currentElement.children.push(text);
            }
        });
    }
    _transform(chunk, encoding, done) {
        this.parser.write(chunk.toString());
        done();
    }
}
