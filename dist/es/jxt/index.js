import XMLElement from './Element';
import Registry from './Registry';
import Translator from './Translator';
export * from './Definitions';
export * from './Types';
export * from './Helpers';
export { default as Parser, parse } from './Parser';
export { default as StreamParser } from './StreamParser';
export { Registry, Translator, XMLElement };
export function define(definitions) {
    return (registry) => {
        registry.define(definitions);
    };
}
