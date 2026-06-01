import { Buffer } from '../platform';
import XMLElement from './Element';
import { parse } from './Parser';
export function createElement(namespace, name, parentNamespace, parent) {
    if (parent) {
        namespace = namespace || parent.getNamespace();
        const root = parent.getNamespaceRoot(namespace);
        if (root) {
            const prefix = root.useNamespace('', namespace);
            name = `${prefix}:${name}`;
        }
    }
    const el = new XMLElement(name);
    if (name.indexOf(':') < 0 && (!parentNamespace || namespace !== parentNamespace)) {
        el.setAttribute('xmlns', namespace);
    }
    return el;
}
export function getLang(xml, lang) {
    return (xml.getAttribute('xml:lang') || lang || '').toLowerCase();
}
export function getTargetLang(children, context) {
    const availableLanguages = [];
    for (const child of children) {
        availableLanguages.push(getLang(child, context.lang));
    }
    let targetLanguage;
    if (!context.resolveLanguage) {
        targetLanguage = context.lang;
    }
    else {
        targetLanguage = context.resolveLanguage(availableLanguages, context.acceptLanguages || [], context.lang);
    }
    return targetLanguage || '';
}
export function findAll(xml, namespace, element, lang) {
    const existing = xml.getChildren(element, namespace);
    const parentLang = getLang(xml);
    if (existing.length) {
        if (lang) {
            return existing.filter(child => {
                const childLang = getLang(child, parentLang);
                if (childLang === lang) {
                    return true;
                }
            });
        }
        else {
            return existing;
        }
    }
    return [];
}
export function findOrCreate(xml, namespace, element, lang) {
    namespace = namespace || xml.getNamespace();
    const existing = findAll(xml, namespace, element, lang);
    if (existing.length) {
        return existing[0];
    }
    const created = createElement(namespace, element, xml.getDefaultNamespace(), xml);
    const parentLang = getLang(xml, lang);
    if (lang && parentLang !== lang) {
        created.setAttribute('xml:lang', lang);
    }
    xml.appendChild(created);
    return created;
}
function createAttributeField(opts) {
    return {
        importer(xml) {
            const rawValue = xml.getAttribute(opts.name, opts.namespace);
            if (!rawValue) {
                return opts.dynamicDefault ? opts.dynamicDefault(rawValue) : opts.staticDefault;
            }
            return opts.parseValue(rawValue);
        },
        exporter(xml, value) {
            if (value === undefined || value === opts.staticDefault) {
                return;
            }
            const output = opts.writeValue(value);
            if (!output && !opts.emitEmpty) {
                return;
            }
            if (!opts.namespace || !opts.prefix) {
                xml.setAttribute(opts.name, output, opts.emitEmpty);
            }
            else {
                let prefix;
                const root = xml.getNamespaceRoot(opts.namespace);
                if (root) {
                    prefix = root.useNamespace(opts.prefix, opts.namespace);
                }
                else {
                    const namespaces = xml.getNamespaceContext();
                    if (!namespaces[opts.namespace]) {
                        prefix = xml.useNamespace(opts.prefix, opts.namespace);
                        namespaces[opts.namespace] = prefix;
                    }
                }
                xml.setAttribute(`${prefix}:${opts.name}`, output, opts.emitEmpty);
            }
        }
    };
}
function createAttributeType(parser, createOpts) {
    return (name, defaultValue = undefined, opts = {}) => {
        opts = Object.assign({ staticDefault: defaultValue }, opts);
        return createAttributeField(Object.assign(Object.assign({ name }, parser), (createOpts ? createOpts(opts) : opts)));
    };
}
function createNamespacedAttributeType(parser, createOpts) {
    return (prefix, namespace, name, defaultValue = undefined, opts = {}) => {
        opts = Object.assign({ staticDefault: defaultValue }, opts);
        return createAttributeField(Object.assign(Object.assign({ name,
            namespace,
            prefix }, parser), (createOpts ? createOpts(opts) : opts)));
    };
}
function createChildAttributeField(opts) {
    const converter = opts.converter ||
        createAttributeField(Object.assign(Object.assign({}, opts), { namespace: opts.attributeNamespace }));
    return {
        importer(xml, context) {
            const child = xml.getChild(opts.element, opts.namespace || xml.getNamespace());
            if (!child) {
                return opts.dynamicDefault ? opts.dynamicDefault() : opts.staticDefault;
            }
            return converter.importer(child, context);
        },
        exporter(xml, value, context) {
            if (value !== undefined && value !== opts.staticDefault) {
                const child = findOrCreate(xml, opts.namespace || xml.getNamespace(), opts.element);
                converter.exporter(child, value, context);
            }
        }
    };
}
function createChildAttributeType(parser, createOpts) {
    return (namespace, element, name, defaultValue = undefined, opts = {}) => {
        opts = Object.assign({ staticDefault: defaultValue }, opts);
        return createChildAttributeField(Object.assign(Object.assign({ element,
            name,
            namespace }, parser), (createOpts ? createOpts(opts) : opts)));
    };
}
function createTextField(opts) {
    return {
        importer(xml) {
            const rawValue = xml.getText();
            if (!rawValue) {
                return opts.dynamicDefault ? opts.dynamicDefault(rawValue) : opts.staticDefault;
            }
            return opts.parseValue(rawValue);
        },
        exporter(xml, value) {
            if (!value && opts.emitEmpty) {
                xml.children.push('');
                return;
            }
            if (value === undefined || value === opts.staticDefault) {
                return;
            }
            const output = opts.writeValue(value);
            if (output) {
                xml.children.push(output);
            }
        }
    };
}
function createChildTextField(opts) {
    const converter = createTextField(opts);
    return {
        importer(xml, context) {
            const children = findAll(xml, opts.namespace || xml.getNamespace(), opts.element);
            const targetLanguage = getTargetLang(children, context);
            if (!children.length) {
                return opts.dynamicDefault ? opts.dynamicDefault() : opts.staticDefault;
            }
            if (opts.matchLanguage) {
                for (const child of children) {
                    if (getLang(child, context.lang) === targetLanguage) {
                        return converter.importer(child, context);
                    }
                }
            }
            return converter.importer(children[0], context);
        },
        exporter(xml, value, context) {
            if (!value && opts.emitEmpty) {
                findOrCreate(xml, opts.namespace || xml.getNamespace(), opts.element, opts.matchLanguage ? context.lang : undefined);
                return;
            }
            if (value !== undefined && value !== opts.staticDefault) {
                const child = findOrCreate(xml, opts.namespace || xml.getNamespace(), opts.element, opts.matchLanguage ? context.lang : undefined);
                converter.exporter(child, value, context);
            }
        }
    };
}
const stringParser = {
    parseValue: v => v,
    writeValue: v => v
};
const integerParser = {
    parseValue: v => parseInt(v, 10),
    writeValue: v => v.toString()
};
const floatParser = {
    parseValue: v => parseFloat(v),
    writeValue: v => v.toString()
};
const boolParser = {
    parseValue: v => {
        if (v === 'true' || v === '1') {
            return true;
        }
        if (v === 'false' || v === '0') {
            return false;
        }
        return;
    },
    writeValue: v => (v ? '1' : '0')
};
const dateParser = {
    parseValue: v => new Date(v),
    writeValue: v => (typeof v === 'string' ? v : v.toISOString())
};
const jsonParser = {
    parseValue: v => JSON.parse(v),
    writeValue: v => JSON.stringify(v)
};
const bufferParser = (encoding = 'utf8') => ({
    parseValue: v => {
        if (encoding === 'base64' && v === '=') {
            v = '';
        }
        return Buffer.from(v.trim(), encoding);
    },
    writeValue: v => {
        let data;
        if (typeof v === 'string') {
            data = Buffer.from(v).toString(encoding);
        }
        else if (v) {
            data = v.toString(encoding);
        }
        else {
            data = '';
        }
        if (encoding === 'base64') {
            data = data || '=';
        }
        return data;
    }
});
const tzOffsetParser = {
    parseValue: v => {
        let sign = -1;
        if (v.charAt(0) === '-') {
            sign = 1;
            v = v.slice(1);
        }
        const split = v.split(':');
        const hours = parseInt(split[0], 10);
        const minutes = parseInt(split[1], 10);
        return (hours * 60 + minutes) * sign;
    },
    writeValue: v => {
        if (typeof v === 'string') {
            return v;
        }
        else {
            let formatted = '-';
            if (v < 0) {
                v = -v;
                formatted = '+';
            }
            const hours = v / 60;
            const minutes = v % 60;
            formatted +=
                (hours < 10 ? '0' : '') + hours + ':' + (minutes < 10 ? '0' : '') + minutes;
            return formatted;
        }
    }
};
// ====================================================================
// Field Types
// ====================================================================
export const attribute = createAttributeType(stringParser, opts => (Object.assign({ dynamicDefault: opts.emitEmpty ? v => (v === '' ? '' : opts.staticDefault) : undefined }, opts)));
export const booleanAttribute = createAttributeType(boolParser);
export const integerAttribute = createAttributeType(integerParser);
export const floatAttribute = createAttributeType(floatParser);
export const dateAttribute = createAttributeType(dateParser);
export const namespacedAttribute = createNamespacedAttributeType(stringParser);
export const namespacedBooleanAttribute = createNamespacedAttributeType(boolParser);
export const namespacedIntegerAttribute = createNamespacedAttributeType(integerParser);
export const namespacedFloatAttribute = createNamespacedAttributeType(floatParser);
export const namespacedDateAttribute = createNamespacedAttributeType(dateParser);
export const childAttribute = createChildAttributeType(stringParser);
export const childBooleanAttribute = createChildAttributeType(boolParser);
export const childIntegerAttribute = createChildAttributeType(integerParser);
export const childFloatAttribute = createChildAttributeType(floatParser);
export const childDateAttribute = createChildAttributeType(dateParser);
export const text = (defaultValue) => createTextField(Object.assign({ staticDefault: defaultValue }, stringParser));
export const textJSON = () => createTextField(Object.assign({}, jsonParser));
export const textBuffer = (encoding = 'utf8') => createTextField(Object.assign({}, bufferParser(encoding)));
export function languageAttribute() {
    return {
        importer(xml, context) {
            return getLang(xml, context.lang);
        },
        exporter(xml, value, context) {
            if (value && value.toLowerCase() !== context.lang) {
                xml.setAttribute('xml:lang', value);
            }
            else {
                xml.setAttribute('xml:lang', undefined);
            }
        }
    };
}
export const childLanguageAttribute = (namespace, element) => createChildAttributeField(Object.assign({ converter: languageAttribute(), element, name: 'xml:lang', namespace }, stringParser));
export const childText = (namespace, element, defaultValue, emitEmpty = false) => createChildTextField(Object.assign({ element,
    emitEmpty, matchLanguage: true, namespace, staticDefault: defaultValue }, stringParser));
export const childTextBuffer = (namespace, element, encoding = 'utf8') => createChildTextField(Object.assign({ element, matchLanguage: true, namespace }, bufferParser(encoding)));
export const childDate = (namespace, element) => createChildTextField(Object.assign({ element,
    namespace }, dateParser));
export const childInteger = (namespace, element, defaultValue) => createChildTextField(Object.assign({ element,
    namespace, staticDefault: defaultValue }, integerParser));
export const childFloat = (namespace, element, defaultValue) => createChildTextField(Object.assign({ element,
    namespace, staticDefault: defaultValue }, floatParser));
export const childJSON = (namespace, element) => createChildTextField(Object.assign({ element,
    namespace }, jsonParser));
export function childTimezoneOffset(namespace, element) {
    return createChildTextField(Object.assign({ element,
        namespace, staticDefault: 0 }, tzOffsetParser));
}
export function childBoolean(namespace, element) {
    return {
        importer(xml) {
            const child = xml.getChild(element, namespace || xml.getNamespace());
            if (child) {
                return true;
            }
        },
        exporter(xml, value) {
            if (value) {
                findOrCreate(xml, namespace || xml.getNamespace(), element);
            }
        }
    };
}
const deepChildExporter = (path, xml, value) => {
    if (!value) {
        return;
    }
    let current = xml;
    for (const node of path) {
        current = findOrCreate(current, node.namespace || current.getNamespace(), node.element);
    }
    current.children.push(value.toString());
};
export function deepChildText(path, defaultValue) {
    return {
        importer(xml) {
            let current = xml;
            for (const node of path) {
                current = current.getChild(node.element, node.namespace || current.getNamespace());
                if (!current) {
                    return defaultValue;
                }
            }
            return current.getText() || defaultValue;
        },
        exporter(xml, value) {
            deepChildExporter(path, xml, value);
        }
    };
}
export function deepChildInteger(path, defaultValue) {
    return {
        importer(xml) {
            let current = xml;
            for (const node of path) {
                current = current.getChild(node.element, node.namespace || current.getNamespace());
                if (!current) {
                    return;
                }
            }
            const data = current.getText();
            if (data) {
                return parseInt(data, 10);
            }
            else if (defaultValue) {
                return defaultValue;
            }
        },
        exporter(xml, value) {
            deepChildExporter(path, xml, value);
        }
    };
}
export function deepChildBoolean(path) {
    return {
        importer(xml) {
            let current = xml;
            for (const node of path) {
                current = current.getChild(node.element, node.namespace || current.getNamespace());
                if (!current) {
                    return false;
                }
            }
            return true;
        },
        exporter(xml, value) {
            if (!value) {
                return;
            }
            let current = xml;
            for (const node of path) {
                current = findOrCreate(current, node.namespace || current.getNamespace(), node.element);
            }
        }
    };
}
export function deepMultipleChildText(path) {
    const finalChild = path.pop();
    return {
        importer(xml, context) {
            let current = xml;
            for (const node of path) {
                current = current.getChild(node.element, node.namespace || current.getNamespace());
                if (!current) {
                    return [];
                }
            }
            const result = [];
            const children = findAll(current, finalChild.namespace || current.getNamespace(), finalChild.element);
            const targetLanguage = getTargetLang(children, context);
            for (const child of children) {
                if (getLang(child, context.lang) === targetLanguage) {
                    result.push(child.getText());
                }
            }
            return result;
        },
        exporter(xml, values, context) {
            if (!values.length) {
                return;
            }
            let current = xml;
            for (const node of path) {
                current = findOrCreate(current, node.namespace || current.getNamespace(), node.element);
            }
            const { namespace, element } = finalChild;
            for (const value of values) {
                const child = createElement(namespace || current.getNamespace(), element, context.namespace, current);
                child.children.push(value);
                current.appendChild(child);
            }
        }
    };
}
export function childEnum(namespace, elements, defaultValue) {
    const elementNames = new Map();
    const valueNames = new Map();
    for (const el of elements) {
        if (typeof el === 'string') {
            elementNames.set(el, el);
            valueNames.set(el, el);
        }
        else {
            elementNames.set(el[1], el[0]);
            valueNames.set(el[0], el[1]);
        }
    }
    return {
        importer(xml) {
            for (const child of xml.children) {
                if (typeof child === 'string') {
                    continue;
                }
                else if (child.getNamespace() === (namespace || xml.getNamespace()) &&
                    elementNames.has(child.getName())) {
                    return elementNames.get(child.getName());
                }
            }
            return defaultValue;
        },
        exporter(xml, value) {
            if (valueNames.has(value)) {
                findOrCreate(xml, namespace, valueNames.get(value));
            }
        }
    };
}
export function childDoubleEnum(namespace, parentElements, childElements, defaultValue) {
    const parentNames = new Set(parentElements);
    const childNames = new Set(childElements);
    return {
        importer(xml) {
            for (const parent of xml.children) {
                if (typeof parent === 'string') {
                    continue;
                }
                else if (parent.getNamespace() === (namespace || xml.getNamespace()) &&
                    parentNames.has(parent.getName())) {
                    for (const child of parent.children) {
                        if (typeof child === 'string') {
                            continue;
                        }
                        else if (child.getNamespace() === (namespace || xml.getNamespace()) &&
                            childNames.has(child.getName())) {
                            return [parent.getName(), child.getName()];
                        }
                    }
                    return [parent.getName()];
                }
            }
            return defaultValue;
        },
        exporter(xml, value) {
            const parent = findOrCreate(xml, namespace, value[0]);
            if (value[1]) {
                findOrCreate(parent, namespace, value[1]);
            }
        }
    };
}
export function multipleChildText(namespace, element) {
    return {
        importer(xml, context) {
            const result = [];
            const children = findAll(xml, namespace || xml.getNamespace(), element);
            const targetLanguage = getTargetLang(children, context);
            for (const child of children) {
                if (getLang(child, context.lang) === targetLanguage) {
                    result.push(child.getText());
                }
            }
            return result;
        },
        exporter(xml, values, context) {
            for (const value of values) {
                const child = createElement(namespace || xml.getNamespace(), element, context.namespace, xml);
                child.children.push(value);
                xml.appendChild(child);
            }
        }
    };
}
export function multipleChildAttribute(namespace, element, name) {
    return {
        importer(xml) {
            const result = [];
            const children = xml.getChildren(element, namespace || xml.getNamespace());
            for (const child of children) {
                const childAttr = child.getAttribute(name);
                if (childAttr !== undefined) {
                    result.push(childAttr);
                }
            }
            return result;
        },
        exporter(xml, values, context) {
            for (const value of values) {
                const child = createElement(namespace || xml.getNamespace(), element, context.namespace, xml);
                child.setAttribute(name, value);
                xml.appendChild(child);
            }
        }
    };
}
export function multipleChildIntegerAttribute(namespace, element, name) {
    return {
        importer(xml) {
            const result = [];
            const children = xml.getChildren(element, namespace || xml.getNamespace());
            for (const child of children) {
                const childAttr = child.getAttribute(name);
                if (childAttr !== undefined) {
                    result.push(parseInt(childAttr, 10));
                }
            }
            return result;
        },
        exporter(xml, values, context) {
            for (const value of values) {
                const child = createElement(namespace || xml.getNamespace(), element, context.namespace, xml);
                child.setAttribute(name, value.toString());
                xml.appendChild(child);
            }
        }
    };
}
export function childAlternateLanguageText(namespace, element) {
    return {
        importer(xml, context) {
            const results = [];
            const children = findAll(xml, namespace || xml.getNamespace(), element);
            const seenLanuages = new Set();
            for (const child of children) {
                const langText = child.getText();
                if (langText) {
                    const lang = getLang(child, context.lang);
                    if (seenLanuages.has(lang)) {
                        continue;
                    }
                    results.push({ lang, value: langText });
                    seenLanuages.add(lang);
                }
            }
            return seenLanuages.size > 0 ? results : undefined;
        },
        exporter(xml, values, context) {
            for (const entry of values) {
                const val = entry.value;
                if (val) {
                    const child = createElement(namespace || xml.getNamespace(), element, context.namespace, xml);
                    if (entry.lang !== context.lang) {
                        child.setAttribute('xml:lang', entry.lang);
                    }
                    child.children.push(val);
                    xml.appendChild(child);
                }
            }
        }
    };
}
export function multipleChildAlternateLanguageText(namespace, element) {
    return {
        importer(xml, context) {
            const results = [];
            const langIndex = new Map();
            let hasResults = false;
            const children = findAll(xml, namespace || xml.getNamespace(), element);
            for (const child of children) {
                const langText = child.getText();
                if (langText) {
                    const lang = getLang(child, context.lang);
                    let langResults = langIndex.get(lang);
                    if (!langResults) {
                        langResults = [];
                        langIndex.set(lang, langResults);
                        results.push({ lang, value: langResults });
                    }
                    langResults.push(langText);
                    hasResults = true;
                }
            }
            return hasResults ? results : undefined;
        },
        exporter(xml, values, context) {
            for (const entry of values) {
                for (const val of entry.value) {
                    const child = createElement(namespace || xml.getNamespace(), element, context.namespace, xml);
                    if (entry.lang !== context.lang) {
                        child.setAttribute('xml:lang', entry.lang);
                    }
                    child.children.push(val);
                    xml.appendChild(child);
                }
            }
        }
    };
}
export function multipleChildEnum(namespace, elements) {
    const elementNames = new Map();
    const valueNames = new Map();
    for (const el of elements) {
        if (typeof el === 'string') {
            elementNames.set(el, el);
            valueNames.set(el, el);
        }
        else {
            elementNames.set(el[1], el[0]);
            valueNames.set(el[0], el[1]);
        }
    }
    return {
        importer(xml) {
            const results = [];
            for (const child of xml.children) {
                if (typeof child === 'string') {
                    continue;
                }
                else if (child.getNamespace() === (namespace || xml.getNamespace()) &&
                    elementNames.has(child.getName())) {
                    results.push(elementNames.get(child.getName()));
                }
            }
            return results;
        },
        exporter(xml, values) {
            for (const value of values) {
                findOrCreate(xml, namespace, valueNames.get(value));
            }
        }
    };
}
export function splicePath(namespace, element, path, multiple = false) {
    return {
        importer(xml, context) {
            const child = xml.getChild(element, namespace || xml.getNamespace());
            if (!child) {
                return;
            }
            const results = [];
            for (const grandChild of child.children) {
                if (typeof grandChild === 'string') {
                    continue;
                }
                if (context.registry.getImportKey(grandChild) === path) {
                    const imported = context.registry.import(grandChild);
                    if (imported) {
                        results.push(imported);
                    }
                }
            }
            return multiple ? results : results[0];
        },
        exporter(xml, data, context) {
            let values = [];
            if (!Array.isArray(data)) {
                values = [data];
            }
            else {
                values = data;
            }
            const children = [];
            for (const value of values) {
                const child = context.registry.export(path, value, Object.assign(Object.assign({}, context), { namespace: namespace || xml.getNamespace() || undefined }));
                if (child) {
                    children.push(child);
                }
            }
            if (children.length) {
                const skipChild = findOrCreate(xml, namespace || xml.getNamespace(), element);
                for (const child of children) {
                    skipChild.appendChild(child);
                }
            }
        }
    };
}
export function staticValue(value) {
    return {
        exporter: () => undefined,
        importer: () => value
    };
}
export function childRawElement(namespace, element, sanitizer) {
    return {
        importer(xml, context) {
            if (sanitizer && (!context.sanitizers || !context.sanitizers[sanitizer])) {
                return;
            }
            const child = xml.getChild(element, namespace || xml.getNamespace());
            if (child) {
                if (sanitizer) {
                    return context.sanitizers[sanitizer](child.toJSON());
                }
                else {
                    return child.toJSON();
                }
            }
        },
        exporter(xml, value, context) {
            if (typeof value === 'string') {
                const wrapped = parse(`<${element} xmlns="${namespace || xml.getNamespace()}">${value}</${element}>`);
                value = wrapped.toJSON();
            }
            if (sanitizer) {
                if (!context.sanitizers || !context.sanitizers[sanitizer]) {
                    return;
                }
                value = context.sanitizers[sanitizer](value);
            }
            if (value) {
                xml.appendChild(new XMLElement(value.name, value.attributes, value.children));
            }
        }
    };
}
export function childLanguageRawElement(namespace, element, sanitizer) {
    return {
        importer(xml, context) {
            if (sanitizer && (!context.sanitizers || !context.sanitizers[sanitizer])) {
                return;
            }
            const children = findAll(xml, namespace || xml.getNamespace(), element);
            const targetLanguage = getTargetLang(children, context);
            for (const child of children) {
                if (getLang(child, context.lang) === targetLanguage) {
                    if (sanitizer) {
                        return context.sanitizers[sanitizer](child.toJSON());
                    }
                    else {
                        return child.toJSON();
                    }
                }
            }
            if (children[0]) {
                if (sanitizer) {
                    return context.sanitizers[sanitizer](children[0].toJSON());
                }
                else {
                    return children[0].toJSON();
                }
            }
        },
        exporter(xml, value, context) {
            if (typeof value === 'string') {
                const wrapped = parse(`<${element} xmlns="${namespace || xml.getNamespace()}">${value}</${element}>`);
                value = wrapped.toJSON();
            }
            if (value && sanitizer) {
                if (!context.sanitizers || !context.sanitizers[sanitizer]) {
                    return;
                }
                value = context.sanitizers[sanitizer](value);
            }
            if (!value) {
                return;
            }
            const rawElement = findOrCreate(xml, namespace || xml.getNamespace(), element, context.lang);
            for (const child of value.children) {
                if (typeof child === 'string') {
                    rawElement.appendChild(child);
                }
                else if (child) {
                    rawElement.appendChild(new XMLElement(child.name, child.attributes, child.children));
                }
            }
        }
    };
}
export function childAlternateLanguageRawElement(namespace, element, sanitizer) {
    return {
        importer(xml, context) {
            if (sanitizer && (!context.sanitizers || !context.sanitizers[sanitizer])) {
                return;
            }
            const results = [];
            const seenLanuages = new Set();
            const children = findAll(xml, namespace || xml.getNamespace(), element);
            for (const child of children) {
                let result = child.toJSON();
                if (sanitizer) {
                    result = context.sanitizers[sanitizer](result);
                }
                if (result) {
                    const lang = getLang(child, context.lang);
                    if (seenLanuages.has(lang)) {
                        continue;
                    }
                    results.push({ lang, value: result });
                    seenLanuages.add(lang);
                }
            }
            return seenLanuages.size > 0 ? results : undefined;
        },
        exporter(xml, values, context) {
            for (const entry of values) {
                let value = entry.value;
                if (typeof value === 'string') {
                    const wrapped = parse(`<${element} xmlns="${namespace || xml.getNamespace()}">${value}</${element}>`);
                    value = wrapped.toJSON();
                }
                if (value && sanitizer) {
                    if (!context.sanitizers || !context.sanitizers[sanitizer]) {
                        continue;
                    }
                    value = context.sanitizers[sanitizer](value);
                }
                if (value) {
                    const rawElement = createElement(namespace || xml.getNamespace(), element, context.namespace, xml);
                    xml.appendChild(rawElement);
                    if (entry.lang !== context.lang) {
                        rawElement.setAttribute('xml:lang', entry.lang);
                    }
                    for (const child of value.children) {
                        if (typeof child === 'string') {
                            rawElement.appendChild(child);
                        }
                        else {
                            rawElement.appendChild(new XMLElement(child.name, child.attributes, child.children));
                        }
                    }
                }
            }
        }
    };
}
export function parameterMap(namespace, element, keyName, valueName) {
    return {
        importer(xml, context) {
            const result = {};
            const params = findAll(xml, namespace, element);
            const keyImporter = attribute(keyName).importer;
            const valueImporter = attribute(valueName).importer;
            for (const param of params) {
                result[keyImporter(param, context)] = valueImporter(param, context);
            }
            return result;
        },
        exporter(xml, values, context) {
            const keyExporter = attribute(keyName).exporter;
            const valueExporter = attribute(valueName).exporter;
            const ns = namespace || xml.getNamespace();
            for (const [param, value] of Object.entries(values)) {
                const paramEl = createElement(ns, element, context.namespace, xml);
                keyExporter(paramEl, param, context);
                if (values[param]) {
                    valueExporter(paramEl, value, context);
                }
                xml.appendChild(paramEl);
            }
        }
    };
}
