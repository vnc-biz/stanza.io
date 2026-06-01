import JXTError from './Error';
const ESCAPE_XML_CHAR = {
    '"': '&quot;',
    '&': '&amp;',
    "'": '&apos;',
    '<': '&lt;',
    '>': '&gt;'
};
const UNESCAPE_XML_CHAR = {
    '&amp;': '&',
    '&apos;': "'",
    '&gt;': '>',
    '&lt;': '<',
    '&quot;': '"'
};
const ESCAPE_SEQUENCE = /&([a-zA-Z0-9]+|#[0-9]+|#x[0-9a-fA-F]+);/g;
const NEED_ESCAPING = /&|<|>|"|'/g;
const NEED_ESCAPING_TEXT = /&|<|>/g;
function escapeXMLReplaceChar(match) {
    return ESCAPE_XML_CHAR[match];
}
function unescapeXMLReplaceChar(match) {
    if (UNESCAPE_XML_CHAR[match]) {
        return UNESCAPE_XML_CHAR[match];
    }
    const hex = match.startsWith('&#x');
    const code = parseInt(match.substring(hex ? 3 : 2, match.length - 1), hex ? 16 : 10);
    if (code === 0x9 ||
        code === 0xa ||
        code === 0xd ||
        (0x20 <= code && code <= 0xd7ff) ||
        (0xe000 <= code && code <= 0xfffd) ||
        (0x10000 <= code && code <= 0x10ffff)) {
        return String.fromCodePoint(code);
    }
    throw JXTError.restrictedXML('Prohibited entity: ' + match);
}
export function escapeXML(text) {
    return text.replace(NEED_ESCAPING, escapeXMLReplaceChar);
}
export function unescapeXML(text) {
    return text.replace(ESCAPE_SEQUENCE, match => {
        return unescapeXMLReplaceChar(match);
    });
}
export function escapeXMLText(text) {
    return text.replace(NEED_ESCAPING_TEXT, escapeXMLReplaceChar);
}
export function basicLanguageResolver(available, accept = [], current = '') {
    const avail = new Set(available.map(a => a.toLowerCase()));
    for (let acceptLang of accept.map(a => a.toLowerCase())) {
        if (acceptLang === '*') {
            continue;
        }
        while (acceptLang.length > 0) {
            if (avail.has(acceptLang)) {
                return acceptLang;
            }
            // Remove ending tag
            acceptLang = acceptLang.substring(0, acceptLang.lastIndexOf('-')).toLowerCase();
            // Remove leftover single character tag
            if (acceptLang.lastIndexOf('-') === acceptLang.length - 2) {
                acceptLang = acceptLang.substring(0, acceptLang.lastIndexOf('-'));
            }
        }
    }
    return current;
}
