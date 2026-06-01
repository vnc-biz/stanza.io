// ====================================================================
// RFC 4287: The Atom Syndication Format
// --------------------------------------------------------------------
// Source: https://tools.ietf.org/html/rfc4287
// ====================================================================
import { attribute, childDate, childText, pubsubItemContentAliases, text } from '../jxt';
import { NS_ATOM } from '../Namespaces';
const Protocol = [
    {
        aliases: ['atomentry', ...pubsubItemContentAliases()],
        element: 'entry',
        fields: {
            id: childText(null, 'id'),
            published: childDate(null, 'published'),
            updated: childDate(null, 'updated')
        },
        namespace: NS_ATOM,
        type: NS_ATOM,
        typeField: 'itemType'
    },
    {
        element: 'summary',
        fields: {
            text: text(),
            type: attribute('type', 'text')
        },
        namespace: NS_ATOM,
        path: 'atomentry.summary'
    },
    {
        element: 'title',
        fields: {
            text: text(),
            type: attribute('type', 'text')
        },
        namespace: NS_ATOM,
        path: 'atomentry.title'
    },
    {
        aliases: [{ path: 'atomentry.links', multiple: true }],
        element: 'link',
        fields: {
            href: attribute('href'),
            mediaType: attribute('type'),
            rel: attribute('rel')
        },
        namespace: NS_ATOM
    },
    {
        aliases: [{ path: 'atomentry.authors', multiple: true }],
        element: 'author',
        fields: {
            name: childText(null, 'name'),
            uri: childText(null, 'uri'),
            email: childText(null, 'email')
        },
        namespace: NS_ATOM
    },
    {
        aliases: [{ path: 'atomentry.contributors', multiple: true }],
        element: 'contributor',
        fields: {
            name: childText(null, 'name'),
            uri: childText(null, 'uri'),
            email: childText(null, 'email')
        },
        namespace: NS_ATOM
    },
    {
        aliases: [{ path: 'atomentry.categories', multiple: true }],
        element: 'category',
        fields: {
            term: attribute('term'),
            scheme: attribute('scheme'),
            label: attribute('label')
        },
        namespace: NS_ATOM
    },
    {
        element: 'content',
        fields: {
            text: text(),
            type: attribute('type', 'text')
        },
        namespace: NS_ATOM,
        path: 'atomentry.content'
    },
    {
        element: 'rights',
        fields: {
            text: text(),
            type: attribute('type', 'text')
        },
        namespace: NS_ATOM,
        path: 'atomentry.rights'
    }
];
export default Protocol;
