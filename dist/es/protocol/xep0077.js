// ====================================================================
// XEP-0077: In-Band Registration
// --------------------------------------------------------------------
// Source: https://xmpp.org/extensions/xep-0077.html
// Version: 2.4 (2012-01-253)
// ====================================================================
import { addAlias, childBoolean, childDate, childText, extendStreamFeatures } from '../jxt';
import { NS_DATAFORM, NS_INBAND_REGISTRATION, NS_OOB, NS_REGISTER } from '../Namespaces';
const Protocol = [
    extendStreamFeatures({
        inbandRegistration: childBoolean(NS_INBAND_REGISTRATION, 'register')
    }),
    addAlias(NS_DATAFORM, 'x', ['iq.account.form']),
    addAlias(NS_OOB, 'x', ['iq.account.registrationLink']),
    {
        element: 'query',
        fields: {
            address: childText(null, 'address'),
            date: childDate(null, 'date'),
            email: childText(null, 'email'),
            familyName: childText(null, 'last'),
            fullName: childText(null, 'name'),
            givenName: childText(null, 'first'),
            instructions: childText(null, 'instructions'),
            key: childText(null, 'key'),
            locality: childText(null, 'city'),
            misc: childText(null, 'misc'),
            nick: childText(null, 'nick'),
            password: childText(null, 'password'),
            phone: childText(null, 'phone'),
            postalCode: childText(null, 'zip'),
            region: childText(null, 'state'),
            registered: childBoolean(null, 'registered'),
            remove: childBoolean(null, 'remove'),
            text: childText(null, 'text'),
            uri: childText(null, 'uri'),
            username: childText(null, 'username')
        },
        namespace: NS_REGISTER,
        path: 'iq.account'
    }
];
export default Protocol;
