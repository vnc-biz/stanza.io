// ====================================================================
// XEP-0247: Jingle XML Streams
// --------------------------------------------------------------------
// Source: https://xmpp.org/extensions/xep-0247.html
// Version: 0.2 (2009-02-20)
// ====================================================================
import { NS_JINGLE_XML_0 } from '../Namespaces';
const Protocol = {
    element: 'description',
    namespace: NS_JINGLE_XML_0,
    path: 'iq.jingle.contents.application',
    type: NS_JINGLE_XML_0,
    typeField: 'applicationType'
};
export default Protocol;
