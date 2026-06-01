// ====================================================================
// XEP-0261: Jingle In-Band Bytestreams Transport Method
// --------------------------------------------------------------------
// Source: https://xmpp.org/extensions/xep-0047.html
// Version: 1.0 (2011-09-23)
// ====================================================================
import { attribute, integerAttribute } from '../jxt';
import { NS_JINGLE_IBB_1 } from '../Namespaces';
const Protocol = {
    element: 'transport',
    fields: {
        ack: {
            importer(xml, context) {
                const stanza = attribute('stanza', 'iq').importer(xml, context);
                return stanza !== 'message';
            },
            exporter(xml, data, context) {
                if (data === false) {
                    attribute('stanza').exporter(xml, 'message', context);
                }
            }
        },
        blockSize: integerAttribute('block-size'),
        sid: attribute('sid')
    },
    namespace: NS_JINGLE_IBB_1,
    path: 'iq.jingle.contents.transport',
    type: NS_JINGLE_IBB_1,
    typeField: 'transportType'
};
export default Protocol;
