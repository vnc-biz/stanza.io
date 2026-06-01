// ====================================================================
// XEP-0224: Attention
// --------------------------------------------------------------------
// Source: https://xmpp.org/extensions/xep-0224.html
// Version: Version 1.0 (2008-11-13)
// ====================================================================
import { childBoolean, extendMessage } from '../jxt';
import { NS_ATTENTION_0 } from '../Namespaces';
export default extendMessage({
    requestingAttention: childBoolean(NS_ATTENTION_0, 'attention')
});
