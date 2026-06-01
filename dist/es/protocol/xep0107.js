// ====================================================================
// XEP-0107: User Mood
// --------------------------------------------------------------------
// Source: https://xmpp.org/extensions/xep-0107.html
// Version: 1.2.1 (2018-03-13)
// ====================================================================
import { USER_MOODS } from '../Constants';
import { childAlternateLanguageText, childEnum, childText, pubsubItemContentAliases } from '../jxt';
import { NS_MOOD } from '../Namespaces';
const Protocol = {
    aliases: [{ path: 'message.mood', impliedType: true }, ...pubsubItemContentAliases()],
    element: 'mood',
    fields: {
        alternateLanguageText: childAlternateLanguageText(null, 'text'),
        text: childText(null, 'text'),
        value: childEnum(null, USER_MOODS)
    },
    namespace: NS_MOOD,
    type: NS_MOOD
};
export default Protocol;
