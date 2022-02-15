export default function (client, stanzas) {
  const types = stanzas.utils;
  stanzas.define({
    name: "iq",
    namespace: "jabber:client",
    element: "iq",
    topLevel: true,
    fields: {
        t: types.numberAttribute("t"), // message timestamp
        f: types.attribute("f"), // message id
        id: types.attribute("id"),
        to: types.jidAttribute("to", true),
        from: types.jidAttribute("from", true),
        type: types.attribute("type")
    }
  });
  const replaceMessage = stanzas.define({
    name: "replace",
    element: "replace",
    namespace: "urn:xmpp:message-correct:0",
    fields: {
      id: types.attribute("id"),
      value: types.text()
    }
  });

  stanzas.withMessage((Message) => {
    stanzas.extend(Message, replaceMessage);
  });


  let NS = "vcard-temp";
  let VCardTemp = stanzas.define({
      name: "vCardTemp",
      namespace: NS,
      element: "vCard",
      fields: {
          role: types.textSub(NS, "ROLE"),
          website: types.textSub(NS, "URL"),
          vncAppUser: types.textSub(NS, "X-VNC-APPUSER"),
          title: types.textSub(NS, "TITLE"),
          description: types.textSub(NS, "DESC"),
          fullName: types.textSub(NS, "FN"),
          birthday: types.dateSub(NS, "BDAY"),
          nicknames: types.multiTextSub(NS, "NICKNAME"),
          jids: types.multiTextSub(NS, "JABBERID")
      }
  });

  let Email = stanzas.define({
      name: "_email",
      namespace: NS,
      element: "EMAIL",
      fields: {
          email: types.textSub(NS, "USERID"),
          home: types.boolSub(NS, "HOME"),
          work: types.boolSub(NS, "WORK"),
          preferred: types.boolSub(NS, "PREF")
      }
  });

  let PhoneNumber = stanzas.define({
      name: "_tel",
      namespace: NS,
      element: "TEL",
      fields: {
          number: types.textSub(NS, "NUMBER"),
          home: types.boolSub(NS, "HOME"),
          work: types.boolSub(NS, "WORK"),
          mobile: types.boolSub(NS, "CELL"),
          preferred: types.boolSub(NS, "PREF")
      }
  });

  let Address = stanzas.define({
      name: "_address",
      namespace: NS,
      element: "ADR",
      fields: {
          street: types.textSub(NS, "STREET"),
          street2: types.textSub(NS, "EXTADD"),
          country: types.textSub(NS, "CTRY"),
          city: types.textSub(NS, "LOCALITY"),
          region: types.textSub(NS, "REGION"),
          postalCode: types.textSub(NS, "PCODE"),
          pobox: types.textSub(NS, "POBOX"),
          home: types.boolSub(NS, "HOME"),
          work: types.boolSub(NS, "WORK"),
          preferred: types.boolSub(NS, "PREF")
      }
  });

  let Organization = stanzas.define({
      name: "organization",
      namespace: NS,
      element: "ORG",
      fields: {
          name: types.textSub(NS, "ORGNAME"),
          unit: types.textSub(NS, "ORGUNIT")
      }
  });

  let Name = stanzas.define({
      name: "name",
      namespace: NS,
      element: "N",
      fields: {
          family: types.textSub(NS, "FAMILY"),
          given: types.textSub(NS, "GIVEN"),
          middle: types.textSub(NS, "MIDDLE"),
          prefix: types.textSub(NS, "PREFIX"),
          suffix: types.textSub(NS, "SUFFIX")
      }
  });

  let Photo = stanzas.define({
      name: "photo",
      namespace: NS,
      element: "PHOTO",
      fields: {
          type: types.textSub(NS, "TYPE"),
          data: types.textSub(NS, "BINVAL"),
          url: types.textSub(NS, "EXTVAL")
      }
  });

  stanzas.extend(VCardTemp, Email, "emails");
  stanzas.extend(VCardTemp, Address, "addresses");
  stanzas.extend(VCardTemp, PhoneNumber, "phoneNumbers");
  stanzas.extend(VCardTemp, Organization);
  stanzas.extend(VCardTemp, Name);
  stanzas.extend(VCardTemp, Photo);
  stanzas.extendIQ(VCardTemp);
}