---
title: "MLS Associated parties"
abbrev: "MLSAP"
category: info

docname: draft-kohbrok-mls-associated-parties-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "Messaging Layer Security"
keyword:
 - security
 - messaging layer security
venue:
  group: "Messaging Layer Security"
  type: "Working Group"
  mail: "mls@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/mls/"
  github: "kkohbrok/mls-associated-parties"
  latest: "https://kkohbrok.github.io/mls-associated-parties/draft-kohbrok-mls-associated-parties.html"

author:
 -
    fullname: "Konrad Kohbrok"
    organization: Phoenix R&D
    email: "konrad.kohbrok@datashrine.de"
 -
    fullname: "Raphael Robert"
    organization: Phoenix R&D
    email: "ietf@raphaelrobert.com"

normative:

informative:


--- abstract

The Messaging Layer Security (MLS) protocol allows a group of clients to
exchange symmetric keys, agree on group state and send application messages.

The main purpose of an MLS group is thus to facilitate agreement on group state
and key material between the members of the group. In some cases, however, it is
useful to share agreement on the (public) group state, as well as key material
with another party that is not a full member of the group.

This document describes a safe extension to do just that.

--- middle

# Introduction

This document outlines a mechanism that allows an MLS group (i.e. the members
thereof) to share key material with one or more associated parties such as a
server acting as the delivery service.

The mechanism provides the following properties:

- All members of the group agree on the associated parties and their public key
  material
- All members of the group agree on the key material shared with the associated
  parties

The mechanism makes the following assumptions:

- All associated parties keep track of the group state on a per-commit basis
  including the group’s RatchetTree and GroupInfo
- All external parties publish AssociatedPartyEntries that can be retrieved by
  group members to add the owner to a group as an associated party

# Overview

The mechanism sketched in this document is essentially a copy of the MLS key
schedule shared with an individual external party (with a distinct key schedule
for each such party).

The key material of each epoch carries over to the previous epoch, where new key
material is injected into the key schedule with each commit.

# Associated party entries

Any party that wants to be eligible as an associated party to an MLS group must
publish the key material required.

~~~ tls
enum {
  reserved(0),
  published(1),
  update(2),
  (255)
} AssociatedPartyEntrySource;

struct {
  HPKEPublicKey encryption_key;
  SignaturePublicKey signature_key;
  Credential credential;
  AssociatedPartyEntrySource source;
  select (AssociatedPartyEntry.source) {
    case published:
        Lifetime lifetime;

    case update:
        struct{};
  };
} AssociatedPartyEntry

struct {
    HPKEPublicKey encryption_key;
    SignaturePublicKey signature_key;
    Credential credential;

    AssociatedPartyEntrySource source;
    select (AssociatedPartyEntryTBS.source) {
        case published:
            Lifetime lifetime;
        case update:
            struct{};
    };

    select (AssociatedPartyEntryTBS.source) {
        case published:
            struct{};

        case update:
            opaque group_id<V>;
            uint32 leaf_index;
    };
} AssociatedPartyEntryTBS
~~~

All published AssociatedPartyEntries MUST have their `source` set to
`published`.

Published AssociatedPartyEntries can be retrieved by MLS group members for use
in AddAssociatedParty proposals as described in {{managing-associated-parties}}.

Open Question: Do we want an extension version in these structs?

Open Question: Do we want to support AP capabilities? That would allow us to
support AP extensions as well.

# Managing associated parties

AssociatedParties of a group are listed in the AssociatedParties GroupContext
extension.

~~~ tls
struct {
  AssociatedPartyEntry associated_parties<V>;
} AssociatedParties
~~~

A group member can add or remove associated parties in the context of a group by
sending Add- or RemoveAssociatedParty proposals.

~~~ tls
struct {
  AssociatedPartyEntry new_party;
} AddAssociatedParty

struct {
  u32 removed_party_index;
} RemoveAssociatedParty
~~~

Any AssociatedPartyEntry in an AddAssociatedParty proposal MUST have `source`
set to `published`.

Associated parties act as external senders and can additionally send
UpdateAssociatedParty proposals to update their own key material.

~~~ tls
struct {
  AssociatedPartyEntry updated_party;
} UpdateAssociatedParty
~~~

Any AssociatedPartyEntry in an UpdateAssociatedParty proposal MUST have `source`
set to `update`.

When a group member commits one or more of theses proposals, the
AssociatedParties extension is updated accordingly.

- The associated parties in the `removed_party_index`es of all
  RemoveAssociatedParty proposals are removed from the `associated_parties` vector.
- The `new_party` AssociatedPartyEntry in all AddAssociatedParty proposals are
  apended to the `associated_parties` vector.
- The AssociatedPartyEntries in the `associated_parties` vector of the senders
  of all UpdateAssociatedParty proposals are replaced by the `update_party` in
  the respective proposal.

# Associated party key schedule

An associated party key schedule is a key schedule that group members share with
an associated party. It follows the same pattern as the main MLS key schedule,
where fresh randomness is injected with each epoch and a secret from the old
epoch is used to seed the next. Associated party key schedules are separate for
each associated party.

~~~ aasvg
                         ap_init_secret_[n-1]
                                 |
                                 |
                                 V
         ap_commit_secret --> KDF.Extract
                                 |
                                 |
                                 V
ap_proposal_secret (or 0) --> KDF.Extract
                                 |
                                 |
                                 V
                         ExpandWithLabel(., "ap_epoch", GroupContext_[n], KDF.Nh)
                                 |
                                 |
                                 V
                           ap_epoch_secret
                                 |
                                 |
                                 +--> DeriveSecret(., "ap_exporter")
                                 |    = ap_exporter_secret
                                 |
                                 V
                           DeriveSecret(., "init")
                                 |
                                 |
                                 V
                           init_secret_[n]
~~~
{: title="The Associated Party Key Schedule" #ap-key-schedule }

# Injecting randomness with each commit

Whenever a group member creates a commit, it exports the `associated_parties_secret`
from the group’s `epoch_secret` (of the new epoch). The `ap_exporter_secret` is
then used to derive the `ap_commit_base_secret` for each associated party, where
`context` is the AssociatedPartyExportContext with `ap_index` as the associated
party's index in the AssociatedParties extension and `ap_entry` as the
associated party's AssociatedPartyEntry.

~~~ tls
associated_parties_secret =
  DeriveExtensionSecret(epoch_secret, "AP Exporter Secret")

struct {
  u32 ap_index;
  AssociatedPartyEntry ap_entry;
} AssociatedPartyExportContext

ap_commit_base_secret =
  ExpandWithLabel(associated_parties_secret, "AP Commit Base Secret",
                    context, KDF.Nh)
~~~

From the `ap_commit_base_secret`, the committer derives the `ap_commit_secret`
and the `ap_commit_secret_id`.

~~~ tls
ap_commit_secret =
  DeriveSecret(ap_commit_base_secret, "AP Commit Secret")

ap_commit_secret_id =
  DeriveSecret(ap_commit_base_secret, "AP Commit Secret ID")
~~~

The committer then encrypts the `ap_commit_base_secret` with an
AssociatedPartyCommitEncryptionContext as `context`, where `group_context` is
the context of the group's new epoch.

~~~ tls
struct {
  opaque label = "AP Commit Secret";
  GroupContext group_context;
  opaque ap_commit_secret_id<V>;
} AssociatedPartyCommitEncryptionContext;

(kem_output, ciphertext) =
  SafeEncryptWithContext(0xXXXX, external_pub, context,
                          ap_commit_base_secret)
~~~

`kem_output`, `ciphertext` and the `ap_commit_secret_id` are sent as a separate
message stapled to the commit. The associated party can decrypt the ciphertext
to get the `ap_commit_base_secret`. Other group members receiving the commit
export the `ap_commit_base_secret` from the key schedule of the new epoch.

Both associated party and all other group members finally derive the
`ap_commit_secret_id` and the `ap_commit_secret`. They compare the
`ap_commit_secret_id` to the one they received along with the ciphertext to
ensure that everyone got the same base secret. The `ap_commit_secret` is later
used to compute the new epoch of the associated party key schedule.

TODO: We probably want a distinct WireFormat for the message with `kem_output`,
`ciphertext and `ap_commit_secret_id`. That message should also be authenticated
using a signature.

## Randomness contributions from associated parties

Associated parties can also contribute secret key material to the shared key
schedule. An associated party can do so by sampling fresh randomness and
HPKE-encrypting it to the public key in the group’s ExternalPub GroupInfo
extension (if present). The associated party then includes the resulting HPKE
ciphertext in an AssociatedPartySecret proposal and sends it to the group. That
secret is injected into the associated party key schedule in the epoch in which
it is committed.

~~~ tls
struct {
  opaque associated_party_proposal_secret<V>;
} AssociatedPartySecret;
~~~

TODO: Since the `ap_commit_secret`s come from the MLS key schedule and any
AssociatedPartySecret proposals are included in the transcript, the group should
always be in agreement on what the AP key schedule looks like. Is additional
binding necessary by injecting something from the AP key schedule back into the
MLS key schedule?

## Computing a new key schedule epoch and exporting secrets

In each epoch, the `ap_init_secret` of the previous epoch, the
`ap_commit_secret` of this epoch, as well as any secrets from
AssociatedPartySecret proposals are used to derive this epoch’s
`ap_epoch_secret` as shown in {{ap-key-schedule}}. If the associated party was
added in this epoch, the `ap_init_secret` of the past epoch is 0. Just like in
the MLS key schedule, the GroupContext is used as context in the operation to
derive the `ap_epoch_secret`.

The `ap_epoch_secret` is used to derive two secrets: The `ap_init_secret` of
this epoch and the `ap_exporter_secret`. The former is stored until the next
epoch starts. The latter is used to seed a PPRF from which the application or
other extensions can sample further secrets, domain-separated by an
application-provided string or the extension ID.

All `ap_`-secrets are deleted after use.

# Sharing associated party secrets with new group members

When adding new group members via Welcome messages, the current
`ap_init_secret`s of all associated parties are included in an
AssociatedPartySecrets GroupInfo extension, ordered per associated party
according to the `associated_parties` vector in the group's AssociatedParties
extension.

~~~ tls
struct {
  opaque associated_party_init_secret<V>;
} AssociatedPartySecrets
~~~

When a new member joins via external commit, it creates the HPKE ciphertext and
key id in the same way as a normal committer would. When deriving the secrets
for the new epoch of the associated party key schedule, the
`ap_init_secret` is set to 0.


# Security Considerations

TODO Security


# IANA Considerations

This document registers the AssociatedParties extension with ID 0xXXXX.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
