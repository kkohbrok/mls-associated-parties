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
- All members of the group agree on the key material shared with each associated
  party

The mechanism makes the following assumptions:

- All associated parties keep track of the group state on a per-commit basis
  including the group’s RatchetTree and GroupInfo

# Overview

The mechanism sketched in this document allows members of an MLS group to add
one or more associated parties (APs). With each AP the group shares secret key
material that is evolved with each epoch in the same fashion as the MLS key
schedule.

The list of APs is part of the group state and thus covered by MLS' group
agreement properties. APs can act as external senders and thus send proposals to
the group (but can't commit them).

APs can be added, updated or removed by group members via proposals.

# Associated partys

An Associated party (AP) is represented in groups through AssociatedPartyEntry
struct, which contains the APs credential and signature public key, as well as
the HPKE encryption key to which the shared key material is encrypted.

~~~ tls
struct {
  HPKEPublicKey encryption_key;
  SignaturePublicKey signature_key;
  Credential credential;
  opaque signature;
} AssociatedPartyEntry

struct {
  HPKEPublicKey encryption_key;
  SignaturePublicKey signature_key;
  Credential credential;
} AssociatedPartyEntryTBS
~~~

The `signature` in an AssociatedPartyEntry MUST be a valid signature under the
`signature_key` over an AssociatedPartyEntryTBS with matching fields.

The APs of a group are listed in the group's AssociatedParties GroupContext
extension.

~~~ tls
struct {
  AssociatedPartyEntry associated_parties<V>;
} AssociatedParties
~~~

## Associated parties as external senders

Associated parties can act as external senders and thus send external proposals
as specified in Section 12.1.8 of {{!RFC9420}}. An AP that sends an external
proposal MUST use the `external` SenderType with an index that is the number of
entries in the group's `external_senders` (0 if no such extension is present)
plus its own index in the group's AssociatedParties extension. For external
sender indices, the AssociatedParties extension thus extends the
`external_senders` extension.

Recipients of a message sent by an AP MUST verify the message's signature
against the `signature_key` in the sender's AssociatedPartyEntry.

## Managing associated parties

APs can be added, removed or updated via Add-, Remove-, or UpdateAssociatedParty
proposals.

~~~ tls
struct {
  AssociatedPartyEntry new_party;
} AddAssociatedParty

struct {
  u32 removed_party_index;
} RemoveAssociatedParty

struct {
  AssociatedPartyEntry updated_party;
} UpdateAssociatedParty
~~~

When a group member commits one or more of theses proposals, the
AssociatedParties extension is updated accordingly.

- The associated parties in the `removed_party_index`es of all
  RemoveAssociatedParty proposals are removed from the `associated_parties` vector.
- The `new_party` AssociatedPartyEntry in all AddAssociatedParty proposals are
  apended to the `associated_parties` vector.
- The AssociatedPartyEntries in the `associated_parties` vector of the senders
  of all UpdateAssociatedParty proposals are replaced by the `update_party` in
  the respective proposal.

Open Question: Do we want to restrict UpdateAssociatedParty proposals to be sent
only by the affected AP? If we don't do that, we may run into the same problem
as we do with KeyPackages, where key material is "updated" to key material that
is actually older than the current one.

# Exporting the AP secrets

With each new epoch, new, distinct secrets are exported from the MLS key
schedule for each AP. The secrets are then sent to the AP and injected into the
respective AP key schedules (see {{associated-party-key-schedule}}).

## Derivation from the MLS key schedule

After a group member creates a commit, it exports the `ap_secret` from the
group’s new `epoch_secret`. The `ap_secret` is then used to derive the
`ap_commit_base_secret` for each associated party, where `context` is the
AssociatedPartyExportContext with `ap_index` as the associated party's index in
the AssociatedParties extension and `ap_entry` as the associated party's
AssociatedPartyEntry.

~~~ tls
ap_secret =
  DeriveExtensionSecret(epoch_secret, "AP Secret")

struct {
  u32 ap_index;
  AssociatedPartyEntry ap_entry;
} AssociatedPartyExportContext

ap_commit_base_secret =
  ExpandWithLabel(ap_secret, "AP Commit Base Secret",
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

## AP secret encryption

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
ensure that everyone got the same base secret. The `ap_commit_secret` is used to
compute the new epoch of the associated party key schedule as described in
{{associated-party-key-schedule}}.

Open Question: Do we want a completely new message format here? It would
probably be easier to extend the `ContentType` enum, which would allow this
document to re-use the PublicMessage semantics. The content should then consist
of `kem_output`, `ciphertext and `ap_commit_secret_id`.

# Associated party key schedule

The secrets exported from the MLS key schedule and sent to the APs as described
in {{exporting-the-ap-secrets}} drive the AP key schedule, a simple key schedule
that mimics the MLS key schedule. In each epoch, the newly added key material is
combined with the key material from the previous epoch to derive the `ap_init`
for the next epoch and the `ap_exporter`. The `ap_exporter` keys a puncturable
pseudorandom function (PPRF), which the application or other MLS extensions can
use to derive further secrets.

~~~ aasvg
                ap_init_secret_[n-1]
                        |
                        |
                        V
ap_commit_secret --> KDF.Extract
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
                ap_init_secret_[n]
~~~
{: title="The Associated Party Key Schedule" #ap-key-schedule }

As the `ap_commit_secret` is distinct for each AP, each AP has its own key
schedule. Key material is thus shared between the group and each AP individually
s.t. APs don't share key material with one-another.

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
