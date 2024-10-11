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
 - next generation
 - unicorn
 - sparkling distributed ledger
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
- All external parties publish LeafNodes that can be retrieved by group members
  to add the owner to a group as an associated party

# Overview

The mechanism sketched in this document is essentially a copy of the MLS key
schedule shared with an individual external party (with a distinct key schedule
for each such party).

The key material of each epoch carries over to the previous epoch, where new key
material is injected into the key schedule with each commit.

# Managing associated parties of a group

AssociatedParties of a group are listed in the AssociatedParties GroupContext
extension.

~~~ tls
struct {
  LeafNode associated_parties<V>;
} AssociatedParties
~~~

A group member can add or remove associated parties in the context of a group by
sending Add- or RemoveAssociatedParty proposals.

~~~ tls
struct {
  LeafNode new_party;
} AddAssociatedParty

struct {
  u32 removed_party_index;
} RemoveAssociatedParty
~~~

Associated parties act as external senders and can additionally send
UpdateAssociatedParty proposals to update their own key material.

~~~ tls
struct {
  LeafNode updated_party;
} UpdateAssociatedParty
~~~

When a group member commits one or more of theses proposals, the
AssociatedParties extension is updated accordingly.

- The associated parties in the `removed_party_index`es of all
  RemoveAssociatedParty proposals are removed from the `associated_parties` vector.
- The `new_party` LeafNodes in all AddAssociatedParty proposals are apended to
  the `associated_parties` vector.
- The LeafNode in the `associated_parties` vector of the senders of all
  UpdateAssociatedParty proposals are replaced by the `update_party` in the
  respective proposal.

# Associated party key schedule

An associated party key schedule is a key schedule that group members share with
an associated party. It follows the same pattern as the main MLS key schedule,
where fresh randomness is injected with each epoch and a secret from the old
epoch is used to seed the next. Associated party key schedules are separate for
each associated party.


TODO: For all sections below, specify how exactly the keys are derived.

TODO: Add visual showing the flow of the key schedule like in the MLS RFC.

# Injecting randomness with each commit

Whenever a group member creates a commit, it exports the
AssociatedPartyCommitBaseSecret from the group’s key schedule (of the new epoch)
for each associated party. From the AssociatedPartyCommitBaseSecret, the
committer derives the AssociatedPartyCommitSecret and the
AssociatedPartyCommitSecretId. The committer then HPKE-encrypts the
AssociatedPartyCommitSecret to the encryption_key in the LeafNode of the
associated party, using the AssociatedPartyCommitSecretId as AAD. 

The HPKE ciphertext and the AssociatedPartyCommitSecretId are sent as a separate
message stapled to the commit. The associated party can decrypt the ciphertext
to get the AssociatedPartyCommitBaseSecret. Other group members receiving the
commit export the AssociatedPartyCommitBaseSecret from the key schedule of the
new epoch.

Both associated party and all other group members finally derive the
AssociatedPartyCommitSecretId and the AssociatedPartyCommitSecret. They compare
the AssociatedPartyCommitSecretId to the one they received along with the
ciphertext to ensure that everyone got the same base secret. The
AssociatedPartyCommitSecret is later used to compute the new epoch of the
associated party key schedule. 

## Randomness contributions from associated parties

Associated parties can also contribute secret key material to the shared key
schedule. An associated party can do so by sampling fresh randomness and
HPKE-encrypting it to the public key in the group’s ExternalPub GroupInfo
extension (if present). The associated party then includes the resulting HPKE
ciphertext in an AssociatedPartySecret proposal and sends it to the group. That
secret is injected into the associated party key schedule in the epoch in which
it is committed. 

## Computing a new key schedule epoch and exporting secrets

In each epoch, the AssociatedPartyInitSecret of the previous epoch, the
AssociatedPartyCommitSecret of this epoch, as well as any secrets from
AssociatedPartySecret proposals are used to derive this epoch’s
AssociatedPartyEpochSecret. If the associated party was added in this epoch, the
AssociatedPartyInitSecret of the past epoch is 0. Just like in the MLS key
schedule, the GroupContext is used as context in the operation to derive the
AssociatedPartyEpochSecret.

The AssociatedPartyEpochSecret is used to derive two secrets: The
AssociatedPartyInitSecret of this epoch and the AssociatedPartyExporterSecret.
The former is stored until the next epoch starts. The latter is used to seed a
PPRF from which the application or other extensions can sample further secrets,
domain-separated by an application-provided string or the extension ID.

All AssociatedParty-secrets are deleted after use.

# Sharing associated party secrets with new group members

When adding new group members via Welcome messages, the current
AssociatedPartyInitSecrets of all associated parties are included in an
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
AssociatedPartyInitSecret is set to 0.


# Security Considerations

TODO Security


# IANA Considerations

This document registers the AssociatedParties extension with ID 0xXXXX.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
