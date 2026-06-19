import { createGroup, joinGroup } from "../../src/clientState.js"
import { createProposal, createSelfRemoveProposal } from "../../src/createMessage.js"
import { Credential } from "../../src/credential.js"
import { defaultCredentialTypes } from "../../src/defaultCredentialType.js"
import { CiphersuiteName, ciphersuites } from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { generateKeyPackage } from "../../src/keyPackage.js"
import { ProposalAdd } from "../../src/proposal.js"
import { selfRemoveProposalType } from "../../src/selfRemove.js"
import { checkHpkeKeysMatch } from "../crypto/keyMatch.js"
import {
  cannotMessageAnymore,
  createCommitEnsureNoMutation,
  processMessageEnsureNoMutation,
  testEveryoneCanMessageEveryone,
} from "./common.js"
import { acceptAll } from "../../src/incomingMessageAction.js"
import { defaultProposalTypes } from "../../src/defaultProposalType.js"
import { wireformats } from "../../src/wireformat.js"
import { unsafeTestingAuthenticationService } from "../../src/authenticationService.js"

test.concurrent.each(Object.keys(ciphersuites))(`SelfRemove Proposal %s`, async (cs) => {
  await selfRemove(cs as CiphersuiteName, true)
  await selfRemove(cs as CiphersuiteName, false)
})

// Alice proposes her own removal with a self_remove proposal (empty body; she is
// the sender). Bob commits it by reference — RFC 9420 §12.2 forbids the committer
// from removing their own leaf, but a self_remove is committed by another member.
// Alice ends up removed; Bob and Charlie converge and can still message.
async function selfRemove(cipherSuite: CiphersuiteName, publicMessage: boolean) {
  const impl = await getCiphersuiteImpl(cipherSuite)
  const ctx = { cipherSuite: impl, authService: unsafeTestingAuthenticationService }
  const preferredWireformat = publicMessage ? wireformats.mls_public_message : wireformats.mls_private_message

  const aliceCredential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: new TextEncoder().encode("alice"),
  }
  const alice = await generateKeyPackage({ credential: aliceCredential, cipherSuite: impl })

  const groupId = new TextEncoder().encode("group1")
  let aliceGroup = await createGroup({
    context: ctx,
    groupId,
    keyPackage: alice.publicPackage,
    privateKeyPackage: alice.privatePackage,
  })

  const bob = await generateKeyPackage({
    credential: { credentialType: defaultCredentialTypes.basic, identity: new TextEncoder().encode("bob") },
    cipherSuite: impl,
  })
  const charlie = await generateKeyPackage({
    credential: { credentialType: defaultCredentialTypes.basic, identity: new TextEncoder().encode("charlie") },
    cipherSuite: impl,
  })

  const addBobProposal: ProposalAdd = {
    proposalType: defaultProposalTypes.add,
    add: { keyPackage: bob.publicPackage },
  }
  const addCharlieProposal: ProposalAdd = {
    proposalType: defaultProposalTypes.add,
    add: { keyPackage: charlie.publicPackage },
  }

  const addCommit = await createCommitEnsureNoMutation({
    context: ctx,
    state: aliceGroup,
    wireAsPublicMessage: publicMessage,
    extraProposals: [addBobProposal, addCharlieProposal],
    ratchetTreeExtension: true,
  })
  aliceGroup = addCommit.newState

  let bobGroup = await joinGroup({
    context: ctx,
    welcome: addCommit.welcome!.welcome,
    keyPackage: bob.publicPackage,
    privateKeys: bob.privatePackage,
  })
  let charlieGroup = await joinGroup({
    context: ctx,
    welcome: addCommit.welcome!.welcome,
    keyPackage: charlie.publicPackage,
    privateKeys: charlie.privatePackage,
  })

  expect(bobGroup.keySchedule.epochAuthenticator).toStrictEqual(aliceGroup.keySchedule.epochAuthenticator)
  expect(charlieGroup.keySchedule.epochAuthenticator).toStrictEqual(aliceGroup.keySchedule.epochAuthenticator)

  // Alice proposes her own removal via self_remove.
  const selfRemoveResult = publicMessage
    ? await createSelfRemoveProposal({ context: ctx, state: aliceGroup })
    : await createProposal({
        context: ctx,
        state: aliceGroup,
        wireAsPublicMessage: false,
        proposal: { proposalType: selfRemoveProposalType },
      })
  aliceGroup = selfRemoveResult.newState

  if (selfRemoveResult.message.wireformat !== preferredWireformat)
    throw new Error(`Expected ${preferredWireformat} message`)

  bobGroup = (
    await processMessageEnsureNoMutation({
      context: ctx,
      state: bobGroup,
      message: selfRemoveResult.message,
      callback: acceptAll,
    })
  ).newState
  charlieGroup = (
    await processMessageEnsureNoMutation({
      context: ctx,
      state: charlieGroup,
      message: selfRemoveResult.message,
      callback: acceptAll,
    })
  ).newState

  // Bob commits Alice's self_remove (by reference from his unapplied proposals).
  const bobCommit = await createCommitEnsureNoMutation({
    context: ctx,
    state: bobGroup,
    wireAsPublicMessage: publicMessage,
    ratchetTreeExtension: false,
  })
  bobGroup = bobCommit.newState

  if (bobCommit.commit.wireformat !== preferredWireformat) throw new Error(`Expected ${preferredWireformat} message`)

  // Alice processes the commit removing her: she detects she was removed.
  aliceGroup = (
    await processMessageEnsureNoMutation({
      context: ctx,
      state: aliceGroup,
      message: bobCommit.commit,
      callback: acceptAll,
    })
  ).newState
  charlieGroup = (
    await processMessageEnsureNoMutation({
      context: ctx,
      state: charlieGroup,
      message: bobCommit.commit,
      callback: acceptAll,
    })
  ).newState

  expect(bobGroup.unappliedProposals).toEqual({})
  expect(charlieGroup.unappliedProposals).toEqual({})
  expect(aliceGroup.groupActiveState).toStrictEqual({ kind: "removedFromGroup" })

  await cannotMessageAnymore(aliceGroup, impl)
  await checkHpkeKeysMatch(bobGroup, impl)
  await checkHpkeKeysMatch(charlieGroup, impl)
  await testEveryoneCanMessageEveryone([bobGroup, charlieGroup], impl)
}
