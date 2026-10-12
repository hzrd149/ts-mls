import {
  createCommit,
  createGroup,
  decode,
  defaultCredentialTypes,
  defaultProposalTypes,
  encode,
  generateKeyPackage,
  getCiphersuiteImpl,
  groupContextEncoder,
  joinGroupWithExtensions,
  leafToNodeIndex,
  makeCustomExtension,
  nodeTypes,
  unsafeTestingAuthenticationService,
  type KeyPackageWithPrivateKey,
  type LeafIndex,
} from "../src/index.js"
import { groupContextDecoder } from "../src/groupContext.js"
import { verifyGroupInfoSignature } from "../src/groupInfo.js"

test.each([false, true])("public Welcome join APIs (ratchet tree extension: %s)", async (ratchetTreeExtension) => {
  const cipherSuite = await getCiphersuiteImpl("MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519")
  const context = { cipherSuite, authService: unsafeTestingAuthenticationService }
  const makePackage = (identity: string): Promise<KeyPackageWithPrivateKey> =>
    generateKeyPackage({
      cipherSuite,
      credential: { credentialType: defaultCredentialTypes.basic, identity: new TextEncoder().encode(identity) },
    })
  const alice = await makePackage("alice")
  const bob = await makePackage("bob")
  const state = await createGroup({
    context,
    groupId: new TextEncoder().encode("public-api-test"),
    keyPackage: alice.publicPackage,
    privateKeyPackage: alice.privatePackage,
  })
  const extension = makeCustomExtension({ extensionType: 92, extensionData: new Uint8Array([1, 2, 3]) })
  const commit = await createCommit({
    context,
    state,
    extraProposals: [{ proposalType: defaultProposalTypes.add, add: { keyPackage: bob.publicPackage } }],
    groupInfoExtensions: [extension],
    ratchetTreeExtension,
  })
  const joined = await joinGroupWithExtensions({
    context,
    welcome: commit.welcome!.welcome,
    keyPackage: bob.publicPackage,
    privateKeys: bob.privatePackage,
    ratchetTree: ratchetTreeExtension ? undefined : commit.newState.ratchetTree,
  })

  expect(joined.groupInfo.groupContext).toStrictEqual(commit.newState.groupContext)
  expect(joined.groupInfo.confirmationTag).toStrictEqual(commit.newState.confirmationTag)
  expect(joined.groupInfoExtensions).toStrictEqual(joined.groupInfo.extensions)
  expect(joined.groupInfo.extensions).toContainEqual(extension)
  expect(decode(groupContextDecoder, encode(groupContextEncoder, joined.groupInfo.groupContext))).toStrictEqual(
    joined.state.groupContext,
  )

  const signer = joined.state.ratchetTree[leafToNodeIndex(joined.groupInfo.signer as LeafIndex)]
  expect(signer?.nodeType).toBe(nodeTypes.leaf)
  if (signer?.nodeType !== nodeTypes.leaf) throw new Error("Expected signer leaf")
  expect(await verifyGroupInfoSignature(joined.groupInfo, signer.leaf.signaturePublicKey, cipherSuite.signature)).toBe(
    true,
  )
  expect(leafToNodeIndex(1 as LeafIndex)).toBe(2)
})
