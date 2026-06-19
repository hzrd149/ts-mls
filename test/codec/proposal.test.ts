import { proposalEncoder, proposalDecoder, Proposal, isSelfRemoveProposal } from "../../src/proposal.js"
import { defaultProposalTypes } from "../../src/defaultProposalType.js"
import { selfRemoveProposalType } from "../../src/selfRemove.js"
import { decode } from "../../src/codec/tlsDecoder.js"
import { encode } from "../../src/codec/tlsEncoder.js"
import { ciphersuites } from "../../src/crypto/ciphersuite.js"
import { protocolVersions } from "../../src/protocolVersion.js"
import { defaultCredentialTypes } from "../../src/defaultCredentialType.js"
import { createRoundtripTest } from "./roundtrip.js"
import { leafNodeSources } from "../../src/leafNodeSource.js"

const dummyProposalAdd: Proposal = {
  proposalType: defaultProposalTypes.add,
  add: {
    keyPackage: {
      version: protocolVersions.mls10,
      cipherSuite: ciphersuites.MLS_256_XWING_AES256GCM_SHA512_Ed25519,
      initKey: new Uint8Array([]),
      leafNode: {
        hpkePublicKey: new Uint8Array([]),
        signaturePublicKey: new Uint8Array([]),
        credential: { credentialType: defaultCredentialTypes.basic, identity: new Uint8Array([]) },
        capabilities: {
          versions: [],
          ciphersuites: [],
          extensions: [],
          proposals: [],
          credentials: [],
        },
        leafNodeSource: leafNodeSources.key_package,
        lifetime: { notBefore: 0n, notAfter: 0n },
        extensions: [],
        signature: new Uint8Array([]),
      },
      extensions: [],
      signature: new Uint8Array([]),
    },
  },
}

const dummyProposalRemove: Proposal = {
  proposalType: defaultProposalTypes.remove,
  remove: { removed: 42 },
}

const dummyProposalSelfRemove: Proposal = {
  proposalType: selfRemoveProposalType,
}

describe("Proposal roundtrip", () => {
  const roundtrip = createRoundtripTest(proposalEncoder, proposalDecoder)

  test("roundtrips add", () => {
    roundtrip(dummyProposalAdd)
  })

  test("roundtrips remove", () => {
    roundtrip(dummyProposalRemove)
  })

  test("roundtrips self_remove", () => {
    roundtrip(dummyProposalSelfRemove)
  })

  test("self_remove encodes to exactly the 2-byte proposal type (empty body)", () => {
    const bytes = encode(proposalEncoder, dummyProposalSelfRemove)
    // 0x000a, big-endian uint16, no trailing body bytes.
    expect(Array.from(bytes)).toEqual([0x00, 0x0a])
  })

  test("self_remove decodes from exactly the 2-byte type to a typed self_remove proposal", () => {
    const decoded = decode(proposalDecoder, new Uint8Array([0x00, 0x0a]))
    expect(decoded).toBeDefined()
    expect(isSelfRemoveProposal(decoded!)).toBe(true)
  })
})
