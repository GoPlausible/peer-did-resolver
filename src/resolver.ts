import { DIDDocument, DIDResolutionResult, DIDResolver, ParsedDID } from 'did-resolver'
import { IDIDDocumentServiceDescriptor, resolve } from '@aviarytech/did-peer'

export function getResolver(): Record<string, DIDResolver> {
  async function resolveInner(did: string, parsed: ParsedDID): Promise<DIDResolutionResult> {
    const didDocumentMetadata = {}
    let didDocument: DIDDocument | null = null
    let err = ''
    let errorCode: 'notFound' | 'invalidDid' = 'notFound'
    do {
      try {
        const doc = await resolve(did)
        didDocument = {
          '@context': doc['@context'],
          id: doc.id,
          verificationMethod: doc.verificationMethod,
          keyAgreement: doc.keyAgreement,
          authentication: doc.authentication,
          assertionMethod: doc.assertionMethod,
          capabilityInvocation: doc.capabilityInvocation,
          capabilityDelegation: doc.capabilityDelegation,
          service: doc.service as IDIDDocumentServiceDescriptor[],
        }
        if (doc.alsoKnownAs) {
          didDocument.alsoKnownAs = doc.alsoKnownAs
        }
        if (doc.controller) {
          didDocument.controller = doc.controller
        }
      } catch (error) {
        // Report what the core found: a malformed identifier, unusable key material or a
        // malformed service is an invalidDid with the core's own reason; only a numalgo
        // this resolver does not support is reported as notFound.
        const reason = error instanceof Error ? error.message : String(error)
        if (/NumAlgo1 not supported/.test(reason)) {
          err = 'did:peer numalgo 1 is not supported by this resolver'
        } else {
          err = reason
          errorCode = 'invalidDid'
        }
        break
      }

      const docIdMatchesDid = didDocument?.id === parsed.did
      if (!docIdMatchesDid) {
        err = 'resolver_error: DID document id does not match requested did'
        // break // uncomment this when adding more checks
      }
      // eslint-disable-next-line no-constant-condition
    } while (false)

    const contentType =
      typeof didDocument?.['@context'] !== 'undefined' ? 'application/did+ld+json' : 'application/did+json'

    if (err) {
      // DID Resolution: no document and no document metadata when resolution fails.
      return {
        didDocument: null,
        didDocumentMetadata: {},
        didResolutionMetadata: {
          error: errorCode,
          message: err,
        },
      }
    } else {
      return {
        didDocument,
        didDocumentMetadata,
        didResolutionMetadata: { contentType },
      }
    }
  }

  return { peer: resolveInner }
}
