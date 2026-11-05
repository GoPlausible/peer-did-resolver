import { DIDDocument, Resolvable, Resolver } from 'did-resolver'
import { getResolver } from '../resolver'

describe('did:peer resolver', () => {
  let didResolver: Resolvable

  beforeAll(async () => {
    didResolver = new Resolver(getResolver())
  })

  it('resolves simple document with num_algo=0', async () => {
    expect.assertions(2)
    const did = 'did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V'
    const result = await didResolver.resolve(did)
    expect(result.didDocument).toEqual({
      '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/ed25519-2020/v1'],
      id: did,
      verificationMethod: [
        {
          id: 'did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V#6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V',
          type: 'Ed25519VerificationKey2020',
          controller: 'did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V',
          publicKeyMultibase: 'z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V',
        },
      ],
      authentication: [
        'did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V#6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V',
      ],
      assertionMethod: [
        'did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V#6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V',
      ],
      capabilityInvocation: [
        'did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V#6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V',
      ],
      capabilityDelegation: [
        'did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V#6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V',
      ],
    })
    expect(result.didResolutionMetadata.contentType).toEqual('application/did+ld+json')
  })

  it('resolves simple document with num_algo=2', async () => {
    expect.assertions(2)
    const did =
      'did:peer:2.Ez6LSpSrLxbAhg2SHwKk7kwpsH7DM7QjFS5iK6qP87eViohud.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludDEiLCJyIjpbImRpZDpleGFtcGxlOnNvbWVtZWRpYXRvciNzb21la2V5MSJdLCJhIjpbImRpZGNvbW0vdjIiLCJkaWRjb21tL2FpcDI7ZW52PXJmYzU4NyJdfQ'
    const result = await didResolver.resolve(did)
    expect(result.didDocument).toEqual({
      '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/multikey/v1', { '@base': did }],
      id: did,
      verificationMethod: [
        {
          id: '#key-2',
          type: 'Multikey',
          controller: did,
          publicKeyMultibase: 'z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V',
        },
        {
          id: '#key-1',
          type: 'Multikey',
          controller: did,
          publicKeyMultibase: 'z6LSpSrLxbAhg2SHwKk7kwpsH7DM7QjFS5iK6qP87eViohud',
        },
      ],
      keyAgreement: ['#key-1'],
      authentication: ['#key-2'],
      service: [
        {
          id: '#service',
          type: 'DIDCommMessaging',
          serviceEndpoint: 'https://example.com/endpoint1',
          routingKeys: ['did:example:somemediator#somekey1'],
          accept: ['didcomm/v2', 'didcomm/aip2;env=rfc587'],
        },
      ],
    })
    expect(result.didResolutionMetadata.contentType).toEqual('application/did+ld+json')
  })

  it('resolves document with num_algo=2 and multiple service endpoints', async () => {
    expect.assertions(2)
    const did =
      'did:peer:2.Ez6LSpSrLxbAhg2SHwKk7kwpsH7DM7QjFS5iK6qP87eViohud.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludDEiLCJyIjpbImRpZDpleGFtcGxlOnNvbWVtZWRpYXRvciNzb21la2V5MSJdLCJhIjpbImRpZGNvbW0vdjIiLCJkaWRjb21tL2FpcDI7ZW52PXJmYzU4NyJdfQ.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludDIiLCJyIjpbImRpZDpleGFtcGxlOnNvbWVtZWRpYXRvciNzb21la2V5MiJdLCJhIjpbImRpZGNvbW0vdjIiLCJkaWRjb21tL2FpcDI7ZW52PXJmYzU4NyJdfQ'
    const result = await didResolver.resolve(did)
    expect(result.didDocument.service).toEqual([
      {
        id: '#service',
        type: 'DIDCommMessaging',
        serviceEndpoint: 'https://example.com/endpoint1',
        routingKeys: ['did:example:somemediator#somekey1'],
        accept: ['didcomm/v2', 'didcomm/aip2;env=rfc587'],
      },
      {
        id: '#service-1',
        type: 'DIDCommMessaging',
        serviceEndpoint: 'https://example.com/endpoint2',
        routingKeys: ['did:example:somemediator#somekey2'],
        accept: ['didcomm/v2', 'didcomm/aip2;env=rfc587'],
      },
    ])
    expect(result.didResolutionMetadata.contentType).toEqual('application/did+ld+json')
  })
})

describe('did:peer resolver errors', () => {
  const resolve = (did: string) => new Resolver(getResolver()).resolve(did)

  it('reports a malformed identifier as invalidDid with the reason, and no document', async () => {
    for (const did of ['did:peer:9zQmX', 'did:peer:2']) {
      const result = await resolve(did)
      expect(result.didDocument).toBeNull()
      expect(result.didDocumentMetadata).toEqual({})
      expect(result.didResolutionMetadata.error).toBe('invalidDid')
      expect(result.didResolutionMetadata.message).toContain('is not a valid did:peer')
    }
  })

  it('reports numalgo 1, which the core does not support, as notFound without a document', async () => {
    const result = await resolve('did:peer:1zQmZMygzYqNwU6Uhmewx5Xepf2VLp5S4HLSwwgf2aiKZuwa')
    expect(result.didDocument).toBeNull()
    expect(result.didResolutionMetadata.error).toBe('notFound')
    expect(result.didResolutionMetadata.message).toContain('numalgo 1')
  })
})
