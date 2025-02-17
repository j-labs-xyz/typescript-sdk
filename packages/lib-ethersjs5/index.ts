import { DfnsApiClient } from '@dfns/sdk'
import { KeyCurve, KeyScheme, SignatureKind, SignatureStatus } from '@dfns/sdk/codegen/datamodel/Wallets'
import { getAddress } from '@ethersproject/address'
import { Provider, TransactionRequest } from '@ethersproject/abstract-provider'
import { Signer, TypedDataDomain, TypedDataField, TypedDataSigner } from '@ethersproject/abstract-signer'
import { joinSignature } from '@ethersproject/bytes'
import { hashMessage, _TypedDataEncoder } from '@ethersproject/hash'
import { keccak256 } from '@ethersproject/keccak256'
import { defineReadOnly, resolveProperties } from '@ethersproject/properties'
import { computeAddress, serialize, UnsignedTransaction } from '@ethersproject/transactions'

const sleep = (interval = 0) => new Promise((resolve) => setTimeout(resolve, interval))

export type DfnsWalletOptions = {
  walletId: string
  dfnsClient: DfnsApiClient
  maxRetries?: number
  retryInterval?: number
}

export class DfnsWallet extends Signer implements TypedDataSigner {
  private address?: string
  private options: Required<DfnsWalletOptions>

  constructor(options: DfnsWalletOptions, provider?: Provider | null) {
    super()

    this.options = {
      ...options,
      maxRetries: options.maxRetries ?? 3,
      retryInterval: options.retryInterval ?? 1000,
    }

    defineReadOnly(this, 'provider', provider || undefined)
  }

  connect(provider: Provider | null): Signer {
    return new DfnsWallet(this.options, provider)
  }

  async getAddress(): Promise<string> {
    if (!this.address) {
      const { walletId, dfnsClient } = this.options
      const res = await dfnsClient.wallets.getWallet({ walletId })

      if (!res.signingKey || res.signingKey.scheme !== KeyScheme.ECDSA || res.signingKey.curve !== KeyCurve.secp256k1) {
        throw new Error(
          `wallet ${walletId} has incompatible scheme (${res.signingKey?.scheme}) or curve (${res.signingKey?.curve})`
        )
      }

      if (res.address) {
        this.address = getAddress(res.address)
      } else {
        this.address = computeAddress('0x' + res.signingKey.publicKey)
      }
    }

    return this.address
  }

  async waitForSignature(signatureId: string): Promise<string> {
    const { walletId, dfnsClient, retryInterval } = this.options

    let maxRetries = this.options.maxRetries
    while (maxRetries > 0) {
      await sleep(retryInterval)

      const res = await dfnsClient.wallets.getSignature({ walletId, signatureId })
      if (res.status === SignatureStatus.Signed) {
        if (!res.signature) break
        return joinSignature({
          r: res.signature.r,
          s: res.signature.s,
          recoveryParam: res.signature.recid,
        })
      } else if (res.status === SignatureStatus.Failed) {
        break
      }

      maxRetries -= 1
    }

    throw new Error(`signature ${signatureId} not available`)
  }

  async signTransaction(transaction: TransactionRequest): Promise<string> {
    return resolveProperties(transaction).then(async (tx) => {
      if (tx.from != null) {
        if (getAddress(tx.from) !== (await this.getAddress())) {
          throw new Error('transaction from address mismatch')
        }
        delete tx.from
      }

      const { walletId, dfnsClient } = this.options
      const res = await dfnsClient.wallets.generateSignature({
        walletId,
        body: { kind: SignatureKind.Hash, hash: keccak256(serialize(<UnsignedTransaction>tx)) },
      })
      const signature = await this.waitForSignature(res.id)

      return serialize(<UnsignedTransaction>tx, signature)
    })
  }

  async signMessage(message: string | Uint8Array): Promise<string> {
    const { walletId, dfnsClient } = this.options
    const res = await dfnsClient.wallets.generateSignature({
      walletId,
      body: { kind: SignatureKind.Hash, hash: hashMessage(message) },
    })

    return this.waitForSignature(res.id)
  }

  async _signTypedData(
    domain: TypedDataDomain,
    types: Record<string, TypedDataField[]>,
    value: Record<string, any>
  ): Promise<string> {
    // Populate any ENS names
    const populated = await _TypedDataEncoder.resolveNames(domain, types, value, async (name: string) => {
      if (!this.provider) {
        throw new Error('cannot resolve ENS names without a provider')
      }
      const resolved = await this.provider.resolveName(name)
      if (!resolved) throw new Error(`unconfigured ENS name ${name}`)
      return resolved
    })

    const { walletId, dfnsClient } = this.options
    const res = await dfnsClient.wallets.generateSignature({
      walletId,
      body: {
        kind: SignatureKind.Hash,
        hash: _TypedDataEncoder.hash(populated.domain, types, populated.value),
      },
    })

    return this.waitForSignature(res.id)
  }
}
