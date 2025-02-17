'use client'

import { WebAuthn } from '@dfns/sdk-webauthn'
import { Wallet } from '@dfns/sdk/codegen/datamodel/Wallets'
import { useCallback, useEffect, useState } from 'react'

export default function Wallets() {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(undefined)
  const [wallets, setWallets] = useState<Wallet[]>([])

  useEffect(() => {
    setLoading(true)
    fetch('/api/wallets')
      .then((result) => result.json())
      .then((result) => setWallets(result.wallets))
      .catch((err) => setError(err))
      .finally(() => setLoading(false))
  }, [])

  const createWallet = useCallback(() => {
    setLoading(true)
    fetch('/api/wallets/create/init', { method: 'POST' })
      .then(async (result) => {
        const { request, challenge } = await result.json()
        const webauthn = new WebAuthn({ rpId: process.env.NEXT_PUBLIC_DFNS_WEBAUTHN_RPID! })
        const assertion = await webauthn.sign(challenge.challenge, challenge.allowCredentials)
        return fetch('/api/wallets/create/complete', {
          method: 'POST',
          body: JSON.stringify({
            request,
            signedChallenge: { challengeIdentifier: challenge.challengeIdentifier, firstFactor: assertion },
          }),
        })
      })
      .then((response) => response.json())
      .then((result) => setWallets((wallets) => [result.wallet, ...wallets]))
      .catch((err) => setError(err))
      .finally(() => setLoading(false))
  }, [])

  return (
    <div className="w-full">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl">List of Wallets</h1>
        <button className="btn" onClick={createWallet}>
          Create New
        </button>
      </div>

      {!!loading && <span>loading...</span>}

      {!!error && <div className="text-red-700">{error}</div>}

      {wallets.map((wallet) => (
        <pre key={wallet.id} className="p-4 drop-shadow-lg mt-2 overflow-x-scroll">
          {JSON.stringify(wallet, null, 2)}
        </pre>
      ))}

      {!loading && !error && !wallets.length && <p>No Wallets yet</p>}
    </div>
  )
}
