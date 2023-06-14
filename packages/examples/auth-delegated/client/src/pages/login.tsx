import React, { FormEvent } from 'react'

import '../globals.css'
import useAuth from '../hooks/useAuth'

export default function Login(): JSX.Element {
  const { login, loading, error } = useAuth()

  const handleLogin = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()

    const formData = new FormData(event.currentTarget)

    login(formData.get('email') as string, formData.get('password') as string)
  }

  return (
    <form onSubmit={handleLogin}>
      <div className="w-full">
        <h1 className='text-2x'>Login</h1>

        <div className="flex items-center gap-2">
          <input className="input" id="email" name="email" placeholder="email" />

          <input className="input" id="password" name="password" type="password" placeholder="password" />

          <button className="btn" disabled={loading} type="submit">
            Submit
          </button>
        </div>

        {error && <div className="text-red-700">error.message</div>}
      </div>
    </form>
  )
}
