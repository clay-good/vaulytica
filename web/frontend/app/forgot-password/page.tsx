'use client'

import { useState } from 'react'
import Link from 'next/link'
import { api } from '@/lib/api'
import { ArrowLeft, Mail, CheckCircle } from 'lucide-react'

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [submitted, setSubmitted] = useState(false)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)

    try {
      await api.forgotPassword(email)
      setSubmitted(true)
    } catch (err: any) {
      // Even on rate limit, show generic message for security
      if (err.response?.status === 429) {
        setError('Too many requests. Please wait a moment and try again.')
      } else {
        setError('An error occurred. Please try again.')
      }
    } finally {
      setLoading(false)
    }
  }

  if (submitted) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-gray-50">
        <div className="w-full max-w-md space-y-8 rounded-lg bg-white p-8 shadow-lg">
          <div className="text-center">
            <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-full bg-green-100">
              <CheckCircle className="h-8 w-8 text-green-600" />
            </div>
            <h1 className="mt-4 text-2xl font-bold text-gray-900">Check your email</h1>
            <p className="mt-2 text-gray-600">
              If an account with that email exists, we've sent you a password reset link.
            </p>
          </div>

          <div className="space-y-4">
            <p className="text-center text-sm text-gray-500">
              The link will expire in 1 hour. If you don't see the email, check your spam folder.
            </p>

            <Link
              href="/login"
              className="flex w-full items-center justify-center rounded-md bg-gray-900 px-4 py-2 text-white hover:bg-gray-800"
            >
              Return to Login
            </Link>

            <button
              onClick={() => {
                setSubmitted(false)
                setEmail('')
              }}
              className="flex w-full items-center justify-center rounded-md border border-gray-300 px-4 py-2 text-gray-700 hover:bg-gray-50"
            >
              Try a different email
            </button>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-gray-50">
      <div className="w-full max-w-md space-y-8 rounded-lg bg-white p-8 shadow-lg">
        <div className="text-center">
          <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-full bg-gray-100">
            <Mail className="h-8 w-8 text-gray-600" />
          </div>
          <h1 className="mt-4 text-2xl font-bold text-gray-900">Forgot password?</h1>
          <p className="mt-2 text-gray-600">
            No worries, we'll send you reset instructions.
          </p>
        </div>

        <form onSubmit={handleSubmit} className="mt-8 space-y-6">
          {error && (
            <div className="rounded-md bg-red-50 p-4 text-sm text-red-700">
              {error}
            </div>
          )}

          <div>
            <label htmlFor="email" className="block text-sm font-medium text-gray-700">
              Email address
            </label>
            <input
              id="email"
              name="email"
              type="email"
              autoComplete="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 shadow-sm focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
              placeholder="Enter your email"
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full rounded-md bg-gray-900 px-4 py-2 text-white hover:bg-gray-800 focus:outline-none focus:ring-2 focus:ring-gray-900 focus:ring-offset-2 disabled:opacity-50"
          >
            {loading ? 'Sending...' : 'Reset password'}
          </button>
        </form>

        <Link
          href="/login"
          className="flex items-center justify-center text-sm text-gray-600 hover:text-gray-900"
        >
          <ArrowLeft className="mr-2 h-4 w-4" />
          Back to login
        </Link>
      </div>
    </div>
  )
}
