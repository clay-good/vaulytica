'use client'

import { useState, useEffect, Suspense } from 'react'
import { useSearchParams } from 'next/navigation'
import Link from 'next/link'
import { api } from '@/lib/api'
import { KeyRound, CheckCircle, XCircle, Loader2, ArrowLeft } from 'lucide-react'

function ResetPasswordForm() {
  const searchParams = useSearchParams()
  const token = searchParams.get('token')

  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [validating, setValidating] = useState(true)
  const [tokenValid, setTokenValid] = useState(false)
  const [tokenError, setTokenError] = useState('')
  const [success, setSuccess] = useState(false)
  const [userEmail, setUserEmail] = useState('')

  useEffect(() => {
    const validateToken = async () => {
      if (!token) {
        setTokenError('No reset token provided')
        setValidating(false)
        return
      }

      try {
        const result = await api.validateResetToken(token)
        if (result.valid) {
          setTokenValid(true)
          setUserEmail(result.email || '')
        } else {
          setTokenError(
            result.reason === 'Token expired'
              ? 'This reset link has expired. Please request a new one.'
              : result.reason === 'Token already used'
              ? 'This reset link has already been used.'
              : 'This reset link is invalid.'
          )
        }
      } catch (err) {
        setTokenError('Unable to validate reset link. Please try again.')
      } finally {
        setValidating(false)
      }
    }

    validateToken()
  }, [token])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')

    if (password.length < 8) {
      setError('Password must be at least 8 characters long')
      return
    }

    if (password !== confirmPassword) {
      setError('Passwords do not match')
      return
    }

    setLoading(true)

    try {
      await api.resetPassword(token!, password)
      setSuccess(true)
    } catch (err: any) {
      if (err.response?.status === 400) {
        setError(err.response.data.detail || 'Invalid or expired reset link')
      } else if (err.response?.status === 429) {
        setError('Too many attempts. Please wait a moment and try again.')
      } else {
        setError('An error occurred. Please try again.')
      }
    } finally {
      setLoading(false)
    }
  }

  if (validating) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-gray-50">
        <div className="w-full max-w-md space-y-8 rounded-lg bg-white p-8 shadow-lg text-center">
          <Loader2 className="mx-auto h-12 w-12 animate-spin text-gray-400" />
          <p className="text-gray-600">Validating reset link...</p>
        </div>
      </div>
    )
  }

  if (!tokenValid) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-gray-50">
        <div className="w-full max-w-md space-y-8 rounded-lg bg-white p-8 shadow-lg">
          <div className="text-center">
            <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-full bg-red-100">
              <XCircle className="h-8 w-8 text-red-600" />
            </div>
            <h1 className="mt-4 text-2xl font-bold text-gray-900">Invalid Reset Link</h1>
            <p className="mt-2 text-gray-600">{tokenError}</p>
          </div>

          <div className="space-y-4">
            <Link
              href="/forgot-password"
              className="flex w-full items-center justify-center rounded-md bg-gray-900 px-4 py-2 text-white hover:bg-gray-800"
            >
              Request New Reset Link
            </Link>

            <Link
              href="/login"
              className="flex w-full items-center justify-center rounded-md border border-gray-300 px-4 py-2 text-gray-700 hover:bg-gray-50"
            >
              Return to Login
            </Link>
          </div>
        </div>
      </div>
    )
  }

  if (success) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-gray-50">
        <div className="w-full max-w-md space-y-8 rounded-lg bg-white p-8 shadow-lg">
          <div className="text-center">
            <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-full bg-green-100">
              <CheckCircle className="h-8 w-8 text-green-600" />
            </div>
            <h1 className="mt-4 text-2xl font-bold text-gray-900">Password Reset Complete</h1>
            <p className="mt-2 text-gray-600">
              Your password has been successfully changed. You can now log in with your new password.
            </p>
          </div>

          <Link
            href="/login"
            className="flex w-full items-center justify-center rounded-md bg-gray-900 px-4 py-2 text-white hover:bg-gray-800"
          >
            Continue to Login
          </Link>
        </div>
      </div>
    )
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-gray-50">
      <div className="w-full max-w-md space-y-8 rounded-lg bg-white p-8 shadow-lg">
        <div className="text-center">
          <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-full bg-gray-100">
            <KeyRound className="h-8 w-8 text-gray-600" />
          </div>
          <h1 className="mt-4 text-2xl font-bold text-gray-900">Set new password</h1>
          {userEmail && (
            <p className="mt-2 text-gray-600">
              for <span className="font-medium">{userEmail}</span>
            </p>
          )}
        </div>

        <form onSubmit={handleSubmit} className="mt-8 space-y-6">
          {error && (
            <div className="rounded-md bg-red-50 p-4 text-sm text-red-700">
              {error}
            </div>
          )}

          <div className="space-y-4">
            <div>
              <label htmlFor="password" className="block text-sm font-medium text-gray-700">
                New Password
              </label>
              <input
                id="password"
                name="password"
                type="password"
                autoComplete="new-password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 shadow-sm focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
                placeholder="Enter new password"
                minLength={8}
              />
              <p className="mt-1 text-xs text-gray-500">Must be at least 8 characters</p>
            </div>

            <div>
              <label htmlFor="confirmPassword" className="block text-sm font-medium text-gray-700">
                Confirm Password
              </label>
              <input
                id="confirmPassword"
                name="confirmPassword"
                type="password"
                autoComplete="new-password"
                required
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 shadow-sm focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
                placeholder="Confirm new password"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full rounded-md bg-gray-900 px-4 py-2 text-white hover:bg-gray-800 focus:outline-none focus:ring-2 focus:ring-gray-900 focus:ring-offset-2 disabled:opacity-50"
          >
            {loading ? 'Resetting...' : 'Reset password'}
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

export default function ResetPasswordPage() {
  return (
    <Suspense
      fallback={
        <div className="flex min-h-screen items-center justify-center bg-gray-50">
          <div className="w-full max-w-md space-y-8 rounded-lg bg-white p-8 shadow-lg text-center">
            <Loader2 className="mx-auto h-12 w-12 animate-spin text-gray-400" />
            <p className="text-gray-600">Loading...</p>
          </div>
        </div>
      }
    >
      <ResetPasswordForm />
    </Suspense>
  )
}
