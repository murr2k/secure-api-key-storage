'use client'

import { useState } from 'react'
import { useRouter } from 'next/navigation'
import { Lock, Key, Shield } from 'lucide-react'
import { useAuth } from '@/lib/auth-context'

export default function LoginPage() {
  const [password, setPassword] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const { login } = useAuth()
  const router = useRouter()

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!password) return

    setIsLoading(true)
    try {
      await login(password)
      router.push('/')
    } catch (error) {
      // Error is handled in auth context
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="min-h-screen gradient-bg flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        {/* Logo and Title */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-white/10 backdrop-blur-md mb-4">
            <Shield className="w-8 h-8 text-white" />
          </div>
          <h1 className="text-3xl font-bold text-white mb-2">
            Secure API Key Storage
          </h1>
          <p className="text-white/60">
            Enter your master password to access the dashboard
          </p>
        </div>

        {/* Login Form */}
        <form onSubmit={handleSubmit} className="glass-effect rounded-lg p-8">
          <div className="mb-6">
            <label htmlFor="password" className="block text-sm font-medium text-white/80 mb-2">
              Master Password
            </label>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                <Lock className="h-5 w-5 text-white/40" />
              </div>
              <input
                type="password"
                id="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="block w-full pl-10 pr-3 py-3 bg-white/10 border border-white/20 rounded-lg text-white placeholder-white/40 focus:outline-none focus:ring-2 focus:ring-white/40 focus:border-transparent backdrop-blur-md"
                placeholder="Enter your master password"
                required
                disabled={isLoading}
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={isLoading}
            className="w-full flex items-center justify-center px-4 py-3 bg-white text-slate-900 rounded-lg font-medium hover:bg-white/90 focus:outline-none focus:ring-2 focus:ring-white/40 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            {isLoading ? (
              <>
                <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-slate-900 mr-2"></div>
                Authenticating...
              </>
            ) : (
              <>
                <Key className="w-5 h-5 mr-2" />
                Unlock Dashboard
              </>
            )}
          </button>
        </form>

        {/* Security Notice */}
        <div className="mt-6 text-center text-sm text-white/60">
          <p>🔒 Your master password is never stored</p>
          <p className="mt-1">All keys are encrypted with AES-256-GCM</p>
        </div>
      </div>
    </div>
  )
}