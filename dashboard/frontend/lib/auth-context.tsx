'use client'

import { createContext, useContext, useState, useEffect, ReactNode } from 'react'
import { useRouter } from 'next/navigation'
import axios from 'axios'
import Cookies from 'js-cookie'
import toast from 'react-hot-toast'

interface User {
  username: string
  role: string
}

interface AuthContextType {
  user: User | null
  isLoading: boolean
  login: (password: string) => Promise<void>
  logout: () => void
  checkAuth: () => Promise<void>
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const router = useRouter()

  useEffect(() => {
    checkAuth()
  }, [])

  const checkAuth = async () => {
    try {
      const token = Cookies.get('access_token')
      if (!token) {
        setUser(null)
        return
      }

      const response = await axios.get('/api/auth/session', {
        headers: { Authorization: `Bearer ${token}` }
      })
      
      setUser(response.data)
    } catch (error) {
      setUser(null)
      Cookies.remove('access_token')
      Cookies.remove('refresh_token')
    } finally {
      setIsLoading(false)
    }
  }

  const login = async (password: string) => {
    try {
      const formData = new FormData()
      formData.append('username', 'admin')
      formData.append('password', password)

      const response = await axios.post('/api/auth/login', formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      })

      const { access_token, refresh_token } = response.data

      // Store tokens
      Cookies.set('access_token', access_token, { expires: 1 })
      Cookies.set('refresh_token', refresh_token, { expires: 7 })

      // Set auth header for future requests
      axios.defaults.headers.common['Authorization'] = `Bearer ${access_token}`

      // Get user info
      await checkAuth()
      
      toast.success('Successfully logged in!')
      router.push('/')
    } catch (error: any) {
      toast.error(error.response?.data?.detail || 'Login failed')
      throw error
    }
  }

  const logout = async () => {
    try {
      const token = Cookies.get('access_token')
      if (token) {
        await axios.post('/api/auth/logout', {}, {
          headers: { Authorization: `Bearer ${token}` }
        })
      }
    } catch (error) {
      // Ignore logout errors
    } finally {
      setUser(null)
      Cookies.remove('access_token')
      Cookies.remove('refresh_token')
      delete axios.defaults.headers.common['Authorization']
      router.push('/login')
      toast.success('Logged out successfully')
    }
  }

  return (
    <AuthContext.Provider value={{ user, isLoading, login, logout, checkAuth }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}