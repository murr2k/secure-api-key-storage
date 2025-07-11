import axios from 'axios'
import Cookies from 'js-cookie'
import toast from 'react-hot-toast'

const apiClient = axios.create({
  baseURL: process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000',
  headers: {
    'Content-Type': 'application/json',
  },
})

// Request interceptor to add auth token
apiClient.interceptors.request.use(
  (config) => {
    const token = Cookies.get('access_token')
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }
    return config
  },
  (error) => {
    return Promise.reject(error)
  }
)

// Response interceptor to handle token refresh
apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config

    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true

      try {
        const refreshToken = Cookies.get('refresh_token')
        if (!refreshToken) {
          throw new Error('No refresh token')
        }

        const response = await axios.post('/api/auth/refresh', {
          refresh_token: refreshToken
        })

        const { access_token, refresh_token: newRefreshToken } = response.data

        Cookies.set('access_token', access_token, { expires: 1 })
        Cookies.set('refresh_token', newRefreshToken, { expires: 7 })

        originalRequest.headers.Authorization = `Bearer ${access_token}`
        return apiClient(originalRequest)
      } catch (refreshError) {
        // Refresh failed, redirect to login
        Cookies.remove('access_token')
        Cookies.remove('refresh_token')
        window.location.href = '/login'
        return Promise.reject(refreshError)
      }
    }

    // Show error message
    if (error.response?.data?.detail) {
      toast.error(error.response.data.detail)
    }

    return Promise.reject(error)
  }
)

export default apiClient

// API functions
export const api = {
  // Auth
  auth: {
    login: (password: string) => {
      const formData = new FormData()
      formData.append('username', 'admin')
      formData.append('password', password)
      return apiClient.post('/api/auth/login', formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      })
    },
    logout: () => apiClient.post('/api/auth/logout'),
    session: () => apiClient.get('/api/auth/session'),
    refresh: (refreshToken: string) => 
      apiClient.post('/api/auth/refresh', { refresh_token: refreshToken }),
  },

  // Keys
  keys: {
    list: (params?: { service?: string; search?: string }) => 
      apiClient.get('/api/keys', { params }),
    create: (data: any) => apiClient.post('/api/keys', data),
    get: (id: string) => apiClient.get(`/api/keys/${id}`),
    update: (id: string, data: any) => apiClient.put(`/api/keys/${id}`, data),
    delete: (id: string) => apiClient.delete(`/api/keys/${id}`),
    rotate: (id: string) => apiClient.post(`/api/keys/${id}/rotate`),
    copy: (id: string) => apiClient.post(`/api/keys/${id}/copy`),
  },

  // Audit
  audit: {
    list: (params?: { skip?: number; limit?: number; action?: string; key_name?: string }) =>
      apiClient.get('/api/audit', { params }),
    export: () => apiClient.get('/api/audit/export'),
  },

  // Analytics
  analytics: {
    overview: () => apiClient.get('/api/analytics/overview'),
    usage: () => apiClient.get('/api/analytics/usage'),
    security: () => apiClient.get('/api/analytics/security'),
  },
}