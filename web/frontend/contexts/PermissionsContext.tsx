'use client'

import { createContext, useContext, useEffect, useState, ReactNode } from 'react'
import { api } from '@/lib/api'
import { UserPermissions, canEditDomain, canAdminDomain } from '@/lib/types'

interface PermissionsContextType {
  permissions: UserPermissions | null
  loading: boolean
  error: string | null
  refresh: () => Promise<void>
  canEdit: (domain: string) => boolean
  canAdmin: (domain: string) => boolean
  hasAccessTo: (domain: string) => boolean
}

const PermissionsContext = createContext<PermissionsContextType | undefined>(undefined)

export function PermissionsProvider({ children }: { children: ReactNode }) {
  const [permissions, setPermissions] = useState<UserPermissions | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const fetchPermissions = async () => {
    try {
      setLoading(true)
      setError(null)
      const data = await api.getUserPermissions()
      setPermissions(data)
    } catch (err: any) {
      // Don't set error for 401 - user not logged in
      if (err.response?.status !== 401) {
        setError('Failed to load permissions')
      }
      setPermissions(null)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    // Only fetch if we have a token
    if (typeof window !== 'undefined' && localStorage.getItem('access_token')) {
      fetchPermissions()
    } else {
      setLoading(false)
    }
  }, [])

  const canEdit = (domain: string): boolean => {
    return canEditDomain(permissions, domain)
  }

  const canAdmin = (domain: string): boolean => {
    return canAdminDomain(permissions, domain)
  }

  const hasAccessTo = (domain: string): boolean => {
    if (!permissions) return false
    if (permissions.is_superuser) return true
    return permissions.accessible_domains.includes(domain)
  }

  return (
    <PermissionsContext.Provider
      value={{
        permissions,
        loading,
        error,
        refresh: fetchPermissions,
        canEdit,
        canAdmin,
        hasAccessTo,
      }}
    >
      {children}
    </PermissionsContext.Provider>
  )
}

export function usePermissions() {
  const context = useContext(PermissionsContext)
  if (context === undefined) {
    throw new Error('usePermissions must be used within a PermissionsProvider')
  }
  return context
}
