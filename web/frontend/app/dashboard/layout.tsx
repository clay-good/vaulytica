'use client'

import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import { Sidebar, MobileSidebar } from '@/components/layout/sidebar'
import { Header } from '@/components/layout/header'
import { ErrorBoundary, LoadingFallback } from '@/components/ErrorBoundary'
import { PermissionsProvider } from '@/contexts/PermissionsContext'
import { MobileSidebarProvider } from '@/contexts/MobileSidebarContext'
import { SkipLink } from '@/components/ui/form-input'

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode
}) {
  const router = useRouter()
  const [isAuthenticated, setIsAuthenticated] = useState(false)

  useEffect(() => {
    const token = localStorage.getItem('access_token')
    if (!token) {
      router.push('/login')
    } else {
      setIsAuthenticated(true)
    }
  }, [router])

  if (!isAuthenticated) {
    return <LoadingFallback />
  }

  return (
    <PermissionsProvider>
      <MobileSidebarProvider>
        <SkipLink href="#main-content">Skip to main content</SkipLink>
        <div className="flex h-screen">
          <Sidebar />
          <MobileSidebar />
          <div className="flex flex-1 flex-col overflow-hidden">
            <Header />
            <main
              id="main-content"
              className="flex-1 overflow-y-auto bg-gray-50 dark:bg-gray-900 p-4 sm:p-6"
              role="main"
              tabIndex={-1}
            >
              <ErrorBoundary>
                {children}
              </ErrorBoundary>
            </main>
          </div>
        </div>
      </MobileSidebarProvider>
    </PermissionsProvider>
  )
}
