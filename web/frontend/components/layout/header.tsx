'use client'

import { useEffect, useState } from 'react'
import { User } from '@/lib/types'
import { useMobileSidebar } from '@/contexts/MobileSidebarContext'
import { Menu, Shield } from 'lucide-react'
import Link from 'next/link'

export function Header() {
  const [user, setUser] = useState<User | null>(null)
  const { toggle } = useMobileSidebar()

  useEffect(() => {
    const userData = localStorage.getItem('user')
    if (userData) {
      setUser(JSON.parse(userData))
    }
  }, [])

  return (
    <header
      className="flex h-16 items-center justify-between border-b border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 px-4 sm:px-6"
      role="banner"
    >
      {/* Mobile: menu button + logo */}
      <div className="flex items-center lg:hidden">
        <button
          onClick={toggle}
          className="rounded-md p-2 text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2"
          aria-label="Open navigation menu"
          aria-expanded="false"
          aria-controls="mobile-sidebar"
        >
          <Menu className="h-6 w-6" aria-hidden="true" />
        </button>
        <Link
          href="/dashboard"
          className="ml-2 flex items-center space-x-2 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 rounded-md"
          aria-label="Vaulytica - Go to dashboard"
        >
          <Shield className="h-6 w-6 text-gray-900 dark:text-white" aria-hidden="true" />
          <span className="text-lg font-bold text-gray-900 dark:text-white">Vaulytica</span>
        </Link>
      </div>

      {/* Desktop: title */}
      <div className="hidden lg:block">
        <h1 className="text-lg font-semibold text-gray-900 dark:text-white">
          Security Dashboard
        </h1>
      </div>

      {/* User info - always visible but adapts */}
      <div
        className="flex items-center space-x-2 sm:space-x-4"
        role="region"
        aria-label="User information"
      >
        <span
          className="hidden sm:block text-sm text-gray-600 dark:text-gray-300 truncate max-w-[200px]"
          aria-label={`Logged in as ${user?.email || 'Loading'}`}
        >
          {user?.email || 'Loading...'}
        </span>
        <div
          className="h-8 w-8 rounded-full bg-gray-200 dark:bg-gray-600 flex items-center justify-center flex-shrink-0"
          role="img"
          aria-label={`User avatar for ${user?.email || 'user'}`}
        >
          <span className="text-sm font-medium text-gray-600 dark:text-gray-200" aria-hidden="true">
            {user?.email?.[0]?.toUpperCase() || '?'}
          </span>
        </div>
      </div>
    </header>
  )
}
