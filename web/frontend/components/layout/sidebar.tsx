'use client'

import Link from 'next/link'
import { usePathname, useRouter } from 'next/navigation'
import { cn } from '@/lib/utils'
import { ThemeToggle } from '@/components/ui/theme-toggle'
import { useMobileSidebar } from '@/contexts/MobileSidebarContext'
import {
  LayoutDashboard,
  Scan,
  AlertTriangle,
  Settings,
  LogOut,
  Shield,
  Users,
  UserCog,
  FileWarning,
  Key,
  Calendar,
  Bell,
  ClipboardCheck,
  GitCompare,
  X,
} from 'lucide-react'

const navigation = [
  { name: 'Dashboard', href: '/dashboard', icon: LayoutDashboard },
  { name: 'Scans', href: '/dashboard/scans', icon: Scan },
  { name: 'Findings', href: '/dashboard/findings', icon: AlertTriangle },
  { name: 'Delta Tracking', href: '/dashboard/delta', icon: GitCompare },
  { name: 'Compliance', href: '/dashboard/compliance', icon: ClipboardCheck },
  { name: 'Schedules', href: '/dashboard/schedules', icon: Calendar },
  { name: 'Alerts', href: '/dashboard/alerts', icon: Bell },
  { name: 'Users', href: '/dashboard/users', icon: UserCog },
  { name: 'Settings', href: '/dashboard/settings', icon: Settings },
]

const findingCategories = [
  { name: 'Security Posture', href: '/dashboard/findings?type=security', icon: Shield },
  { name: 'High-Risk Files', href: '/dashboard/findings?type=files', icon: FileWarning },
  { name: 'Inactive Users', href: '/dashboard/findings?type=users', icon: Users },
  { name: 'Risky OAuth Apps', href: '/dashboard/findings?type=oauth', icon: Key },
]

function SidebarContent({ onNavigate }: { onNavigate?: () => void }) {
  const pathname = usePathname()
  const router = useRouter()

  const handleLogout = () => {
    localStorage.removeItem('access_token')
    localStorage.removeItem('user')
    router.push('/login')
  }

  const handleLinkClick = () => {
    if (onNavigate) {
      onNavigate()
    }
  }

  const handleKeyDown = (e: React.KeyboardEvent, action: () => void) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault()
      action()
    }
  }

  return (
    <>
      <nav
        className="flex-1 space-y-1 px-3 py-4 overflow-y-auto"
        aria-label="Main navigation"
        role="navigation"
      >
        <ul className="space-y-1" role="list">
          {navigation.map((item) => {
            const isActive = pathname === item.href
            return (
              <li key={item.name} role="listitem">
                <Link
                  href={item.href}
                  onClick={handleLinkClick}
                  aria-current={isActive ? 'page' : undefined}
                  className={cn(
                    'flex items-center rounded-md px-3 py-2 text-sm font-medium transition-colors',
                    'focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 focus:ring-offset-gray-900',
                    isActive
                      ? 'bg-gray-800 text-white'
                      : 'text-gray-300 hover:bg-gray-800 hover:text-white'
                  )}
                >
                  <item.icon className="mr-3 h-5 w-5 flex-shrink-0" aria-hidden="true" />
                  <span>{item.name}</span>
                </Link>
              </li>
            )
          })}
        </ul>

        <div className="pt-6" role="region" aria-labelledby="finding-categories-heading">
          <h2
            id="finding-categories-heading"
            className="px-3 text-xs font-semibold uppercase tracking-wider text-gray-400"
          >
            Finding Categories
          </h2>
          <ul className="mt-2 space-y-1" role="list">
            {findingCategories.map((item) => (
              <li key={item.name} role="listitem">
                <Link
                  href={item.href}
                  onClick={handleLinkClick}
                  className={cn(
                    'flex items-center rounded-md px-3 py-2 text-sm font-medium text-gray-300',
                    'hover:bg-gray-800 hover:text-white transition-colors',
                    'focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 focus:ring-offset-gray-900'
                  )}
                >
                  <item.icon className="mr-3 h-5 w-5 flex-shrink-0" aria-hidden="true" />
                  <span>{item.name}</span>
                </Link>
              </li>
            ))}
          </ul>
        </div>
      </nav>

      <div className="border-t border-gray-800 p-4 space-y-2" role="region" aria-label="User actions">
        <ThemeToggle />
        <button
          onClick={handleLogout}
          onKeyDown={(e) => handleKeyDown(e, handleLogout)}
          className={cn(
            'flex w-full items-center rounded-md px-3 py-2 text-sm font-medium text-gray-300',
            'hover:bg-gray-800 hover:text-white transition-colors',
            'focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 focus:ring-offset-gray-900'
          )}
          aria-label="Sign out of your account"
        >
          <LogOut className="mr-3 h-5 w-5 flex-shrink-0" aria-hidden="true" />
          <span>Sign out</span>
        </button>
      </div>
    </>
  )
}

// Desktop sidebar - hidden on mobile
export function Sidebar() {
  return (
    <aside
      className="hidden lg:flex h-full w-64 flex-col bg-gray-900 flex-shrink-0"
      aria-label="Main sidebar"
    >
      <div className="flex h-16 items-center px-6">
        <Link
          href="/dashboard"
          className="flex items-center space-x-2 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 focus:ring-offset-gray-900 rounded-md"
          aria-label="Vaulytica - Go to dashboard"
        >
          <Shield className="h-8 w-8 text-white" aria-hidden="true" />
          <span className="text-xl font-bold text-white">Vaulytica</span>
        </Link>
      </div>
      <SidebarContent />
    </aside>
  )
}

// Mobile sidebar - overlay on mobile
export function MobileSidebar() {
  const { isOpen, close } = useMobileSidebar()

  // Handle escape key to close sidebar
  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape') {
      close()
    }
  }

  return (
    <>
      {/* Backdrop */}
      <div
        className={cn(
          'fixed inset-0 z-40 bg-black/50 transition-opacity lg:hidden',
          isOpen ? 'opacity-100' : 'opacity-0 pointer-events-none'
        )}
        onClick={close}
        aria-hidden="true"
      />

      {/* Sidebar panel */}
      <aside
        className={cn(
          'fixed inset-y-0 left-0 z-50 w-64 bg-gray-900 transform transition-transform duration-300 ease-in-out lg:hidden',
          isOpen ? 'translate-x-0' : '-translate-x-full'
        )}
        aria-label="Mobile navigation menu"
        aria-hidden={!isOpen}
        role="dialog"
        aria-modal="true"
        onKeyDown={handleKeyDown}
      >
        <div className="flex h-16 items-center justify-between px-6">
          <Link
            href="/dashboard"
            className="flex items-center space-x-2 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 focus:ring-offset-gray-900 rounded-md"
            onClick={close}
            aria-label="Vaulytica - Go to dashboard"
          >
            <Shield className="h-8 w-8 text-white" aria-hidden="true" />
            <span className="text-xl font-bold text-white">Vaulytica</span>
          </Link>
          <button
            onClick={close}
            className="rounded-md p-2 text-gray-400 hover:bg-gray-800 hover:text-white focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 focus:ring-offset-gray-900"
            aria-label="Close navigation menu"
          >
            <X className="h-5 w-5" aria-hidden="true" />
          </button>
        </div>
        <SidebarContent onNavigate={close} />
      </aside>
    </>
  )
}
