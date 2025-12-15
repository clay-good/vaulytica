'use client'

import { useTheme } from '@/contexts/ThemeContext'
import { Sun, Moon, Monitor } from 'lucide-react'

export function ThemeToggle() {
  const { theme, setTheme, resolvedTheme } = useTheme()

  const cycleTheme = () => {
    if (theme === 'light') {
      setTheme('dark')
    } else if (theme === 'dark') {
      setTheme('system')
    } else {
      setTheme('light')
    }
  }

  const getIcon = () => {
    if (theme === 'system') {
      return <Monitor className="h-5 w-5" />
    }
    if (theme === 'dark') {
      return <Moon className="h-5 w-5" />
    }
    return <Sun className="h-5 w-5" />
  }

  const getLabel = () => {
    if (theme === 'system') {
      return 'System'
    }
    if (theme === 'dark') {
      return 'Dark'
    }
    return 'Light'
  }

  return (
    <button
      onClick={cycleTheme}
      className="flex w-full items-center rounded-md px-3 py-2 text-sm font-medium text-gray-300 hover:bg-gray-800 hover:text-white"
      title={`Current theme: ${getLabel()}. Click to change.`}
    >
      {getIcon()}
      <span className="ml-3">{getLabel()} Mode</span>
    </button>
  )
}

export function ThemeToggleDropdown() {
  const { theme, setTheme } = useTheme()

  return (
    <div className="relative">
      <div className="flex flex-col space-y-1">
        <button
          onClick={() => setTheme('light')}
          className={`flex items-center rounded-md px-3 py-2 text-sm font-medium ${
            theme === 'light'
              ? 'bg-gray-800 text-white'
              : 'text-gray-300 hover:bg-gray-800 hover:text-white'
          }`}
        >
          <Sun className="mr-3 h-5 w-5" />
          Light
        </button>
        <button
          onClick={() => setTheme('dark')}
          className={`flex items-center rounded-md px-3 py-2 text-sm font-medium ${
            theme === 'dark'
              ? 'bg-gray-800 text-white'
              : 'text-gray-300 hover:bg-gray-800 hover:text-white'
          }`}
        >
          <Moon className="mr-3 h-5 w-5" />
          Dark
        </button>
        <button
          onClick={() => setTheme('system')}
          className={`flex items-center rounded-md px-3 py-2 text-sm font-medium ${
            theme === 'system'
              ? 'bg-gray-800 text-white'
              : 'text-gray-300 hover:bg-gray-800 hover:text-white'
          }`}
        >
          <Monitor className="mr-3 h-5 w-5" />
          System
        </button>
      </div>
    </div>
  )
}
