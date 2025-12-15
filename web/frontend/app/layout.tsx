import type { Metadata } from 'next'
import { Inter } from 'next/font/google'
import './globals.css'
import { ErrorBoundary } from '@/components/ErrorBoundary'
import { ToastProvider } from '@/components/ui/toast'
import { ThemeProvider } from '@/contexts/ThemeContext'

const inter = Inter({ subsets: ['latin'] })

export const metadata: Metadata = {
  title: 'Vaulytica - Google Workspace Security Dashboard',
  description: 'Enterprise-Grade Google Workspace Security & Compliance Platform',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className={inter.className}>
        <ThemeProvider>
          <ErrorBoundary>
            <ToastProvider>
              {children}
            </ToastProvider>
          </ErrorBoundary>
        </ThemeProvider>
      </body>
    </html>
  )
}
