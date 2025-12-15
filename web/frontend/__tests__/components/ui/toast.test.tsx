import { render, screen, fireEvent, act, waitFor } from '@testing-library/react'
import { ToastProvider, useToast } from '@/components/ui/toast'

// Test component that uses the toast hook
function TestComponent() {
  const { success, error, warning, info, toasts } = useToast()

  return (
    <div>
      <button onClick={() => success('Success!', 'Operation completed')}>Show Success</button>
      <button onClick={() => error('Error!', 'Something went wrong')}>Show Error</button>
      <button onClick={() => warning('Warning!', 'Please be careful')}>Show Warning</button>
      <button onClick={() => info('Info', 'For your information')}>Show Info</button>
      <div data-testid="toast-count">{toasts.length}</div>
    </div>
  )
}

function renderWithProvider(component: React.ReactNode) {
  return render(<ToastProvider>{component}</ToastProvider>)
}

describe('Toast', () => {
  beforeEach(() => {
    jest.useFakeTimers()
  })

  afterEach(() => {
    jest.useRealTimers()
  })

  describe('ToastProvider', () => {
    it('renders children', () => {
      renderWithProvider(<div>Test Child</div>)
      expect(screen.getByText('Test Child')).toBeInTheDocument()
    })
  })

  describe('useToast', () => {
    it('throws error when used outside provider', () => {
      // Suppress console.error for this test
      const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {})

      function BadComponent() {
        useToast()
        return null
      }

      expect(() => render(<BadComponent />)).toThrow('useToast must be used within a ToastProvider')
      consoleSpy.mockRestore()
    })
  })

  describe('success toast', () => {
    it('displays success toast with title and message', () => {
      renderWithProvider(<TestComponent />)

      fireEvent.click(screen.getByText('Show Success'))

      expect(screen.getByText('Success!')).toBeInTheDocument()
      expect(screen.getByText('Operation completed')).toBeInTheDocument()
    })

    it('applies success styling', () => {
      renderWithProvider(<TestComponent />)

      fireEvent.click(screen.getByText('Show Success'))

      const toast = screen.getByRole('alert')
      expect(toast).toHaveClass('bg-green-50')
      expect(toast).toHaveClass('border-green-200')
    })
  })

  describe('error toast', () => {
    it('displays error toast with title and message', () => {
      renderWithProvider(<TestComponent />)

      fireEvent.click(screen.getByText('Show Error'))

      expect(screen.getByText('Error!')).toBeInTheDocument()
      expect(screen.getByText('Something went wrong')).toBeInTheDocument()
    })

    it('applies error styling', () => {
      renderWithProvider(<TestComponent />)

      fireEvent.click(screen.getByText('Show Error'))

      const toast = screen.getByRole('alert')
      expect(toast).toHaveClass('bg-red-50')
      expect(toast).toHaveClass('border-red-200')
    })
  })

  describe('warning toast', () => {
    it('displays warning toast', () => {
      renderWithProvider(<TestComponent />)

      fireEvent.click(screen.getByText('Show Warning'))

      expect(screen.getByText('Warning!')).toBeInTheDocument()
    })

    it('applies warning styling', () => {
      renderWithProvider(<TestComponent />)

      fireEvent.click(screen.getByText('Show Warning'))

      const toast = screen.getByRole('alert')
      expect(toast).toHaveClass('bg-yellow-50')
    })
  })

  describe('info toast', () => {
    it('displays info toast', () => {
      renderWithProvider(<TestComponent />)

      fireEvent.click(screen.getByText('Show Info'))

      expect(screen.getByText('Info')).toBeInTheDocument()
    })

    it('applies info styling', () => {
      renderWithProvider(<TestComponent />)

      fireEvent.click(screen.getByText('Show Info'))

      const toast = screen.getByRole('alert')
      expect(toast).toHaveClass('bg-blue-50')
    })
  })

  describe('dismiss toast', () => {
    it('removes toast when dismiss button is clicked', () => {
      renderWithProvider(<TestComponent />)

      fireEvent.click(screen.getByText('Show Success'))
      expect(screen.getByText('Success!')).toBeInTheDocument()

      fireEvent.click(screen.getByLabelText('Dismiss'))
      expect(screen.queryByText('Success!')).not.toBeInTheDocument()
    })
  })

  describe('auto-dismiss', () => {
    it('automatically removes success toast after 5 seconds', async () => {
      renderWithProvider(<TestComponent />)

      fireEvent.click(screen.getByText('Show Success'))
      expect(screen.getByText('Success!')).toBeInTheDocument()

      act(() => {
        jest.advanceTimersByTime(5000)
      })

      await waitFor(() => {
        expect(screen.queryByText('Success!')).not.toBeInTheDocument()
      })
    })

    it('automatically removes error toast after 8 seconds', async () => {
      renderWithProvider(<TestComponent />)

      fireEvent.click(screen.getByText('Show Error'))
      expect(screen.getByText('Error!')).toBeInTheDocument()

      // Should still be there after 5 seconds
      act(() => {
        jest.advanceTimersByTime(5000)
      })
      expect(screen.getByText('Error!')).toBeInTheDocument()

      // Should be gone after 8 seconds total
      act(() => {
        jest.advanceTimersByTime(3000)
      })

      await waitFor(() => {
        expect(screen.queryByText('Error!')).not.toBeInTheDocument()
      })
    })
  })

  describe('multiple toasts', () => {
    it('can display multiple toasts at once', () => {
      renderWithProvider(<TestComponent />)

      fireEvent.click(screen.getByText('Show Success'))
      fireEvent.click(screen.getByText('Show Error'))
      fireEvent.click(screen.getByText('Show Warning'))

      expect(screen.getByTestId('toast-count')).toHaveTextContent('3')
      expect(screen.getByText('Success!')).toBeInTheDocument()
      expect(screen.getByText('Error!')).toBeInTheDocument()
      expect(screen.getByText('Warning!')).toBeInTheDocument()
    })
  })
})
