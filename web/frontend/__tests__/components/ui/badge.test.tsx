import { render, screen } from '@testing-library/react'
import { Badge } from '@/components/ui/badge'

describe('Badge', () => {
  it('renders with default variant', () => {
    render(<Badge>Default</Badge>)
    const badge = screen.getByText('Default')
    expect(badge).toBeInTheDocument()
    expect(badge).toHaveClass('bg-primary')
  })

  it('renders with success variant', () => {
    render(<Badge variant="success">Success</Badge>)
    const badge = screen.getByText('Success')
    expect(badge).toBeInTheDocument()
    expect(badge).toHaveClass('bg-green-100')
    expect(badge).toHaveClass('text-green-800')
  })

  it('renders with warning variant', () => {
    render(<Badge variant="warning">Warning</Badge>)
    const badge = screen.getByText('Warning')
    expect(badge).toHaveClass('bg-yellow-100')
    expect(badge).toHaveClass('text-yellow-800')
  })

  it('renders with danger variant', () => {
    render(<Badge variant="danger">Danger</Badge>)
    const badge = screen.getByText('Danger')
    expect(badge).toHaveClass('bg-red-100')
    expect(badge).toHaveClass('text-red-800')
  })

  it('renders with secondary variant', () => {
    render(<Badge variant="secondary">Secondary</Badge>)
    const badge = screen.getByText('Secondary')
    expect(badge).toHaveClass('bg-secondary')
  })

  it('applies custom className', () => {
    render(<Badge className="custom-class">Custom</Badge>)
    const badge = screen.getByText('Custom')
    expect(badge).toHaveClass('custom-class')
  })

  it('passes through additional props', () => {
    render(<Badge data-testid="test-badge">Test</Badge>)
    expect(screen.getByTestId('test-badge')).toBeInTheDocument()
  })
})
