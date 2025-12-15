import { render, screen } from '@testing-library/react'
import {
  Card,
  CardHeader,
  CardFooter,
  CardTitle,
  CardDescription,
  CardContent,
} from '@/components/ui/card'

describe('Card components', () => {
  describe('Card', () => {
    it('renders children', () => {
      render(<Card>Card content</Card>)
      expect(screen.getByText('Card content')).toBeInTheDocument()
    })

    it('applies default classes', () => {
      render(<Card data-testid="card">Content</Card>)
      const card = screen.getByTestId('card')
      expect(card).toHaveClass('rounded-lg')
      expect(card).toHaveClass('border')
      expect(card).toHaveClass('shadow-sm')
    })

    it('applies custom className', () => {
      render(<Card className="custom-card" data-testid="card">Content</Card>)
      expect(screen.getByTestId('card')).toHaveClass('custom-card')
    })

    it('forwards ref', () => {
      const ref = { current: null }
      render(<Card ref={ref}>Content</Card>)
      expect(ref.current).toBeInstanceOf(HTMLDivElement)
    })
  })

  describe('CardHeader', () => {
    it('renders children', () => {
      render(<CardHeader>Header content</CardHeader>)
      expect(screen.getByText('Header content')).toBeInTheDocument()
    })

    it('applies padding', () => {
      render(<CardHeader data-testid="header">Content</CardHeader>)
      expect(screen.getByTestId('header')).toHaveClass('p-6')
    })

    it('applies custom className', () => {
      render(<CardHeader className="custom-header" data-testid="header">Content</CardHeader>)
      expect(screen.getByTestId('header')).toHaveClass('custom-header')
    })
  })

  describe('CardTitle', () => {
    it('renders as h3', () => {
      render(<CardTitle>Title</CardTitle>)
      const title = screen.getByRole('heading', { level: 3 })
      expect(title).toHaveTextContent('Title')
    })

    it('applies font styling', () => {
      render(<CardTitle data-testid="title">Title</CardTitle>)
      const title = screen.getByTestId('title')
      expect(title).toHaveClass('text-2xl')
      expect(title).toHaveClass('font-semibold')
    })

    it('applies custom className', () => {
      render(<CardTitle className="custom-title" data-testid="title">Title</CardTitle>)
      expect(screen.getByTestId('title')).toHaveClass('custom-title')
    })
  })

  describe('CardDescription', () => {
    it('renders as paragraph', () => {
      render(<CardDescription>Description text</CardDescription>)
      expect(screen.getByText('Description text')).toBeInTheDocument()
    })

    it('applies muted styling', () => {
      render(<CardDescription data-testid="desc">Description</CardDescription>)
      const desc = screen.getByTestId('desc')
      expect(desc).toHaveClass('text-sm')
      expect(desc).toHaveClass('text-muted-foreground')
    })

    it('applies custom className', () => {
      render(<CardDescription className="custom-desc" data-testid="desc">Description</CardDescription>)
      expect(screen.getByTestId('desc')).toHaveClass('custom-desc')
    })
  })

  describe('CardContent', () => {
    it('renders children', () => {
      render(<CardContent>Content area</CardContent>)
      expect(screen.getByText('Content area')).toBeInTheDocument()
    })

    it('applies padding', () => {
      render(<CardContent data-testid="content">Content</CardContent>)
      const content = screen.getByTestId('content')
      expect(content).toHaveClass('p-6')
      expect(content).toHaveClass('pt-0')
    })

    it('applies custom className', () => {
      render(<CardContent className="custom-content" data-testid="content">Content</CardContent>)
      expect(screen.getByTestId('content')).toHaveClass('custom-content')
    })
  })

  describe('CardFooter', () => {
    it('renders children', () => {
      render(<CardFooter>Footer content</CardFooter>)
      expect(screen.getByText('Footer content')).toBeInTheDocument()
    })

    it('applies flex layout', () => {
      render(<CardFooter data-testid="footer">Footer</CardFooter>)
      const footer = screen.getByTestId('footer')
      expect(footer).toHaveClass('flex')
      expect(footer).toHaveClass('items-center')
    })

    it('applies custom className', () => {
      render(<CardFooter className="custom-footer" data-testid="footer">Footer</CardFooter>)
      expect(screen.getByTestId('footer')).toHaveClass('custom-footer')
    })
  })

  describe('Full Card composition', () => {
    it('renders a complete card with all parts', () => {
      render(
        <Card data-testid="full-card">
          <CardHeader>
            <CardTitle>Security Scan Results</CardTitle>
            <CardDescription>Last updated 5 minutes ago</CardDescription>
          </CardHeader>
          <CardContent>
            <p>Scan found 3 issues</p>
          </CardContent>
          <CardFooter>
            <button>View Details</button>
          </CardFooter>
        </Card>
      )

      expect(screen.getByTestId('full-card')).toBeInTheDocument()
      expect(screen.getByRole('heading', { name: 'Security Scan Results' })).toBeInTheDocument()
      expect(screen.getByText('Last updated 5 minutes ago')).toBeInTheDocument()
      expect(screen.getByText('Scan found 3 issues')).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'View Details' })).toBeInTheDocument()
    })
  })
})
