import { render, screen, fireEvent } from '@testing-library/react'
import { FormField, Input, Select, Checkbox } from '@/components/ui/form-input'

describe('FormField', () => {
  it('renders label and children', () => {
    render(
      <FormField label="Email">
        <input type="email" data-testid="email-input" />
      </FormField>
    )
    expect(screen.getByText('Email')).toBeInTheDocument()
    expect(screen.getByTestId('email-input')).toBeInTheDocument()
  })

  it('shows required indicator when required', () => {
    render(
      <FormField label="Name" required>
        <input type="text" />
      </FormField>
    )
    expect(screen.getByText('*')).toBeInTheDocument()
    expect(screen.getByText('*')).toHaveClass('text-red-500')
  })

  it('displays error message when provided', () => {
    render(
      <FormField label="Email" error="Invalid email address">
        <input type="email" />
      </FormField>
    )
    expect(screen.getByText('Invalid email address')).toBeInTheDocument()
    expect(screen.getByText('Invalid email address')).toHaveClass('text-red-600')
  })

  it('does not show error when not provided', () => {
    render(
      <FormField label="Email">
        <input type="email" />
      </FormField>
    )
    const errorElement = screen.queryByRole('alert')
    expect(errorElement).not.toBeInTheDocument()
  })
})

describe('Input', () => {
  it('renders with correct type', () => {
    render(<Input type="email" placeholder="Enter email" />)
    const input = screen.getByPlaceholderText('Enter email')
    expect(input).toHaveAttribute('type', 'email')
  })

  it('handles value changes', () => {
    const handleChange = jest.fn()
    render(<Input onChange={handleChange} placeholder="Test" />)
    const input = screen.getByPlaceholderText('Test')
    fireEvent.change(input, { target: { value: 'test value' } })
    expect(handleChange).toHaveBeenCalled()
  })

  it('applies error styling when error prop is true', () => {
    render(<Input error placeholder="Error input" />)
    const input = screen.getByPlaceholderText('Error input')
    expect(input).toHaveClass('border-red-500')
  })

  it('does not apply error styling when error is false', () => {
    render(<Input placeholder="Normal input" />)
    const input = screen.getByPlaceholderText('Normal input')
    expect(input).not.toHaveClass('border-red-500')
    expect(input).toHaveClass('border-gray-300')
  })

  it('applies custom className', () => {
    render(<Input className="custom-input" placeholder="Custom" />)
    const input = screen.getByPlaceholderText('Custom')
    expect(input).toHaveClass('custom-input')
  })

  it('forwards ref correctly', () => {
    const ref = { current: null }
    render(<Input ref={ref} placeholder="Ref test" />)
    expect(ref.current).toBeInstanceOf(HTMLInputElement)
  })
})

describe('Select', () => {
  it('renders with options', () => {
    render(
      <Select data-testid="select">
        <option value="a">Option A</option>
        <option value="b">Option B</option>
      </Select>
    )
    const select = screen.getByTestId('select')
    expect(select).toBeInTheDocument()
    expect(screen.getByText('Option A')).toBeInTheDocument()
    expect(screen.getByText('Option B')).toBeInTheDocument()
  })

  it('handles value changes', () => {
    const handleChange = jest.fn()
    render(
      <Select onChange={handleChange} data-testid="select">
        <option value="a">Option A</option>
        <option value="b">Option B</option>
      </Select>
    )
    const select = screen.getByTestId('select')
    fireEvent.change(select, { target: { value: 'b' } })
    expect(handleChange).toHaveBeenCalled()
  })

  it('applies error styling when error prop is true', () => {
    render(
      <Select error data-testid="error-select">
        <option>Test</option>
      </Select>
    )
    const select = screen.getByTestId('error-select')
    expect(select).toHaveClass('border-red-500')
  })

  it('forwards ref correctly', () => {
    const ref = { current: null }
    render(
      <Select ref={ref} data-testid="ref-select">
        <option>Test</option>
      </Select>
    )
    expect(ref.current).toBeInstanceOf(HTMLSelectElement)
  })
})

describe('Checkbox', () => {
  it('renders with label', () => {
    render(<Checkbox label="Accept terms" />)
    expect(screen.getByText('Accept terms')).toBeInTheDocument()
  })

  it('renders checkbox input', () => {
    render(<Checkbox label="Test checkbox" />)
    const checkbox = screen.getByRole('checkbox')
    expect(checkbox).toBeInTheDocument()
    expect(checkbox).toHaveAttribute('type', 'checkbox')
  })

  it('handles checked state', () => {
    const handleChange = jest.fn()
    render(<Checkbox label="Test" checked={false} onChange={handleChange} />)
    const checkbox = screen.getByRole('checkbox')
    fireEvent.click(checkbox)
    expect(handleChange).toHaveBeenCalled()
  })

  it('displays as checked when checked prop is true', () => {
    render(<Checkbox label="Checked" checked onChange={() => {}} />)
    const checkbox = screen.getByRole('checkbox')
    expect(checkbox).toBeChecked()
  })

  it('applies custom className', () => {
    render(<Checkbox label="Custom" className="custom-checkbox" />)
    const checkbox = screen.getByRole('checkbox')
    expect(checkbox).toHaveClass('custom-checkbox')
  })
})
