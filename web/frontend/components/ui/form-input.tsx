'use client'

import { forwardRef, InputHTMLAttributes, SelectHTMLAttributes, TextareaHTMLAttributes, ReactNode, useId } from 'react'
import { cn } from '@/lib/utils'

export interface FormFieldProps {
  label: string
  error?: string
  required?: boolean
  hint?: string
  children: ReactNode
  id?: string
}

export function FormField({ label, error, required, hint, children, id: propId }: FormFieldProps) {
  const generatedId = useId()
  const id = propId || generatedId
  const errorId = `${id}-error`
  const hintId = `${id}-hint`

  return (
    <div className="space-y-1">
      <label
        htmlFor={id}
        className="block text-sm font-medium text-gray-700 dark:text-gray-200"
      >
        {label}
        {required && <span className="text-red-500 ml-1" aria-hidden="true">*</span>}
        {required && <span className="sr-only">(required)</span>}
      </label>
      {hint && (
        <p id={hintId} className="text-xs text-gray-500 dark:text-gray-400">{hint}</p>
      )}
      {children}
      {error && (
        <p
          id={errorId}
          className="text-xs text-red-600 dark:text-red-400 mt-1"
          role="alert"
          aria-live="polite"
        >
          {error}
        </p>
      )}
    </div>
  )
}

interface InputProps extends InputHTMLAttributes<HTMLInputElement> {
  error?: boolean
  'aria-describedby'?: string
}

export const Input = forwardRef<HTMLInputElement, InputProps>(
  ({ className, error, 'aria-describedby': ariaDescribedBy, ...props }, ref) => {
    return (
      <input
        ref={ref}
        aria-invalid={error ? 'true' : undefined}
        aria-describedby={ariaDescribedBy}
        className={cn(
          "w-full rounded-md border px-3 py-2 text-sm",
          "focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-1",
          "bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100",
          "disabled:opacity-50 disabled:cursor-not-allowed",
          error ? "border-red-500 focus:ring-red-500" : "border-gray-300 dark:border-gray-600",
          className
        )}
        {...props}
      />
    )
  }
)
Input.displayName = 'Input'

interface SelectProps extends SelectHTMLAttributes<HTMLSelectElement> {
  error?: boolean
  children: ReactNode
  'aria-describedby'?: string
}

export const Select = forwardRef<HTMLSelectElement, SelectProps>(
  ({ className, error, children, 'aria-describedby': ariaDescribedBy, ...props }, ref) => {
    return (
      <select
        ref={ref}
        aria-invalid={error ? 'true' : undefined}
        aria-describedby={ariaDescribedBy}
        className={cn(
          "w-full rounded-md border px-3 py-2 text-sm",
          "focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-1",
          "bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100",
          "disabled:opacity-50 disabled:cursor-not-allowed",
          error ? "border-red-500 focus:ring-red-500" : "border-gray-300 dark:border-gray-600",
          className
        )}
        {...props}
      >
        {children}
      </select>
    )
  }
)
Select.displayName = 'Select'

interface CheckboxProps extends InputHTMLAttributes<HTMLInputElement> {
  label: string
}

export function Checkbox({ label, className, id: propId, ...props }: CheckboxProps) {
  const generatedId = useId()
  const id = propId || generatedId

  return (
    <div className="flex items-center space-x-2">
      <input
        type="checkbox"
        id={id}
        className={cn(
          "rounded border-gray-300 dark:border-gray-600 dark:bg-gray-800",
          "focus:ring-2 focus:ring-blue-500 focus:ring-offset-1",
          "disabled:opacity-50 disabled:cursor-not-allowed",
          className
        )}
        {...props}
      />
      <label
        htmlFor={id}
        className="text-sm text-gray-700 dark:text-gray-200 cursor-pointer select-none"
      >
        {label}
      </label>
    </div>
  )
}

interface TextAreaProps extends TextareaHTMLAttributes<HTMLTextAreaElement> {
  error?: boolean
  'aria-describedby'?: string
}

export const TextArea = forwardRef<HTMLTextAreaElement, TextAreaProps>(
  ({ className, error, 'aria-describedby': ariaDescribedBy, ...props }, ref) => {
    return (
      <textarea
        ref={ref}
        aria-invalid={error ? 'true' : undefined}
        aria-describedby={ariaDescribedBy}
        className={cn(
          "w-full rounded-md border px-3 py-2 text-sm resize-y min-h-[80px]",
          "focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-1",
          "bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100",
          "disabled:opacity-50 disabled:cursor-not-allowed",
          error ? "border-red-500 focus:ring-red-500" : "border-gray-300 dark:border-gray-600",
          className
        )}
        {...props}
      />
    )
  }
)
TextArea.displayName = 'TextArea'

// Skip link component for keyboard navigation
export function SkipLink({ href = '#main-content', children = 'Skip to main content' }: { href?: string; children?: ReactNode }) {
  return (
    <a
      href={href}
      className={cn(
        "sr-only focus:not-sr-only focus:absolute focus:top-4 focus:left-4 focus:z-50",
        "bg-blue-600 text-white px-4 py-2 rounded-md font-medium",
        "focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2"
      )}
    >
      {children}
    </a>
  )
}
