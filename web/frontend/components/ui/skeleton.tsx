import { cn } from "@/lib/utils"

interface SkeletonProps extends React.HTMLAttributes<HTMLDivElement> {}

export function Skeleton({ className, ...props }: SkeletonProps) {
  return (
    <div
      className={cn("animate-pulse rounded-md bg-gray-200", className)}
      {...props}
    />
  )
}

export function TableSkeleton({ rows = 5, cols = 5 }: { rows?: number; cols?: number }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full">
        <thead>
          <tr className="border-b">
            {Array.from({ length: cols }).map((_, i) => (
              <th key={i} className="pb-3">
                <Skeleton className="h-4 w-20" />
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {Array.from({ length: rows }).map((_, rowIndex) => (
            <tr key={rowIndex} className="border-b">
              {Array.from({ length: cols }).map((_, colIndex) => (
                <td key={colIndex} className="py-3">
                  <Skeleton className="h-4 w-full max-w-[120px]" />
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export function CardSkeleton() {
  return (
    <div className="rounded-lg border p-4 space-y-3">
      <div className="flex items-center space-x-2">
        <Skeleton className="h-5 w-16" />
        <Skeleton className="h-4 w-24" />
      </div>
      <Skeleton className="h-5 w-3/4" />
      <Skeleton className="h-4 w-full" />
      <Skeleton className="h-4 w-2/3" />
    </div>
  )
}

export function CardListSkeleton({ count = 3 }: { count?: number }) {
  return (
    <div className="space-y-4">
      {Array.from({ length: count }).map((_, i) => (
        <CardSkeleton key={i} />
      ))}
    </div>
  )
}

export function DashboardStatsSkeleton() {
  return (
    <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
      {Array.from({ length: 4 }).map((_, i) => (
        <div key={i} className="rounded-lg border p-6 space-y-2">
          <Skeleton className="h-4 w-24" />
          <Skeleton className="h-8 w-16" />
          <Skeleton className="h-3 w-32" />
        </div>
      ))}
    </div>
  )
}

export function PageHeaderSkeleton() {
  return (
    <div className="space-y-2">
      <Skeleton className="h-8 w-48" />
      <Skeleton className="h-4 w-64" />
    </div>
  )
}

export function FindingsPageSkeleton() {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <PageHeaderSkeleton />
        <div className="flex space-x-2">
          <Skeleton className="h-9 w-20" />
          <Skeleton className="h-9 w-20" />
        </div>
      </div>
      <div className="flex space-x-2 border-b pb-2">
        {Array.from({ length: 4 }).map((_, i) => (
          <Skeleton key={i} className="h-8 w-32" />
        ))}
      </div>
      <div className="rounded-lg border">
        <div className="p-4 border-b">
          <Skeleton className="h-6 w-48" />
        </div>
        <div className="p-4">
          <CardListSkeleton count={5} />
        </div>
      </div>
    </div>
  )
}

export function ScansPageSkeleton() {
  return (
    <div className="space-y-6">
      <PageHeaderSkeleton />
      <div className="rounded-lg border">
        <div className="p-4 border-b">
          <Skeleton className="h-6 w-32" />
        </div>
        <div className="p-4">
          <TableSkeleton rows={8} cols={7} />
        </div>
      </div>
    </div>
  )
}

export function SchedulesPageSkeleton() {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <PageHeaderSkeleton />
        <Skeleton className="h-9 w-32" />
      </div>
      <div className="rounded-lg border">
        <div className="p-4 border-b">
          <Skeleton className="h-6 w-40" />
        </div>
        <div className="p-4 space-y-4">
          {Array.from({ length: 3 }).map((_, i) => (
            <div key={i} className="flex items-center justify-between rounded-lg border p-4">
              <div className="space-y-2">
                <div className="flex items-center space-x-2">
                  <Skeleton className="h-5 w-32" />
                  <Skeleton className="h-5 w-16" />
                </div>
                <Skeleton className="h-4 w-48" />
                <Skeleton className="h-4 w-40" />
              </div>
              <div className="flex space-x-2">
                <Skeleton className="h-8 w-8 rounded" />
                <Skeleton className="h-8 w-8 rounded" />
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

export function UsersPageSkeleton() {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <PageHeaderSkeleton />
        <div className="flex space-x-2">
          <Skeleton className="h-9 w-48" />
          <Skeleton className="h-9 w-24" />
        </div>
      </div>
      <div className="rounded-lg border">
        <div className="p-4 border-b">
          <Skeleton className="h-6 w-32" />
        </div>
        <div className="p-4">
          <TableSkeleton rows={10} cols={6} />
        </div>
      </div>
    </div>
  )
}
