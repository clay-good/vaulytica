'use client'

import { useEffect, useState } from 'react'
import { api } from '@/lib/api'
import { User, AdminUserUpdate } from '@/lib/types'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { UsersPageSkeleton } from '@/components/ui/skeleton'
import { useToast } from '@/components/ui/toast'
import { FormField, Input, Select, Checkbox } from '@/components/ui/form-input'
import { formatDate } from '@/lib/utils'
import {
  UserCog,
  Search,
  ChevronLeft,
  ChevronRight,
  Edit,
  Trash2,
  UserCheck,
  UserX,
  Loader2,
  X,
  Shield,
} from 'lucide-react'

export default function UsersPage() {
  const [loading, setLoading] = useState(true)
  const [users, setUsers] = useState<User[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [totalPages, setTotalPages] = useState(1)
  const [search, setSearch] = useState('')
  const [filterActive, setFilterActive] = useState<boolean | undefined>(undefined)
  const [filterSuperuser, setFilterSuperuser] = useState<boolean | undefined>(undefined)
  const [error, setError] = useState<string | null>(null)
  const [currentUser, setCurrentUser] = useState<User | null>(null)

  // Edit modal state
  const [editingUser, setEditingUser] = useState<User | null>(null)
  const [editForm, setEditForm] = useState<AdminUserUpdate>({})
  const [saving, setSaving] = useState(false)

  // Action states
  const [activatingId, setActivatingId] = useState<number | null>(null)
  const [deactivatingId, setDeactivatingId] = useState<number | null>(null)
  const [deletingId, setDeletingId] = useState<number | null>(null)

  const { success, error: showError } = useToast()

  const fetchUsers = async () => {
    try {
      const data = await api.listUsers(page, 20, search || undefined, filterActive, filterSuperuser)
      setUsers(data.items)
      setTotal(data.total)
      setTotalPages(data.total_pages)
    } catch (err: any) {
      if (err.response?.status === 403) {
        setError('You do not have permission to view users. Admin access required.')
      } else {
        setError(err.response?.data?.detail || 'Failed to load users')
      }
    } finally {
      setLoading(false)
    }
  }

  const fetchCurrentUser = async () => {
    try {
      const user = await api.getCurrentUser()
      setCurrentUser(user)
    } catch (err) {
      // Ignore - user info not critical
    }
  }

  useEffect(() => {
    fetchCurrentUser()
  }, [])

  useEffect(() => {
    fetchUsers()
  }, [page, search, filterActive, filterSuperuser])

  const handleSearch = (value: string) => {
    setSearch(value)
    setPage(1)
  }

  const handleActivate = async (user: User) => {
    setActivatingId(user.id)
    try {
      await api.activateUser(user.id)
      await fetchUsers()
      success('User activated', `${user.email} has been activated.`)
    } catch (err: any) {
      showError('Failed to activate user', err.response?.data?.detail || 'Please try again.')
    } finally {
      setActivatingId(null)
    }
  }

  const handleDeactivate = async (user: User) => {
    setDeactivatingId(user.id)
    try {
      await api.deactivateUser(user.id)
      await fetchUsers()
      success('User deactivated', `${user.email} has been deactivated.`)
    } catch (err: any) {
      showError('Failed to deactivate user', err.response?.data?.detail || 'Please try again.')
    } finally {
      setDeactivatingId(null)
    }
  }

  const handleDelete = async (user: User) => {
    if (!confirm(`Are you sure you want to delete ${user.email}? This action cannot be undone.`)) {
      return
    }
    setDeletingId(user.id)
    try {
      await api.deleteUser(user.id)
      await fetchUsers()
      success('User deleted', `${user.email} has been permanently deleted.`)
    } catch (err: any) {
      showError('Failed to delete user', err.response?.data?.detail || 'Please try again.')
    } finally {
      setDeletingId(null)
    }
  }

  const openEditModal = (user: User) => {
    setEditingUser(user)
    setEditForm({
      email: user.email,
      full_name: user.full_name || '',
      is_active: user.is_active,
      is_superuser: user.is_superuser,
    })
  }

  const closeEditModal = () => {
    setEditingUser(null)
    setEditForm({})
  }

  const handleSaveEdit = async () => {
    if (!editingUser) return
    setSaving(true)
    try {
      await api.updateUser(editingUser.id, editForm)
      await fetchUsers()
      success('User updated', `${editingUser.email} has been updated.`)
      closeEditModal()
    } catch (err: any) {
      showError('Failed to update user', err.response?.data?.detail || 'Please try again.')
    } finally {
      setSaving(false)
    }
  }

  if (loading) {
    return <UsersPageSkeleton />
  }

  if (error) {
    return (
      <div className="space-y-6">
        <div>
          <h1 className="text-3xl font-bold">User Management</h1>
          <p className="text-muted-foreground">Manage web application users</p>
        </div>
        <div className="rounded-lg border border-red-200 bg-red-50 p-6">
          <p className="text-red-700">{error}</p>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">User Management</h1>
          <p className="text-muted-foreground">
            Manage web application users ({total} total)
          </p>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-4">
        <div className="relative flex-1 min-w-[200px] max-w-md">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-400" />
          <input
            type="text"
            placeholder="Search by email or name..."
            value={search}
            onChange={(e) => handleSearch(e.target.value)}
            className="w-full rounded-md border pl-10 pr-4 py-2 text-sm focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
          />
        </div>
        <select
          value={filterActive === undefined ? '' : filterActive.toString()}
          onChange={(e) => {
            setFilterActive(e.target.value === '' ? undefined : e.target.value === 'true')
            setPage(1)
          }}
          className="rounded-md border px-3 py-2 text-sm"
        >
          <option value="">All Status</option>
          <option value="true">Active</option>
          <option value="false">Inactive</option>
        </select>
        <select
          value={filterSuperuser === undefined ? '' : filterSuperuser.toString()}
          onChange={(e) => {
            setFilterSuperuser(e.target.value === '' ? undefined : e.target.value === 'true')
            setPage(1)
          }}
          className="rounded-md border px-3 py-2 text-sm"
        >
          <option value="">All Roles</option>
          <option value="true">Admins</option>
          <option value="false">Regular Users</option>
        </select>
      </div>

      {/* Users Table */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center">
            <UserCog className="mr-2 h-5 w-5" />
            Users
          </CardTitle>
        </CardHeader>
        <CardContent>
          {users.length === 0 ? (
            <p className="text-muted-foreground py-8 text-center">
              No users found matching your criteria.
            </p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b text-left text-sm text-muted-foreground">
                    <th className="pb-3 font-medium">Email</th>
                    <th className="pb-3 font-medium">Name</th>
                    <th className="pb-3 font-medium">Status</th>
                    <th className="pb-3 font-medium">Role</th>
                    <th className="pb-3 font-medium">Last Login</th>
                    <th className="pb-3 font-medium">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {users.map((user) => {
                    const isSelf = currentUser?.id === user.id
                    return (
                      <tr key={user.id} className="border-b">
                        <td className="py-3">
                          <div className="flex items-center">
                            <span className="font-medium">{user.email}</span>
                            {isSelf && (
                              <Badge variant="outline" className="ml-2 text-xs">You</Badge>
                            )}
                          </div>
                        </td>
                        <td className="py-3 text-muted-foreground">
                          {user.full_name || '-'}
                        </td>
                        <td className="py-3">
                          <Badge variant={user.is_active ? 'success' : 'destructive'}>
                            {user.is_active ? 'Active' : 'Inactive'}
                          </Badge>
                        </td>
                        <td className="py-3">
                          {user.is_superuser ? (
                            <Badge variant="default" className="flex items-center w-fit">
                              <Shield className="mr-1 h-3 w-3" />
                              Admin
                            </Badge>
                          ) : (
                            <span className="text-muted-foreground">User</span>
                          )}
                        </td>
                        <td className="py-3 text-sm text-muted-foreground">
                          {user.last_login ? formatDate(user.last_login) : 'Never'}
                        </td>
                        <td className="py-3">
                          <div className="flex items-center space-x-1">
                            <button
                              onClick={() => openEditModal(user)}
                              className="rounded p-1.5 hover:bg-gray-100"
                              title="Edit user"
                            >
                              <Edit className="h-4 w-4 text-gray-600" />
                            </button>
                            {user.is_active ? (
                              <button
                                onClick={() => handleDeactivate(user)}
                                disabled={deactivatingId === user.id || isSelf}
                                className="rounded p-1.5 hover:bg-gray-100 disabled:opacity-50"
                                title={isSelf ? 'Cannot deactivate yourself' : 'Deactivate user'}
                              >
                                {deactivatingId === user.id ? (
                                  <Loader2 className="h-4 w-4 animate-spin text-gray-500" />
                                ) : (
                                  <UserX className="h-4 w-4 text-orange-600" />
                                )}
                              </button>
                            ) : (
                              <button
                                onClick={() => handleActivate(user)}
                                disabled={activatingId === user.id}
                                className="rounded p-1.5 hover:bg-gray-100 disabled:opacity-50"
                                title="Activate user"
                              >
                                {activatingId === user.id ? (
                                  <Loader2 className="h-4 w-4 animate-spin text-gray-500" />
                                ) : (
                                  <UserCheck className="h-4 w-4 text-green-600" />
                                )}
                              </button>
                            )}
                            <button
                              onClick={() => handleDelete(user)}
                              disabled={deletingId === user.id || isSelf}
                              className="rounded p-1.5 hover:bg-gray-100 disabled:opacity-50"
                              title={isSelf ? 'Cannot delete yourself' : 'Delete user'}
                            >
                              {deletingId === user.id ? (
                                <Loader2 className="h-4 w-4 animate-spin text-gray-500" />
                              ) : (
                                <Trash2 className="h-4 w-4 text-red-600" />
                              )}
                            </button>
                          </div>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between pt-4 border-t mt-4">
              <p className="text-sm text-muted-foreground">
                Page {page} of {totalPages} ({total} users)
              </p>
              <div className="flex items-center space-x-2">
                <button
                  onClick={() => setPage(page - 1)}
                  disabled={page <= 1}
                  className="rounded-md border p-2 hover:bg-gray-50 disabled:opacity-50"
                >
                  <ChevronLeft className="h-4 w-4" />
                </button>
                <button
                  onClick={() => setPage(page + 1)}
                  disabled={page >= totalPages}
                  className="rounded-md border p-2 hover:bg-gray-50 disabled:opacity-50"
                >
                  <ChevronRight className="h-4 w-4" />
                </button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Edit Modal */}
      {editingUser && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <div className="w-full max-w-md rounded-lg bg-white p-6 shadow-xl">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold">Edit User</h2>
              <button onClick={closeEditModal} className="rounded p-1 hover:bg-gray-100">
                <X className="h-5 w-5" />
              </button>
            </div>
            <div className="space-y-4">
              <FormField label="Email">
                <Input
                  type="email"
                  value={editForm.email || ''}
                  onChange={(e) => setEditForm({ ...editForm, email: e.target.value })}
                />
              </FormField>
              <FormField label="Full Name">
                <Input
                  type="text"
                  value={editForm.full_name || ''}
                  onChange={(e) => setEditForm({ ...editForm, full_name: e.target.value })}
                />
              </FormField>
              <FormField label="New Password (leave blank to keep current)">
                <Input
                  type="password"
                  value={editForm.password || ''}
                  onChange={(e) => setEditForm({ ...editForm, password: e.target.value || undefined })}
                  placeholder="Enter new password..."
                />
              </FormField>
              <div className="space-y-2">
                <Checkbox
                  label="Active"
                  checked={editForm.is_active ?? true}
                  onChange={(e) => setEditForm({ ...editForm, is_active: e.target.checked })}
                  disabled={currentUser?.id === editingUser.id}
                />
                {currentUser?.id === editingUser.id && (
                  <p className="text-xs text-muted-foreground">Cannot deactivate yourself</p>
                )}
              </div>
              <div className="space-y-2">
                <Checkbox
                  label="Administrator"
                  checked={editForm.is_superuser ?? false}
                  onChange={(e) => setEditForm({ ...editForm, is_superuser: e.target.checked })}
                  disabled={currentUser?.id === editingUser.id}
                />
                {currentUser?.id === editingUser.id && (
                  <p className="text-xs text-muted-foreground">Cannot change your own admin status</p>
                )}
              </div>
            </div>
            <div className="flex justify-end space-x-2 mt-6">
              <button
                onClick={closeEditModal}
                className="rounded-md border px-4 py-2 text-sm hover:bg-gray-50"
              >
                Cancel
              </button>
              <button
                onClick={handleSaveEdit}
                disabled={saving}
                className="flex items-center space-x-2 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
              >
                {saving && <Loader2 className="h-4 w-4 animate-spin" />}
                <span>{saving ? 'Saving...' : 'Save Changes'}</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
