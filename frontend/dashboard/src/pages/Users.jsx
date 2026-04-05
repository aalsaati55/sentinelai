import { useEffect, useState } from 'react'
import { Shield, ShieldAlert, Trash2, UserCog, Users as UsersIcon } from 'lucide-react'
import { api, token } from '../api'
import { Panel } from '../components/Panel'

function fmtDate(ts) {
  if (!ts) return '—'
  return ts.replace('T', ' ').slice(0, 16)
}

const ROLE_STYLES = {
  admin:   'bg-purple-500/15 text-purple-400 border border-purple-500/25',
  analyst: 'bg-blue-500/15 text-blue-400 border border-blue-500/25',
}

export function Users() {
  const [users, setUsers]       = useState([])
  const [loading, setLoading]   = useState(true)
  const [error, setError]       = useState('')
  const [confirm, setConfirm]   = useState(null)  // { type: 'delete'|'role', user, newRole }
  const [busy, setBusy]         = useState(false)

  const me = token.user()

  useEffect(() => {
    api.users()
      .then(setUsers)
      .catch(() => setError('Failed to load users'))
      .finally(() => setLoading(false))
  }, [])

  async function handleRoleChange(user, newRole) {
    setConfirm({ type: 'role', user, newRole })
  }

  async function handleDelete(user) {
    setConfirm({ type: 'delete', user })
  }

  async function confirmAction() {
    setBusy(true)
    try {
      if (confirm.type === 'role') {
        const updated = await api.changeRole(confirm.user.id, confirm.newRole)
        setUsers(prev => prev.map(u => u.id === updated.id ? updated : u))
      } else {
        await api.deleteUser(confirm.user.id)
        setUsers(prev => prev.filter(u => u.id !== confirm.user.id))
      }
      setConfirm(null)
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  if (loading) return (
    <div className="flex items-center justify-center h-64 text-slate-500">
      <UsersIcon size={24} className="animate-pulse mr-2" /> Loading users…
    </div>
  )

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold text-white mb-1">User Management</h2>
        <p className="text-sm text-slate-500">Manage analyst and admin accounts — admin only</p>
      </div>

      {error && (
        <div className="bg-red-500/10 border border-red-500/20 text-red-400 rounded-lg px-4 py-3 text-sm">
          {error}
        </div>
      )}

      <Panel title={`All Users (${users.length})`}>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left">
                {['#', 'Username', 'Email', 'Role', 'Registered', 'Actions'].map(h => (
                  <th key={h} className="pb-3 pr-4 text-xs font-semibold uppercase tracking-wider text-slate-500 whitespace-nowrap">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {users.map(user => (
                <tr key={user.id} className="border-t border-[#30363d] hover:bg-white/[0.02] transition-colors">
                  <td className="py-3 pr-4 text-slate-500 text-xs">{user.id}</td>
                  <td className="py-3 pr-4">
                    <div className="flex items-center gap-2">
                      {user.role === 'admin'
                        ? <ShieldAlert size={14} className="text-purple-400 shrink-0" />
                        : <Shield size={14} className="text-blue-400 shrink-0" />
                      }
                      <span className="text-slate-200 font-medium">{user.username}</span>
                      {user.username === me?.username && (
                        <span className="text-xs text-slate-600">(you)</span>
                      )}
                    </div>
                  </td>
                  <td className="py-3 pr-4 text-slate-400 font-mono text-xs">{user.email}</td>
                  <td className="py-3 pr-4">
                    <span className={`text-xs font-semibold px-2 py-1 rounded-full ${ROLE_STYLES[user.role] || ''}`}>
                      {user.role}
                    </span>
                  </td>
                  <td className="py-3 pr-4 text-slate-500 text-xs whitespace-nowrap">{fmtDate(user.created_at)}</td>
                  <td className="py-3">
                    {user.username === me?.username ? (
                      <span className="text-xs text-slate-700">—</span>
                    ) : (
                      <div className="flex items-center gap-2">
                        {/* Role toggle */}
                        <button
                          onClick={() => handleRoleChange(user, user.role === 'admin' ? 'analyst' : 'admin')}
                          className="flex items-center gap-1 text-xs px-2.5 py-1 rounded-lg border border-[#30363d] text-slate-400 hover:text-blue-400 hover:border-blue-500/30 transition-colors"
                          title={`Make ${user.role === 'admin' ? 'analyst' : 'admin'}`}
                        >
                          <UserCog size={12} />
                          {user.role === 'admin' ? 'Make Analyst' : 'Make Admin'}
                        </button>

                        {/* Delete */}
                        <button
                          onClick={() => handleDelete(user)}
                          className="flex items-center gap-1 text-xs px-2.5 py-1 rounded-lg border border-[#30363d] text-slate-400 hover:text-red-400 hover:border-red-500/30 transition-colors"
                          title="Delete user"
                        >
                          <Trash2 size={12} />
                          Delete
                        </button>
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>

      {/* Confirm modal */}
      {confirm && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50">
          <div className="bg-[#161b22] border border-[#30363d] rounded-xl p-6 w-full max-w-md shadow-2xl">
            <h3 className="text-white font-semibold text-lg mb-2">
              {confirm.type === 'delete' ? 'Delete User' : 'Change Role'}
            </h3>
            <p className="text-slate-400 text-sm mb-6">
              {confirm.type === 'delete'
                ? <>Are you sure you want to delete <span className="text-white font-semibold">{confirm.user.username}</span>? This cannot be undone.</>
                : <>Change <span className="text-white font-semibold">{confirm.user.username}</span>'s role from <span className="font-semibold">{confirm.user.role}</span> to <span className="font-semibold text-blue-400">{confirm.newRole}</span>?</>
              }
            </p>
            <div className="flex gap-3 justify-end">
              <button
                onClick={() => setConfirm(null)}
                disabled={busy}
                className="px-4 py-2 text-sm rounded-lg border border-[#30363d] text-slate-400 hover:text-white transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={confirmAction}
                disabled={busy}
                className={`px-4 py-2 text-sm rounded-lg font-semibold transition-colors ${
                  confirm.type === 'delete'
                    ? 'bg-red-600 hover:bg-red-500 text-white'
                    : 'bg-blue-600 hover:bg-blue-500 text-white'
                }`}
              >
                {busy ? 'Processing…' : confirm.type === 'delete' ? 'Delete' : 'Confirm'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
