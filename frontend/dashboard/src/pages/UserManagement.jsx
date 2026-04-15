import { useEffect, useState } from 'react'
import { Users, Trash2, ShieldCheck, ShieldOff, RefreshCw, Plus, Key, X } from 'lucide-react'
import { api, token } from '../api'
import { Panel } from '../components/Panel'

function fmtTs(ts) {
  if (!ts) return '—'
  return ts.replace('T', ' ').slice(0, 16)
}

const ROLE_COLORS = {
  admin:   'text-purple-400 bg-purple-500/10 border-purple-500/30',
  analyst: 'text-blue-400 bg-blue-500/10 border-blue-500/30',
}

export function UserManagement() {
  const [users, setUsers]           = useState([])
  const [loading, setLoading]       = useState(true)
  const [error, setError]           = useState('')
  const [createModal, setCreateModal] = useState(false)
  const [resetModal, setResetModal]   = useState(null)  // user object
  const [deleteModal, setDeleteModal] = useState(null)  // user object
  const [form, setForm]             = useState({ username: '', email: '', password: '', role: 'analyst' })
  const [resetPw, setResetPw]       = useState('')
  const [saving, setSaving]         = useState(false)
  const [feedback, setFeedback]     = useState('')
  const me = token.user()

  async function load() {
    setLoading(true)
    try {
      const data = await api.users()
      setUsers(data)
    } catch (e) {
      setError(e.message)
    } finally { setLoading(false) }
  }

  useEffect(() => { load() }, [])

  async function createUser() {
    setSaving(true)
    setFeedback('')
    try {
      const r = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token.get()}` },
        body: JSON.stringify(form),
      })
      const d = await r.json()
      if (!r.ok) throw new Error(d.detail || 'Failed')
      // If admin is creating an analyst, role stays analyst. But first user is auto-admin.
      // Patch role if needed
      if (d.role !== form.role) {
        await api.changeRole(d.id, form.role)
      }
      setCreateModal(false)
      setForm({ username: '', email: '', password: '', role: 'analyst' })
      setFeedback('User created successfully.')
      load()
    } catch (e) {
      setFeedback(e.message)
    } finally { setSaving(false) }
  }

  async function changeRole(user, newRole) {
    try {
      await api.changeRole(user.id, newRole)
      setUsers(prev => prev.map(u => u.id === user.id ? { ...u, role: newRole } : u))
    } catch (e) { setFeedback(e.message) }
  }

  async function resetPassword() {
    if (!resetPw.trim()) return
    setSaving(true)
    setFeedback('')
    try {
      const r = await fetch(`/api/auth/users/${resetModal.id}/reset-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token.get()}` },
        body: JSON.stringify({ new_password: resetPw }),
      })
      const d = await r.json()
      if (!r.ok) throw new Error(d.detail || 'Failed')
      setResetModal(null)
      setResetPw('')
      setFeedback(`Password reset for ${resetModal.username}.`)
    } catch (e) { setFeedback(e.message) }
    finally { setSaving(false) }
  }

  async function deleteUser() {
    setSaving(true)
    try {
      await api.deleteUser(deleteModal.id)
      setDeleteModal(null)
      setFeedback(`User ${deleteModal.username} deleted.`)
      load()
    } catch (e) { setFeedback(e.message) }
    finally { setSaving(false) }
  }

  if (me?.role !== 'admin') {
    return (
      <div className="flex items-center justify-center h-64 text-slate-500 text-sm">
        Admin access required.
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <Panel
        title={<span className="flex items-center gap-2"><Users size={16} /> User Management</span>}
        subtitle="Create, manage roles, reset passwords, and remove users"
        actions={
          <div className="flex items-center gap-2">
            {feedback && (
              <span className="text-xs text-green-400 font-medium">{feedback}</span>
            )}
            <button
              onClick={load}
              className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-white border border-[#30363d] px-3 py-1.5 rounded-lg transition-colors"
            >
              <RefreshCw size={12} /> Refresh
            </button>
            <button
              onClick={() => { setCreateModal(true); setFeedback('') }}
              className="flex items-center gap-1.5 text-xs bg-blue-600 hover:bg-blue-500 text-white px-3 py-1.5 rounded-lg transition-colors"
            >
              <Plus size={12} /> New User
            </button>
          </div>
        }
      >
        {error && <div className="text-red-400 text-sm mb-4">{error}</div>}
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left">
                {['#', 'Username', 'Email', 'Role', 'Created', 'Actions'].map(h => (
                  <th key={h} className="pb-3 pr-4 text-xs font-semibold uppercase tracking-wider text-slate-500 whitespace-nowrap">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading && (
                <tr><td colSpan={6} className="py-10 text-center text-slate-500">Loading…</td></tr>
              )}
              {!loading && users.map(u => (
                <tr key={u.id} className={`border-t border-[#30363d] hover:bg-white/[0.02] transition-colors ${u.id === me?.id ? 'bg-blue-500/5' : ''}`}>
                  <td className="py-3 pr-4 text-slate-500 text-xs">{u.id}</td>
                  <td className="py-3 pr-4">
                    <div className="flex items-center gap-2">
                      <div className="w-7 h-7 rounded-full bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center text-xs font-bold text-white shrink-0">
                        {u.username[0].toUpperCase()}
                      </div>
                      <span className="text-slate-200 font-medium text-sm">{u.username}</span>
                      {u.id === me?.id && <span className="text-[10px] text-blue-400 border border-blue-500/30 px-1.5 py-0.5 rounded-full">You</span>}
                    </div>
                  </td>
                  <td className="py-3 pr-4 text-slate-400 text-xs">{u.email}</td>
                  <td className="py-3 pr-4">
                    {u.id === me?.id ? (
                      <span className={`text-xs font-semibold px-2 py-0.5 rounded-full border ${ROLE_COLORS[u.role] || ''}`}>{u.role}</span>
                    ) : (
                      <select
                        value={u.role}
                        onChange={e => changeRole(u, e.target.value)}
                        className={`text-xs font-semibold px-2 py-0.5 rounded-full border bg-transparent cursor-pointer ${ROLE_COLORS[u.role] || 'text-slate-400 border-slate-600'}`}
                      >
                        <option value="analyst">analyst</option>
                        <option value="admin">admin</option>
                      </select>
                    )}
                  </td>
                  <td className="py-3 pr-4 text-slate-500 text-xs whitespace-nowrap">{fmtTs(u.created_at)}</td>
                  <td className="py-3">
                    <div className="flex items-center gap-1">
                      <button
                        onClick={() => { setResetModal(u); setResetPw(''); setFeedback('') }}
                        title="Reset password"
                        className="p-1.5 rounded text-slate-500 hover:text-yellow-400 hover:bg-yellow-500/10 transition-colors"
                      >
                        <Key size={13} />
                      </button>
                      {u.id !== me?.id && (
                        <button
                          onClick={() => { setDeleteModal(u); setFeedback('') }}
                          title="Delete user"
                          className="p-1.5 rounded text-slate-500 hover:text-red-400 hover:bg-red-500/10 transition-colors"
                        >
                          <Trash2 size={13} />
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>

      {/* Create User Modal */}
      {createModal && (
        <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4">
          <div className="bg-[#161b22] border border-[#30363d] rounded-xl w-full max-w-sm p-5 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-white font-semibold text-sm">Create New User</h3>
              <button onClick={() => setCreateModal(false)} className="text-slate-500 hover:text-slate-300"><X size={14} /></button>
            </div>
            {feedback && <p className="text-red-400 text-xs">{feedback}</p>}
            <div className="space-y-3">
              {[
                { label: 'Username', key: 'username', type: 'text', placeholder: 'e.g. john.doe1' },
                { label: 'Email', key: 'email', type: 'email', placeholder: 'john.doe1@sentinelai.com' },
                { label: 'Password', key: 'password', type: 'password', placeholder: 'Min 8 chars, 1 upper, 1 digit, 1 special' },
              ].map(({ label, key, type, placeholder }) => (
                <div key={key}>
                  <label className="text-xs text-slate-500 mb-1 block">{label}</label>
                  <input
                    type={type}
                    value={form[key]}
                    onChange={e => setForm(prev => ({ ...prev, [key]: e.target.value }))}
                    placeholder={placeholder}
                    className="w-full bg-[#1c2128] border border-[#30363d] rounded-lg px-3 py-2 text-sm text-white placeholder-slate-600 focus:outline-none focus:border-blue-500/50"
                  />
                </div>
              ))}
              <div>
                <label className="text-xs text-slate-500 mb-1 block">Role</label>
                <select
                  value={form.role}
                  onChange={e => setForm(prev => ({ ...prev, role: e.target.value }))}
                  className="w-full bg-[#1c2128] border border-[#30363d] rounded-lg px-3 py-2 text-sm text-slate-300 focus:outline-none"
                >
                  <option value="analyst">Analyst</option>
                  <option value="admin">Admin</option>
                </select>
              </div>
            </div>
            <div className="flex gap-3 pt-1">
              <button
                onClick={createUser}
                disabled={saving || !form.username || !form.email || !form.password}
                className="flex-1 bg-blue-600 hover:bg-blue-500 disabled:opacity-40 text-white text-sm font-semibold py-2 rounded-lg transition-colors"
              >
                {saving ? 'Creating…' : 'Create'}
              </button>
              <button
                onClick={() => { setCreateModal(false); setFeedback('') }}
                className="flex-1 bg-[#1c2128] border border-[#30363d] text-slate-300 text-sm py-2 rounded-lg hover:border-slate-500 transition-colors"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Reset Password Modal */}
      {resetModal && (
        <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4">
          <div className="bg-[#161b22] border border-[#30363d] rounded-xl w-full max-w-sm p-5 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-white font-semibold text-sm">Reset password for <span className="text-blue-400">{resetModal.username}</span></h3>
              <button onClick={() => setResetModal(null)} className="text-slate-500 hover:text-slate-300"><X size={14} /></button>
            </div>
            {feedback && <p className="text-red-400 text-xs">{feedback}</p>}
            <div>
              <label className="text-xs text-slate-500 mb-1 block">New Password</label>
              <input
                type="password"
                value={resetPw}
                onChange={e => setResetPw(e.target.value)}
                placeholder="Min 8 chars, 1 upper, 1 digit, 1 special"
                className="w-full bg-[#1c2128] border border-[#30363d] rounded-lg px-3 py-2 text-sm text-white placeholder-slate-600 focus:outline-none focus:border-blue-500/50"
              />
            </div>
            <div className="flex gap-3 pt-1">
              <button
                onClick={resetPassword}
                disabled={saving || !resetPw.trim()}
                className="flex-1 bg-yellow-600 hover:bg-yellow-500 disabled:opacity-40 text-white text-sm font-semibold py-2 rounded-lg transition-colors"
              >
                {saving ? 'Saving…' : 'Reset Password'}
              </button>
              <button
                onClick={() => setResetModal(null)}
                className="flex-1 bg-[#1c2128] border border-[#30363d] text-slate-300 text-sm py-2 rounded-lg hover:border-slate-500 transition-colors"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Delete Confirm Modal */}
      {deleteModal && (
        <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4">
          <div className="bg-[#161b22] border border-[#30363d] rounded-xl w-full max-w-sm p-5 space-y-4">
            <h3 className="text-white font-semibold text-sm">Delete user <span className="text-red-400">{deleteModal.username}</span>?</h3>
            <p className="text-slate-500 text-xs">This action cannot be undone. The user will lose all access immediately.</p>
            <div className="flex gap-3 pt-1">
              <button
                onClick={deleteUser}
                disabled={saving}
                className="flex-1 bg-red-700 hover:bg-red-600 disabled:opacity-40 text-white text-sm font-semibold py-2 rounded-lg transition-colors"
              >
                {saving ? 'Deleting…' : 'Delete'}
              </button>
              <button
                onClick={() => setDeleteModal(null)}
                className="flex-1 bg-[#1c2128] border border-[#30363d] text-slate-300 text-sm py-2 rounded-lg hover:border-slate-500 transition-colors"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
