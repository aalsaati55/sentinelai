import { useEffect, useState } from 'react'
import { Shield, ShieldAlert, Trash2, UserCog, Users as UsersIcon, Plus, Key, X } from 'lucide-react'
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
  const [createModal, setCreateModal] = useState(false)
  const [resetModal, setResetModal]   = useState(null)  // user object
  const [createForm, setCreateForm]   = useState({ username: '', email: '', password: '', role: 'analyst' })
  const [resetPw, setResetPw]         = useState('')
  const [formError, setFormError]     = useState('')
  const [success, setSuccess]         = useState('')

  const me = token.user()

  function load() {
    api.users()
      .then(setUsers)
      .catch(() => setError('Failed to load users'))
      .finally(() => setLoading(false))
  }

  useEffect(() => { load() }, [])

  async function createUser() {
    setBusy(true); setFormError('')
    try {
      const r = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token.get()}` },
        body: JSON.stringify(createForm),
      })
      const d = await r.json()
      if (!r.ok) throw new Error(d.detail || 'Failed')
      if (d.role !== createForm.role) await api.changeRole(d.id, createForm.role)
      setCreateModal(false)
      setCreateForm({ username: '', email: '', password: '', role: 'analyst' })
      setSuccess('User created successfully.')
      load()
    } catch (e) { setFormError(e.message) }
    finally { setBusy(false) }
  }

  async function doResetPassword() {
    setBusy(true); setFormError('')
    try {
      const r = await fetch(`/api/auth/users/${resetModal.id}/reset-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token.get()}` },
        body: JSON.stringify({ new_password: resetPw }),
      })
      const d = await r.json()
      if (!r.ok) throw new Error(d.detail || 'Failed')
      setResetModal(null); setResetPw('')
      setSuccess(`Password reset for ${resetModal.username}.`)
    } catch (e) { setFormError(e.message) }
    finally { setBusy(false) }
  }

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
    <div className="flex items-center justify-center h-64 text-slate-600">
      <UsersIcon size={20} className="animate-pulse mr-2" /> Loading users…
    </div>
  )

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h2 className="page-title">User Management</h2>
          <p className="page-sub">Manage analyst and admin accounts — admin only</p>
        </div>
        <div className="flex items-center gap-3">
          {success && <span className="text-xs text-green-400 font-medium animate-fade-in">{success}</span>}
          <button
            onClick={() => { setCreateModal(true); setFormError(''); setSuccess('') }}
            className="btn-primary flex items-center gap-1.5 text-xs px-3 py-[0.4rem] rounded-[10px]"
          >
            <Plus size={12} /> New User
          </button>
        </div>
      </div>

      {error && (
        <div className="bg-red-500/8 border border-red-500/20 text-red-300 rounded-xl px-4 py-3 text-xs">
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
                <tr key={user.id} className="table-row-hover border-t border-white/[0.05]">
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
                        <button onClick={() => handleRoleChange(user, user.role === 'admin' ? 'analyst' : 'admin')}
                          className="btn-ghost flex items-center gap-1 text-xs px-2.5 py-1 rounded-[8px]"
                          title={`Make ${user.role === 'admin' ? 'analyst' : 'admin'}`}>
                          <UserCog size={11} />{user.role === 'admin' ? 'Make Analyst' : 'Make Admin'}
                        </button>
                        <button onClick={() => { setResetModal(user); setResetPw(''); setFormError('') }}
                          className="flex items-center gap-1 text-xs px-2.5 py-1 rounded-[8px] border border-yellow-500/20 text-yellow-500/70 hover:text-yellow-400 hover:border-yellow-500/40 hover:bg-yellow-500/5 transition-all"
                          title="Reset password">
                          <Key size={11} />Reset PW
                        </button>
                        <button onClick={() => handleDelete(user)}
                          className="btn-danger flex items-center gap-1 text-xs px-2.5 py-1 rounded-[8px]"
                          title="Delete user">
                          <Trash2 size={11} />Delete
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
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50">
          <div className="relative rounded-2xl p-6 w-full max-w-md shadow-[0_24px_80px_rgba(0,0,0,0.6)]"
            style={{ background: 'rgba(13,20,33,0.95)', border: '1px solid rgba(255,255,255,0.1)', backdropFilter: 'blur(20px)' }}>
            <div className="absolute top-0 left-8 right-8 h-px bg-gradient-to-r from-transparent via-red-500/30 to-transparent" />
            <h3 className="text-white font-bold text-base mb-2">
              {confirm.type === 'delete' ? 'Delete User' : 'Change Role'}
            </h3>
            <p className="text-slate-500 text-sm mb-6">
              {confirm.type === 'delete'
                ? <>Are you sure you want to delete <span className="text-white font-semibold">{confirm.user.username}</span>? This cannot be undone.</>
                : <>Change <span className="text-white font-semibold">{confirm.user.username}</span>'s role to <span className="font-semibold text-blue-400">{confirm.newRole}</span>?</>
              }
            </p>
            <div className="flex gap-3 justify-end">
              <button onClick={() => setConfirm(null)} disabled={busy}
                className="btn-ghost text-xs px-4 py-2 rounded-[10px]">
                Cancel
              </button>
              <button onClick={confirmAction} disabled={busy}
                className={`text-xs font-bold px-4 py-2 rounded-[10px] text-white transition-all disabled:opacity-40 ${
                  confirm.type === 'delete' ? 'btn-danger' : 'btn-primary'
                }`}>
                {busy ? 'Processing…' : confirm.type === 'delete' ? 'Delete' : 'Confirm'}
              </button>
            </div>
          </div>
        </div>
      )}
      {/* Create User Modal */}
      {createModal && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="relative rounded-2xl w-full max-w-sm p-6 space-y-4 shadow-[0_24px_80px_rgba(0,0,0,0.6)]"
            style={{ background: 'rgba(13,20,33,0.95)', border: '1px solid rgba(255,255,255,0.1)', backdropFilter: 'blur(20px)' }}>
            <div className="absolute top-0 left-8 right-8 h-px bg-gradient-to-r from-transparent via-blue-500/40 to-transparent" />
            <div className="flex items-center justify-between">
              <h3 className="text-white font-bold text-sm">Create New User</h3>
              <button onClick={() => setCreateModal(false)} className="text-slate-600 hover:text-slate-400 transition-colors"><X size={14} /></button>
            </div>
            {formError && <p className="text-red-300 text-xs bg-red-500/8 border border-red-500/20 rounded-xl px-3 py-2">{formError}</p>}
            <div className="space-y-3">
              {[
                { label: 'Username', key: 'username', type: 'text', placeholder: 'e.g. john.doe1' },
                { label: 'Email', key: 'email', type: 'email', placeholder: 'john.doe1@sentinelai.com' },
                { label: 'Password', key: 'password', type: 'password', placeholder: 'Min 8 chars, 1 upper, 1 digit, 1 special' },
              ].map(({ label, key, type, placeholder }) => (
                <div key={key}>
                  <label className="text-[10px] font-bold text-slate-600 uppercase tracking-widest mb-1.5 block">{label}</label>
                  <input type={type} value={createForm[key]}
                    onChange={e => setCreateForm(prev => ({ ...prev, [key]: e.target.value }))}
                    placeholder={placeholder}
                    className="ctrl-input w-full" />
                </div>
              ))}
              <div>
                <label className="text-[10px] font-bold text-slate-600 uppercase tracking-widest mb-1.5 block">Role</label>
                <div className="relative">
                  <select value={createForm.role} onChange={e => setCreateForm(prev => ({ ...prev, role: e.target.value }))}
                    className="ctrl-select w-full">
                    <option value="analyst">Analyst</option>
                    <option value="admin">Admin</option>
                  </select>
                </div>
              </div>
            </div>
            <div className="flex gap-3 pt-1">
              <button onClick={createUser} disabled={busy || !createForm.username || !createForm.email || !createForm.password}
                className="btn-primary flex-1 text-xs font-bold py-2 rounded-[10px] disabled:opacity-40">
                {busy ? 'Creating…' : 'Create'}
              </button>
              <button onClick={() => { setCreateModal(false); setFormError('') }}
                className="btn-ghost flex-1 text-xs py-2 rounded-[10px]">
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Reset Password Modal */}
      {resetModal && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="relative rounded-2xl w-full max-w-sm p-6 space-y-4 shadow-[0_24px_80px_rgba(0,0,0,0.6)]"
            style={{ background: 'rgba(13,20,33,0.95)', border: '1px solid rgba(255,255,255,0.1)', backdropFilter: 'blur(20px)' }}>
            <div className="absolute top-0 left-8 right-8 h-px bg-gradient-to-r from-transparent via-yellow-500/40 to-transparent" />
            <div className="flex items-center justify-between">
              <h3 className="text-white font-bold text-sm">Reset password for <span className="text-yellow-400">{resetModal.username}</span></h3>
              <button onClick={() => setResetModal(null)} className="text-slate-600 hover:text-slate-400 transition-colors"><X size={14} /></button>
            </div>
            {formError && <p className="text-red-300 text-xs bg-red-500/8 border border-red-500/20 rounded-xl px-3 py-2">{formError}</p>}
            <div>
              <label className="text-[10px] font-bold text-slate-600 uppercase tracking-widest mb-1.5 block">New Password</label>
              <input type="password" value={resetPw} onChange={e => setResetPw(e.target.value)}
                placeholder="Min 8 chars, 1 upper, 1 digit, 1 special"
                className="ctrl-input w-full" />
            </div>
            <div className="flex gap-3 pt-1">
              <button onClick={doResetPassword} disabled={busy || !resetPw.trim()}
                className="flex-1 text-xs font-bold py-2 rounded-[10px] text-white disabled:opacity-40 transition-all"
                style={{ background: 'linear-gradient(135deg,#a16207,#ca8a04)', boxShadow: '0 4px 14px rgba(202,138,4,0.25)' }}>
                {busy ? 'Saving…' : 'Reset Password'}
              </button>
              <button onClick={() => { setResetModal(null); setFormError('') }}
                className="btn-ghost flex-1 text-xs py-2 rounded-[10px]">
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
