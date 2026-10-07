import { useEffect, useState } from 'react';
import { api, post, labels, type Job } from './api';

type Account = { id: string; username: string; role: string; disabled: boolean };

export function AccountManagement({ onChanged }: { onChanged: () => void }) {
  const [users, setUsers] = useState<Account[]>([]), [edit, setEdit] = useState<Account | null>(null);
  const [error, setError] = useState(''), [busy, setBusy] = useState(false);
  const reload = async () => setUsers(await api<Account[]>('/users'));
  useEffect(() => { void reload().catch(x => setError(x.message)); }, []);
  async function save(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault(); if (!edit) return;
    const fields = new FormData(event.currentTarget);
    setBusy(true); setError('');
    try {
      const password = String(fields.get('password') || '');
      await api('/users/' + edit.id, { method: 'PATCH', body: JSON.stringify({
        role: fields.get('role'), disabled: fields.get('disabled') === 'on',
        ...(password ? { new_password: password } : {}),
      }) });
      setEdit(null); onChanged(); await reload();
    } catch (x) { setError((x as Error).message); } finally { setBusy(false); }
  }
  return <section className="panel settings-panel"><div className="panel-head"><h2>账号与权限</h2><button className="secondary" onClick={() => void reload().catch(x => setError(x.message))}>刷新账号</button></div>
    <p className="muted">禁用、改权限或重置密码会撤销该账号全部会话。平台始终保留至少一个可用管理员。</p>
    {error && <p role="alert" className="error">{error}</p>}
    <div className="table-scroll"><table><thead><tr><th>用户名</th><th>权限</th><th>状态</th><th>管理</th></tr></thead>
      <tbody>{users.map(row => <tr key={row.id}><td>{row.username}</td><td>{row.role}</td><td>{row.disabled ? '已禁用' : '可用'}</td>
        <td><button className="secondary" onClick={() => { setEdit(row); setError(''); }}>编辑账号</button></td></tr>)}</tbody></table></div>
    {edit && <form key={edit.id} className="account-edit" onSubmit={save}><h3>编辑 {edit.username}</h3>
      <div className="form-grid"><label>账号权限<select name="role" defaultValue={edit.role}><option value="admin">管理员</option><option value="operator">操作员</option><option value="viewer">查看者</option></select></label>
      <label>重置密码<input name="password" type="password" autoComplete="new-password" minLength={12} maxLength={256} placeholder="留空则保留原密码"/></label></div>
      <label className="checkbox"><input name="disabled" type="checkbox" defaultChecked={edit.disabled}/>禁用此账号</label>
      <div className="head-actions"><button className="primary" disabled={busy}>保存账号变更</button><button type="button" className="secondary" onClick={() => setEdit(null)}>取消编辑</button></div>
    </form>}
  </section>;
}

export function PasswordSettings() {
  const [busy, setBusy] = useState(false), [error, setError] = useState('');
  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault(); const fields = new FormData(event.currentTarget);
    setBusy(true); setError('');
    try {
      await post('/auth/change-password', { current_password: fields.get('current'), new_password: fields.get('new') });
      window.location.reload();
    } catch (x) { setError((x as Error).message); } finally { setBusy(false); }
  }
  return <section className="panel settings-panel"><h2>修改我的密码</h2><p className="muted">修改成功后，所有设备的会话失效，请重新登录。</p>
    <form onSubmit={submit}><div className="form-grid"><label>当前密码<input name="current" type="password" autoComplete="current-password" required maxLength={256}/></label>
    <label>新密码<input name="new" type="password" autoComplete="new-password" required minLength={12} maxLength={256}/></label></div>
    {error && <p role="alert" className="error">{error}</p>}<button className="primary" disabled={busy}>修改密码并重新登录</button></form></section>;
}

type Comparison = { comparable: boolean; warnings: string[]; regressions: number; improvements: number; interpretation: string;
  rows: { case_id: string; case_revision: string; name: string; change: string; baseline: { counts: Record<string, number> } | null; candidate: { counts: Record<string, number> } | null }[] };
const changes: Record<string, string> = { IMPROVED: '改善', REGRESSED: '退化', UNCHANGED: '无变化', CHANGED: '结果变化', UNRESOLVED: '含未知结果', INCOMPARABLE: '不可比较' };
const counts = (group: { counts: Record<string, number> } | null) => group ? Object.entries(group.counts).map(([key, value]) => `${labels[key] ?? key} ${value}`).join('；') : '未运行';

export function ComparisonPanel({ candidate, jobs }: { candidate: Job; jobs: Job[] }) {
  const [baseline, setBaseline] = useState(''), [result, setResult] = useState<Comparison | null>(null);
  const [error, setError] = useState(''), [busy, setBusy] = useState(false);
  const choices = jobs.filter(job => job.id !== candidate.id && job.target.asset_id === candidate.target.asset_id);
  async function compare() {
    setBusy(true); setError('');
    try { setResult(await api<Comparison>(`/comparisons?baseline_id=${encodeURIComponent(baseline)}&candidate_id=${encodeURIComponent(candidate.id)}`)); }
    catch (x) { setError((x as Error).message); } finally { setBusy(false); }
  }
  return <section className="panel settings-panel"><h2>与历史版本比较</h2><p className="muted">比较同一资产、同一用例修订及重复次数。未知结果单列；判定规则、执行引擎或证据模式不同不计为改善／退化，不同预算会标记为不完全可比。</p>
    <div className="head-actions"><label>基线评测<select value={baseline} onChange={e => { setBaseline(e.target.value); setResult(null); }}><option value="">选择历史评测</option>
      {choices.map(job => <option key={job.id} value={job.id}>{job.name} · {job.target.revision.slice(0, 10)} · {labels[job.status]}</option>)}</select></label>
      <button className="secondary" onClick={() => void compare()} disabled={!baseline || busy}>{busy ? '比较中…' : '比较结果'}</button></div>
    {!choices.length && <p className="small muted">同一资产尚无其他评测。通过目标“新修订”创建修复版本后运行评测。</p>}
    {error && <p role="alert" className="error">{error}</p>}
    {result && <><p>{result.comparable ? '样本可比' : '存在不可比或未知项'} · 改善 {result.improvements} 项 · 退化 {result.regressions} 项</p>
      {result.warnings.map(w => <p className="notice" key={w}>{w}</p>)}
      <div className="table-scroll"><table><thead><tr><th>场景</th><th>基线</th><th>当前</th><th>变化</th></tr></thead><tbody>{result.rows.map(row => <tr key={row.case_id + row.case_revision}>
        <td>{row.name}<small className="mono">{row.case_revision.slice(0, 12)}</small></td><td>{counts(row.baseline)}</td><td>{counts(row.candidate)}</td><td>{changes[row.change]}</td></tr>)}</tbody></table></div>
      <p className="small muted">{result.interpretation}</p></>}
  </section>;
}
