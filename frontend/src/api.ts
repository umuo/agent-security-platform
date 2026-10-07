export type Remediation = { version: string; basis: string; actions: string[]; acceptance: string; scope: string };
export type User = { id?: string; username: string; role: string };
export type Target = { id: string; asset_id: string; name: string; kind: string; config: Record<string, any>; revision: string; has_secret: boolean };
export type Case = { id: string; name: string; category: string; surface: string; spec: Record<string, any>; revision: string; builtin: boolean };
export type Attempt = { id: string; case_id: string; case_snapshot: Case; remediation?: Remediation | null; repeat: number; status: string; result?: { verdict: string; evidence: Record<string, any> } };
export type Job = { id: string; name: string; target: Target; status: string; created_at: number; finished_at?: number; error_code?: string; budget: Record<string, number>; budget_usage: {tokens: number; turns: number; tool_calls: number; usage_complete: boolean}; summary: { planned: number; counts: Record<string, number>; attack_success_rate: number | null; false_positive_rate: number | null; clean_completion_rate: number | null; unsafe_completion_rate: number | null; gate_passed: boolean }; attempts?: Attempt[] };
export type Finding = { remediation?: Remediation | null; id: string; title: string; severity: string; status: string; note: string; attempt_id: string; target_id: string; created_at: number };

export async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  const csrf = document.cookie.split('; ').find(x => x.startsWith('agentsec_csrf='))?.split('=').slice(1).join('=') ?? '';
  let response: Response;
  try {
    response = await fetch('/api' + path, { ...options, credentials: 'same-origin', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': decodeURIComponent(csrf), ...options.headers } });
  } catch (cause) {
    if ((cause as Error).name === 'AbortError') throw cause;
    throw Object.assign(new Error('网络连接失败，请检查网络后重试'), {status: 0});
  }
  if (!response.ok) {
    const data = await response.json().catch(() => ({}));
    const error = new Error(typeof data.detail === 'string' ? data.detail : response.status === 422 ? '输入格式不正确，请检查表单' : '请求失败') as Error & { status: number };
    error.status = response.status;
    throw error;
  }
  try { return await response.json(); } catch (cause) {
    if ((cause as Error).name === 'AbortError') throw cause;
    throw Object.assign(new Error('服务返回数据格式异常，请稍后重试'), {status: 502});
  }
}
export const post = <T,>(path: string, body: unknown, headers?: Record<string, string>) => api<T>(path, { method: 'POST', body: JSON.stringify(body), headers });
export const labels: Record<string, string> = { QUEUED: '等待执行', RUNNING: '执行中', COMPLETED: '已完成', CANCELLED: '已取消', FAILED: '执行失败', PENDING: '待执行', INTERRUPTED: '已中断', ATTACK_SUCCEEDED: '攻击成功', ATTACK_PREVENTED: '攻击被阻止', CLEAN_SUCCEEDED: '正常任务完成', FALSE_POSITIVE: '正常任务被误拦', TASK_FAILED: '任务未完成', UNSAFE_COMPLETION: '正常任务出现危险行为', INCONCLUSIVE: '证据不足', ERROR: '执行故障', UNSUPPORTED: '目标不支持', OPEN: '待确认', CONFIRMED: '已确认', FIX_PROPOSED: '修复中', RETESTING: '复测中', VERIFIED: '复测通过', CLOSED: '已关闭', ACCEPTED_RISK: '接受风险' };
export const categories: Record<string, string> = { 'prompt-injection': '提示词注入', 'prompt-attack': '提示词攻击', jailbreak: '越狱攻击', 'indirect-injection': '间接注入', 'data-leakage': '数据泄漏', 'memory-poisoning': '记忆污染', 'tool-poisoning': '工具污染', authorization: '权限越界', 'multi-turn': '多轮攻击', clean: '正常任务', 'sdk-regression': 'SDK 回归' };
export const surfaces: Record<string, string> = { user_message: '用户消息', rag_document: 'RAG 文档', tool_response: '工具返回', memory: '记忆', tool_description: '工具描述' };
