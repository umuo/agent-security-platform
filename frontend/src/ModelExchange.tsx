import type { Target } from './api';

type Message = { role?: string; content?: unknown; tool_calls?: unknown[]; tool_call_id?: string };
const roles: Record<string, string> = { system: '系统约束', user: '用户 / 外部资料', assistant: '目标回复', tool: '工具返回' };
function display(value: unknown): string {
  if (typeof value === 'string') return value;
  if (value == null) return '无文本';
  if (Array.isArray(value)) return value.map(display).join('\n');
  if (typeof value === 'object') return Object.entries(value).map(([key, item]) => `${key}：${display(item)}`).join('\n');
  return String(value);
}
function ToolCalls({ calls }: { calls: unknown }) {
  if (!Array.isArray(calls) || !calls.length) return null;
  return <ul className="exchange-calls">{calls.map((item: any, index) => {
    const name = item?.function?.name ?? item?.name ?? '未记录名称';
    let args = item?.function?.arguments ?? item?.arguments;
    if (typeof args === 'string') { try { args = JSON.parse(args); } catch { /* 非 JSON 参数保留可见文本。 */ } }
    return <li key={index}><strong>请求工具：{display(name)}</strong><p className="trace-text">{display(args)}</p></li>;
  })}</ul>;
}
function Messages({ messages }: { messages: unknown }) {
  if (!Array.isArray(messages)) return null;
  return <div>{messages.map((message: Message, index) => <article className="exchange-message" key={index}>
    <strong>{roles[String(message.role)] ?? '消息'}{message.tool_call_id ? ` · ${message.tool_call_id}` : ''}</strong>
    <p className="trace-text">{display(message.content)}</p><ToolCalls calls={message.tool_calls}/>
  </article>)}</div>;
}
export function ModelExchange({ transcript, target }: { transcript: any; target: Target }) {
  if (!transcript || !Array.isArray(transcript.exchanges)) return <p className="small muted">{['fixture', 'langchain4j'].includes(target.kind) ? '此目标不执行平台可见的真实模型往返，查看工具事件和 SDK 审计即可。' : '这条历史结果没有逐轮往返记录；重新评测后才能查看，旧记录无法补回。'}</p>;
  return <section className="model-exchanges" aria-label="逐轮请求与响应"><h4>逐轮请求与响应</h4>
    <p className="small muted">记录的是平台与目标接口的往返；HTTP Agent 内部的模型调用仍由接入方管理。目标的工具请求与平台实际执行证据分开展示。内容可能截断，不能还原模型内部思考。</p>
    {transcript.limited && <p className="notice">记录达到大小或轮数上限，部分内容省略；不影响原有执行判定。</p>}
    {transcript.exchanges.map((entry: any, index: number) => <details className="exchange-round" key={index} open={index === 0}>
      <summary>第 {entry.round ?? index + 1} 轮 · {({requesting:'请求中',returned:'接口已返回',failed:'请求失败',interrupted:'请求中断'} as Record<string,string>)[entry.status] ?? '状态未知'}{typeof entry.duration_ms === 'number' ? ` · ${entry.duration_ms} ms` : ''}</summary>
      <h5>发送给目标</h5>{entry.request?.omitted ? <p>{display(entry.request.reason)}</p> : <>
        <Messages messages={entry.request?.messages}/>
        {entry.request?.user_message != null && <p className="trace-text">合法任务：{display(entry.request.user_message)}</p>}
        {entry.request?.attack != null && <p className="trace-text">注入内容：{display(entry.request.attack)}</p>}
        {entry.request?.setup_turns != null && <p className="trace-text">前置对话配置：{display(entry.request.setup_turns)}</p>}
        {Array.isArray(entry.request?.tools) && <details><summary>发送的工具定义（含描述）</summary>{entry.request.tools.map((tool: any, i: number) => <p className="trace-text" key={i}>{display(tool.function ?? tool)}</p>)}</details>}
      </>}
      <h5>目标返回</h5>{entry.response ? entry.response.omitted ? <p>{display(entry.response.reason)}</p> : <>
        <p className="trace-text">{display(entry.response.message?.content ?? entry.response.output)}</p>
        <ToolCalls calls={entry.response.message?.tool_calls ?? entry.response.tool_calls}/>
        {entry.response.usage?.total_tokens != null && <p className="small muted">本轮声明用量：{display(entry.response.usage.total_tokens)} token</p>}
      </> : <p className="muted">没有取得响应，不能视为拒绝或防护成功。</p>}
      {entry.tool_results && <><h5>平台返回的工具结果</h5>{Array.isArray(entry.tool_results) ? entry.tool_results.map((tool: any, i: number) => <article className="exchange-message" key={i}><strong>{display(tool.name)} · {display(tool.call_id)}</strong><p className="trace-text">{display(tool.content)}</p></article>) : <p>{display(entry.tool_results.reason)}</p>}</>}
      {entry.tool_results_limited && <p className="notice">本轮工具结果条数超过记录上限，部分省略。</p>}
    </details>)}
  </section>;
}
