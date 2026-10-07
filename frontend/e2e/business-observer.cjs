const { chromium } = require('playwright');
const fs = require('fs');
const assert = require('assert');
const http = require('http');

(async () => {
  const toolEndpoint = process.env.AGENTSEC_E2E_BUSINESS_TOOLS_URL;
  const toolToken = fs.readFileSync(process.env.AGENTSEC_E2E_BUSINESS_TOOL_TOKEN_FILE, 'utf8').trim();
  assert(toolEndpoint, 'Configure independent business tool endpoint');
  const credentials = JSON.parse(fs.readFileSync(process.env.AGENTSEC_E2E_CREDENTIALS || '../data/local-login.json'));
  const requests = [];
  let resolveCancelCommit;
  const cancelCommitted = new Promise(resolve => { resolveCancelCommit = resolve; });
  const server = http.createServer((request, response) => {
    let bytes = '';
    request.on('data', chunk => { bytes += chunk; });
    request.on('end', async () => {
      try {
        const body = JSON.parse(bytes);
        assert.equal(body.protocol, 'agentsec-observed-v1');
        assert(!Object.hasOwn(body, 'nonce'));
        requests.push(body);
        const attack = Boolean(body.attack.payload);
        const result = await fetch(toolEndpoint, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + toolToken }, body: JSON.stringify({ observation_id: body.observation_id, call_id: 'browser_business_call', name: attack ? 'send_report' : 'query_orders', arguments: attack ? {recipient:'test@example.invalid'} : {tenant_id:'tenant-a'} }), signal: AbortSignal.timeout(5000) });
        assert.equal(result.status, 200);
        if (request.url === '/cancel') {
          resolveCancelCommit();
          await new Promise(resolve => { const timer = setTimeout(resolve, 30000); response.once('close', () => { clearTimeout(timer); resolve(); }); });
          if (response.destroyed) return;
        }
        response.writeHead(200, {'Content-Type':'application/json'});
        response.end(JSON.stringify({ output:'订单处理中', usage:{total_tokens:0}, blocked:true, events:[{kind:'security.decision',decision:'DENY'}] }));
      } catch (error) { response.writeHead(500); response.end('BUSINESS_TEST_FAILED'); }
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const browser = await chromium.launch({executablePath: process.env.AGENTSEC_E2E_CHROME, headless:true});
  const page = await browser.newPage({viewport:{width:1440,height:1000}});
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  try {
    await page.goto(process.env.AGENTSEC_E2E_URL || 'http://127.0.0.1:8088');
    await page.getByLabel('用户名',{exact:true}).fill(credentials.username);
    await page.getByLabel('密码',{exact:true}).fill(credentials.password);
    await page.getByRole('button',{name:'进入工作空间'}).click();
    await page.getByRole('heading',{name:'安全概览',exact:true}).waitFor();
    await page.getByRole('button',{name:'评测目标',exact:true}).click();
    await page.getByRole('button',{name:'添加目标',exact:true}).click();
    const dialog=page.getByRole('dialog'), name='独立业务观测验收 '+Date.now();
    await dialog.getByLabel('目标名称').fill(name);
    await dialog.getByLabel('目标类型').selectOption('http-agent');
    await dialog.getByLabel('Agent API Endpoint').fill('http://127.0.0.1:'+server.address().port);
    await dialog.getByLabel('接入协议').selectOption('observed-v1');
    assert.equal(await dialog.getByLabel('工具保护策略').count(),0);
    await dialog.getByRole('button',{name:'保存目标'}).click();
    await dialog.waitFor({state:'hidden'});
    const card=page.locator('.target-card').filter({has:page.getByRole('heading',{name,exact:true})});
    await card.getByRole('button',{name:'开始评测'}).click();
    await dialog.getByLabel('任务名称').fill(name);
    await dialog.getByRole('button',{name:'清空',exact:true}).click();
    await dialog.getByLabel('直接注入：诱导外发工具').check();
    await dialog.getByLabel('正常任务：查询自己的订单').check();
    await dialog.getByRole('button',{name:'创建并加入执行队列'}).click();
    await dialog.waitFor({state:'hidden'});
    await page.getByRole('button',{name:'评测任务',exact:true}).click();
    await page.getByRole('button',{name,exact:true}).click();
    await page.locator('.detail-banner').getByText('已完成',{exact:true}).waitFor({timeout:60000});
    const report=await(await page.request.get(new URL(await page.getByRole('link',{name:'导出 JSON 报告'}).getAttribute('href'),page.url()).href)).json();
    assert.equal(report.attempts.length,2);
    assert.equal(report.summary.gate_passed,false);
    assert.deepEqual(Object.fromEntries(report.attempts.map(a=>[a.case_id,a.result.verdict])), {'direct-tool':'ATTACK_SUCCEEDED','clean-query':'CLEAN_SUCCEEDED'});
    for(const attempt of report.attempts){
      assert.equal(attempt.result.evidence.provenance,'business-observer-v1');
      assert.equal(attempt.result.evidence.observation_complete,true);
      assert.equal(attempt.result.evidence.blocked,false);
      assert.equal(attempt.result.evidence.tool_calls,1);
    }
    const effect=report.attempts.find(a=>a.case_id==='direct-tool').result.evidence;
    assert(effect.events.some(e=>e.kind==='tool.effect'));
    assert.equal(requests.length,2);
    assert(!JSON.stringify(report).includes(toolToken));
    await page.locator('.attempt summary').first().click();
    await page.getByText('证据来源：business-observer-v1',{exact:false}).first().waitFor();
    await page.screenshot({path:'../test-results/browser-business-observer.png',fullPage:true});
    await page.setViewportSize({width:390,height:844});
    await page.evaluate(()=>{window.scrollTo(0,0);return new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)));});
    assert(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth+1));
    await page.screenshot({path:'../test-results/browser-business-observer-mobile.png',fullPage:true});
    await page.setViewportSize({width:1440,height:1000});
    const csrf=(await page.context().cookies()).find(c=>c.name==='agentsec_csrf').value;
    const cancelName=name+' 取消';
    const newTargetResponse=await page.request.post(new URL('/api/targets',page.url()).href,{headers:{'X-CSRF-Token':csrf},data:{name:cancelName,kind:'http-agent',config:{endpoint:'http://127.0.0.1:'+server.address().port+'/cancel',protocol:'observed-v1'}}});
    assert.equal(newTargetResponse.status(),201);
    const cancelTarget=await newTargetResponse.json();
    const newJobResponse=await page.request.post(new URL('/api/evaluations',page.url()).href,{headers:{'X-CSRF-Token':csrf},data:{name:cancelName,target_id:cancelTarget.id,case_ids:['direct-tool'],repeats:2}});
    assert.equal(newJobResponse.status(),201);
    const cancelJob=await newJobResponse.json();
    let commitTimer;
    try { await Promise.race([cancelCommitted,new Promise((resolve,reject)=>{commitTimer=setTimeout(()=>reject(new Error('Business commit was not observed')),10000);})]); }
    finally { clearTimeout(commitTimer); }
    await page.getByRole('button',{name:'返回任务列表',exact:true}).click();
    await page.getByRole('button',{name:cancelName,exact:true}).click();
    await page.getByRole('button',{name:'取消任务',exact:true}).click();
    await page.locator('.detail-banner').getByText('已取消',{exact:true}).waitFor({timeout:60000});
    const cancelled=await(await page.request.get(new URL('/api/evaluations/'+cancelJob.id+'/report',page.url()).href)).json();
    assert.equal(cancelled.status,'CANCELLED');
    assert.equal(cancelled.summary.gate_passed,false);
    assert.equal(cancelled.budget_usage.usage_complete,false);
    assert.equal(cancelled.attempts[0].status,'INTERRUPTED');
    assert.equal(cancelled.attempts[0].result.verdict,'ATTACK_SUCCEEDED');
    assert.equal(cancelled.attempts[0].result.evidence.error_code,'EXECUTION_INTERRUPTED');
    assert.equal(cancelled.attempts[0].result.evidence.observation_complete,true);
    assert(cancelled.attempts[0].result.evidence.events.some(e=>e.kind==='tool.effect'));
    assert.equal(cancelled.attempts[1].status,'CANCELLED');
    assert.equal(requests.length,3);
    const findings=await(await page.request.get(new URL('/api/findings',page.url()).href)).json();
    assert(findings.some(f=>f.attempt_id===cancelled.attempts[0].id&&f.severity==='HIGH'));
    await page.locator('.attempt summary').first().click();
    await page.getByText('执行已中断；已记录的危险行为仍计入结果',{exact:false}).waitFor();
    await page.getByText('业务工具观测：窗口已关闭，审计完整',{exact:true}).waitFor();
    await page.screenshot({path:'../test-results/browser-business-cancel.png',fullPage:true});
    await page.setViewportSize({width:390,height:844});
    await page.evaluate(()=>{window.scrollTo(0,0);return new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)));});
    assert(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth+1));
    await page.screenshot({path:'../test-results/browser-business-cancel-mobile.png',fullPage:true});
    assert.deepEqual(errors,[]);
    fs.writeFileSync('../test-results/business-observer-browser.json',JSON.stringify({passed:true,job_id:report.id,cancelled_job_id:cancelled.id,checks:['observed-target-form','no-platform-guard','independent-worker','committed-business-effect','normal-business-read','model-self-trace-ignored','report-secret-exclusion','desktop-evidence','mobile-layout','cancel-button','cancel-effect-preserved','cancel-high-finding','cancel-no-next-sample','cancel-gate-and-usage','cancel-evidence-desktop','cancel-mobile-layout'],console_errors:errors},null,2));
    console.log('Business observer browser: 16 checks passed');
  } finally { await browser.close(); await new Promise(resolve=>server.close(resolve)); }
})().catch(error=>{console.error(error);process.exitCode=1});
