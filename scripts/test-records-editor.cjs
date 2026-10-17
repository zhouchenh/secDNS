// Run against an isolated test server with ui:true and synthetic data only.
// PLAYWRIGHT_MODULE may name an existing Playwright installation; no dependency is downloaded.
const assert = require('node:assert/strict');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');

(async () => {
  const base = process.env.EDITOR_TEST_URL || 'http://127.0.0.1:19080/test-admin/ui/';
  assert.equal(new URL(base).hostname, '127.0.0.1', 'Local test server required');
  const browser = await chromium.launch({headless:true});
  const context = await browser.newContext({viewport:{width:1280,height:1000}});
  const page = await context.newPage();
  const requests = [], errors = [];
  page.on('request', r => requests.push(r));
  page.on('pageerror', e => errors.push(e.message));
  const token = 'local-browser-test-only';
  const api = new URL('../records', base).href;
  const waitStatus = async text => { await page.locator('#status').filter({hasText:text}).waitFor(); };
  const connect = async () => { await page.locator('#token').fill(token); await page.getByRole('button',{name:'Connect',exact:true}).click(); await waitStatus('Connected.'); };
  const create = async (name,type,value) => {
    await page.locator('#name').fill(name); await page.locator('#type').selectOption(type);
    await page.getByLabel('Record value',{exact:true}).fill(value);
    await page.getByRole('button',{name:'Save record',exact:true}).click(); await waitStatus('Saved.');
  };
  try {
    await page.goto(base);
    assert.equal(requests.filter(r=>r.url()===api).length,0,'no automatic API fetch');
    await connect(); assert.equal(await page.locator('#token').inputValue(),'');
    await create('editor-test.invalid.','TXT','<img src=x onerror="alert(1)">');
    assert.equal(await page.locator('.record-value').textContent(),'<img src=x onerror="alert(1)">');
    assert.equal(await page.locator('tbody img').count(),0);
    await page.getByRole('button',{name:'Edit',exact:true}).click();
    await page.getByLabel('Record value',{exact:true}).fill('');
    await page.locator('#expiry-mode').selectOption('absolute');
    const exact = '2099-01-01T00:00:00.123456789Z'; await page.locator('#expiry').fill(exact);
    await page.locator('#save').click(); await waitStatus('Saved.');
    await page.getByRole('button',{name:'Edit',exact:true}).click();
    assert.equal(await page.locator('#expiry-mode').inputValue(),'keep');
    assert.ok((await page.locator('#expiry-help').textContent()).includes(exact));
    await page.locator('#ttl').fill('321');
    let release; const gate = new Promise(resolve=>release=resolve); let captured;
    await page.route(api, async route => {
      if(route.request().method()==='POST') { captured=route.request().postDataJSON(); await gate; }
      await route.continue();
    });
    await page.locator('#save').click();
    await page.waitForFunction(()=>document.querySelector('#save').disabled);
    assert.equal(await page.locator('#ttl').isDisabled(),true,'in-flight draft is locked');
    assert.equal(await page.getByLabel('Record value',{exact:true}).isDisabled(),true);
    release(); await waitStatus('Saved.'); await page.unroute(api);
    assert.equal(captured.expires_at,exact); assert.deepEqual(captured.values,['']);
    assert.equal(captured.ttl_seconds,321);
    await page.getByRole('button',{name:'Edit',exact:true}).click();
    await page.locator('#expiry-mode').selectOption('permanent');
    await page.locator('#save').click(); await waitStatus('Saved.');
    const data = await context.request.get(api,{headers:{Authorization:'Bearer '+token}});
    const record = (await data.json()).records[0]; assert.equal(record.expires_at,undefined);
    await page.locator('#filter').fill('does-not-exist'); assert.equal(await page.locator('#rows tr').count(),0);
    await page.locator('#filter').fill('');
    await page.getByRole('button',{name:'Edit',exact:true}).click();
    for (const code of [400,409,503]) {
      await page.getByLabel('Record value',{exact:true}).fill('preserved-'+code);
      await page.route(api,route=>route.request().method()==='POST'?route.fulfill({status:code,contentType:'application/json',body:'{"error":"<script>bad</script>"}'}):route.continue());
      await page.locator('#save').click(); await page.locator('#status.error').waitFor();
      assert.equal(await page.getByLabel('Record value',{exact:true}).inputValue(),'preserved-'+code);
      assert.equal((await page.locator('#status').textContent()).includes('<script>'),false);
      await page.unroute(api);
    }
    // Save succeeds but list refresh fails: do not invite a duplicate mutation.
    await page.route(api, route=>route.request().method()==='GET'?route.fulfill({status:503,body:'{}'}):route.continue());
    await page.locator('#save').click(); await waitStatus('Saved, but'); assert.equal(await page.locator('#save').isDisabled(),true);
    await page.unroute(api); await page.locator('#refresh').click(); await waitStatus('Records refreshed.');
    const deletesBefore=requests.filter(r=>r.method()==='DELETE').length;
    await page.getByRole('button',{name:'Delete',exact:true}).click(); await page.locator('#delete-cancel').click();
    assert.equal(requests.filter(r=>r.method()==='DELETE').length,deletesBefore);
    await page.getByRole('button',{name:'Edit',exact:true}).click();
    await page.getByRole('button',{name:'Delete',exact:true}).click();
    let releaseDelete; const deleteGate=new Promise(resolve=>releaseDelete=resolve);
    await page.route(api+'/**',async route=>{await deleteGate; await route.continue();});
    await page.locator('#delete-confirm').click(); assert.equal(await page.locator('#delete-cancel').isDisabled(),true);
    await page.keyboard.press('Escape'); assert.equal(await page.locator('#delete-dialog').isVisible(),true);
    releaseDelete(); await waitStatus('Deleted.'); await page.unroute(api+'/**');
    assert.equal(await page.locator('#name').inputValue(),''); assert.equal(await page.locator('#name').isDisabled(),false);
    await create('visual-test.invalid.','A','192.0.2.10');
    if(process.env.EDITOR_SCREENSHOT) await page.screenshot({path:process.env.EDITOR_SCREENSHOT,fullPage:true});
    await page.setViewportSize({width:390,height:844});
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth <= innerWidth),true,'no narrow viewport overflow');
    if(process.env.EDITOR_SCREENSHOT) await page.screenshot({path:process.env.EDITOR_SCREENSHOT.replace(/\.png$/, '-mobile.png'),fullPage:true});
    await page.setViewportSize({width:1280,height:1000});
    assert.deepEqual(await page.evaluate(()=>({local:localStorage.length,session:sessionStorage.length,cookies:document.cookie})),{local:0,session:0,cookies:''});
    for (const r of requests) { assert.equal(new URL(r.url()).origin,new URL(base).origin); assert.equal(r.url().includes(token),false); }
    await page.locator('#disconnect').click(); assert.equal(await page.locator('#rows tr').count(),0);
    assert.equal(await page.locator('#token').inputValue(),''); assert.equal(await page.locator('#name').inputValue(),'');
    for(const code of [401,403]) {
      await page.route(api,route=>route.fulfill({status:code,body:'{}'}));
      await page.locator('#token').fill(token); await page.getByRole('button',{name:'Connect',exact:true}).click();
      await page.locator('#status.error').waitFor(); assert.equal(await page.locator('#workspace').isVisible(),false);
      assert.equal(await page.locator('#token').inputValue(),''); await page.unroute(api);
    }
    await connect();
    // An old GET must not repopulate the view after disconnect.
    let releaseGet; const getGate=new Promise(resolve=>releaseGet=resolve);
    await page.route(api,async route=>{await getGate; await route.fulfill({status:200,contentType:'application/json',body:'{"records":[{"name":"stale.invalid.","type":"A","ttl_seconds":60,"values":["192.0.2.1"]}]}'});});
    await page.locator('#refresh').click(); await page.locator('#disconnect').click(); releaseGet();
    await page.waitForTimeout(50); assert.equal(await page.locator('#rows tr').count(),0); assert.equal(await page.locator('#workspace').isVisible(),false);
    await page.unroute(api);
    // Redirects are refused, so the Authorization header cannot follow another endpoint.
    await page.route(api,route=>route.fulfill({status:302,headers:{location:'/unapproved'}}));
    await page.locator('#token').fill(token); await page.getByRole('button',{name:'Connect',exact:true}).click(); await page.locator('#status.error').waitFor();
    assert.equal(requests.some(r=>r.url().endsWith('/unapproved')),false); await page.unroute(api);
    assert.deepEqual(errors,[]);
    console.log('PASS: real browser CRUD, exact expiry, empty TXT, literal HTML, errors, delayed mutations, cancel, token storage and disconnect');
  } finally { await context.close(); await browser.close(); }
})().catch(error=>{console.error(error);process.exitCode=1;});
