// Synthetic localhost only; uses an existing Playwright installation.
const assert = require('node:assert/strict');
const {chromium} = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
(async () => {
  const base = process.env.EDITOR_TEST_URL || 'http://127.0.0.1:19082/test-admin/ui/';
  assert.equal(new URL(base).hostname, '127.0.0.1');
  const api = new URL('../snapshot', base).href, token = 'local-browser-test-only', runID=require('node:crypto').randomUUID();
  const browser = await chromium.launch({headless:true});
  const context = await browser.newContext({viewport:{width:1440,height:1100}});
  const page = await context.newPage(), errors=[], posts=[], requests=[];
  page.on('pageerror',e=>errors.push(e.message));
  page.on('dialog',d=>d.accept());
  page.on('request',r=>{if(r.url()===api){requests.push(r.method());if(r.method()==='POST')posts.push(r.postData());}assert.ok(!r.url().includes(token));});
  const status=async text=>page.locator('#status').filter({hasText:text}).waitFor();
  const connect=async()=>{await page.locator('#token').fill(token);await page.locator('#connect').click();await page.waitForFunction(()=>document.querySelector('#connection').textContent.startsWith('Connected'));};
  const stage=async(name,value)=>{await page.locator('#new-record').click();await page.locator('#name').fill(name);await page.locator('#type').selectOption('TXT');await page.getByLabel('Record value',{exact:true}).fill(value);await page.locator('#ttl').fill('0');await page.locator('#stage').click();await status('staged locally');};
  const submit=async()=>{await page.locator('#review').click();await page.locator('#review-confirm').click();};
  const comparison=(name,type='TXT')=>page.locator('.comparison-record').filter({has:page.getByRole('heading',{name:name+' · '+type,exact:true})});
  const get=async()=>{const r=await context.request.get(api,{headers:{Authorization:'Bearer '+token}});assert.equal(r.status(),200);return r.json();};
  const replace=async(records,operation)=>{const s=await get();const r=await context.request.post(api,{headers:{Authorization:'Bearer '+token},data:{expected:{ruleset_id:s.ruleset_id,lineage_id:s.lineage_id,revision:s.revision},operation_id:runID+operation,records}});assert.equal(r.status(),200);return r.json();};
  try {
    await replace([], 'test-reset-'+require('node:crypto').randomUUID());
    await page.goto(base);assert.equal(posts.length,0);await connect();
    await stage('literal.invalid.','<img src=x onerror="alert(1)">');
    assert.equal(await page.locator('#comparison-rows img').count(),0);
    assert.deepEqual(await comparison('literal.invalid.').locator('.comparison-values code').allTextContents(),[JSON.stringify('<img src=x onerror="alert(1)">')]);
    await submit();await status('acknowledged and latest');
    assert.equal(await page.locator('tbody img').count(),0);
    await page.getByRole('button',{name:/^Edit /}).click();
    await page.getByLabel('Record value',{exact:true}).fill('');await page.locator('#add-value').click();await page.getByLabel('Record value',{exact:true}).nth(1).fill('same');await page.locator('#add-value').click();await page.getByLabel('Record value',{exact:true}).nth(2).fill('same');
    await page.locator('#expiry-mode').selectOption('absolute');await page.locator('#expiry').fill('2000-01-01T00:00:00.123456789Z');await page.locator('#stage').click();
    const literalDraft=comparison('literal.invalid.').locator('.comparison-version').nth(1);
    assert.deepEqual(await literalDraft.locator('.comparison-values code').allTextContents(),['""','"same"','"same"']);
    assert.deepEqual(await literalDraft.locator('dd').allTextContents(),['literal.invalid.','TXT','0','2000-01-01T00:00:00.123456789Z']);
    assert.equal(await comparison('literal.invalid.').getByText('Permanent (no expiration)',{exact:true}).count(),2);
    await submit();await status('acknowledged and latest');
    let s=await get();assert.deepEqual(s.records[0].values,['','same','same']);assert.equal(s.records[0].ttl_seconds,0);assert.equal(s.records[0].expires_at,'2000-01-01T00:00:00.123456789Z');assert.equal(await page.locator('.record-expired').count(),1);
    // A GET completing after an unfinished form edit must not clear it.
    let release, entered;const started=new Promise(r=>entered=r), held=new Promise(r=>release=r);
    await page.route(api,async route=>{if(route.request().method()==='GET'){const response=await route.fetch();entered();await held;await route.fulfill({response});}else await route.continue();});
    await page.locator('#refresh').click();await started;await page.locator('#name').fill('unfinished.invalid.');await page.locator('#type').selectOption('TXT');await page.getByLabel('Record value',{exact:true}).fill(' unfinished ');await page.locator('#ttl').fill('123');await page.locator('#expiry-mode').selectOption('absolute');await page.locator('#expiry').fill('2030-01-01T00:00:00.123456789Z');release();await status('Current snapshot fetched');
    assert.equal(await page.locator('#name').inputValue(),'unfinished.invalid.');assert.equal(await page.locator('#type').inputValue(),'TXT');assert.equal(await page.getByLabel('Record value',{exact:true}).inputValue(),' unfinished ');assert.equal(await page.locator('#ttl').inputValue(),'123');assert.equal(await page.locator('#expiry').inputValue(),'2030-01-01T00:00:00.123456789Z');assert.equal(await page.locator('#review').isDisabled(),true);assert.ok(!(await page.locator('#comparison').textContent()).includes('unfinished.invalid.'));assert.ok((await page.locator('#comparison-note').textContent()).includes('Unstaged form fields are not included'));await page.unroute(api);await page.locator('#new-record').click();
    // Authentication rejection clears the session without relying on a valid JSON body.
    await stage('auth-draft.invalid.','preserved');
    for(const [code,body] of [[401,'{"error":'],[403,'']]){
      const before=posts.length;
      await page.route(api,route=>route.request().method()==='GET'?route.fulfill({status:code,contentType:'application/json',body}):route.continue());
      await page.locator('#refresh').click();await page.locator('#login').waitFor({state:'visible'});
      assert.equal(await page.locator('#connection').textContent(),'Disconnected');assert.equal(await page.locator('#token').inputValue(),'');
      assert.equal(await page.locator('#rows').getByText('auth-draft.invalid.',{exact:true}).count(),1);
      await page.unroute(api);await connect();assert.equal(posts.length,before,'reauthentication never resends');
    }
    // Lost acknowledgement, followed by another writer, then exact idempotent retry.
    await stage('recovery.invalid.','pending');let firstBody, committed;
    await page.route(api,async route=>{if(route.request().method()==='POST'){firstBody=route.request().postData();const response=await route.fetch();assert.equal(response.status(),200);committed=await response.json();await route.abort('failed');}else await route.continue();});
    await submit();await status('outcome is uncertain');await page.unroute(api);
    const retained=await page.locator('#comparison').textContent(), requestCount=requests.length, warning=await page.locator('#status').textContent();
    await page.locator('#show-unchanged').focus();await page.keyboard.press('Space');assert.equal(await page.locator('#show-unchanged').isChecked(),true);
    assert.equal(await page.locator('#show-unchanged').evaluate(input=>input.matches(':focus-visible')),true);
    assert.equal(await page.locator('#comparison').textContent(),retained);assert.equal(await page.locator('#status').textContent(),warning);assert.equal(requests.length,requestCount);
    assert.ok((await page.locator('#comparison-note').textContent()).includes('pending operation is still uncertain'));
    await page.keyboard.press('Space');assert.equal(await page.locator('#show-unchanged').isChecked(),false);
    s=await get();const remote={name:'remote.invalid.',type:'A',values:['192.0.2.9'],ttl_seconds:60};await replace([...s.records,remote],'remote-after-lost-ack');
    await page.locator('#disconnect').click();assert.equal(await page.locator('#retry').isDisabled(),true);await connect();assert.equal(await page.locator('#review').isDisabled(),true);
    // Authentication failure during retry retains frozen identity and local work.
    for(const [code,body] of [[401,'{"error":"authentication rejected"}'],[403,'{"error":"authentication rejected"}'],[401,'{"error":'],[403,'']]){
      const before=posts.length;
      await page.route(api,route=>route.request().method()==='POST'?route.fulfill({status:code,contentType:'application/json',body}):route.continue());
      await page.locator('#retry').click();await page.locator('#login').waitFor({state:'visible'});
      assert.equal(await page.locator('#connection').textContent(),'Disconnected');assert.equal(await page.locator('#token').inputValue(),'');assert.equal(posts.at(-1),firstBody);
      await page.unroute(api);await connect();assert.equal(posts.length,before+1,'reauthentication never retries automatically');assert.equal(await page.locator('#review').isDisabled(),true);
    }
    await page.locator('#retry').click();await status('acknowledged and latest');
    assert.equal(posts.at(-1),firstBody);assert.equal(posts.at(-2),firstBody);
    assert.ok((await page.locator('#receipt').textContent()).includes('revision '+committed.revision));
    s=await get();assert.ok(s.records.some(r=>r.name==='remote.invalid.'));assert.ok((await page.locator('#current-version').textContent()).includes(s.revision));
    // Concurrent addition cannot be silently overwritten by rebasing a dirty draft.
    const wideTXT='  '+'x'.repeat(200)+'  ';await stage('local-draft.invalid.',wideTXT);s=await get();await replace([...s.records,{...remote,name:'remote-second.invalid.'}],'remote-before-conflict');
    await submit();await status('server changed');assert.equal(await page.locator('#rows').getByText('local-draft.invalid.',{exact:true}).count(),1);assert.equal(await page.locator('#review').isDisabled(),true);
    await page.locator('#refresh').click();await status('Current snapshot fetched');assert.equal(await page.locator('#rows').getByText('local-draft.invalid.',{exact:true}).count(),1);
    assert.deepEqual(await comparison('local-draft.invalid.').locator('.change-badge').allTextContents(),['Local: added','Observed server: unchanged']);
    assert.equal(await comparison('local-draft.invalid.').locator('.comparison-values code').textContent(),JSON.stringify(wideTXT));
    assert.deepEqual(await comparison('remote-second.invalid.','A').locator('.change-badge').allTextContents(),['Local: unchanged','Observed server: added']);
    assert.equal(await comparison('remote-second.invalid.','A').locator('.comparison-version').nth(1).getByText('Not present in this snapshot',{exact:true}).count(),1);
    assert.equal(await page.locator('#rows').getByText('remote-second.invalid.',{exact:true}).count(),0,'comparison cannot adopt the remote addition');
    const comparedJSON=await page.locator('#comparison').textContent(), comparedRequests=requests.length;
    await page.locator('#show-unchanged').check();assert.ok(await page.locator('.comparison-record').count()>2);await page.locator('#show-unchanged').uncheck();
    assert.equal(await page.locator('.comparison-record').count(),2);assert.equal(await page.locator('#comparison').textContent(),comparedJSON);assert.equal(requests.length,comparedRequests);
    if(process.env.EDITOR_SCREENSHOT)await page.screenshot({path:process.env.EDITOR_SCREENSHOT,fullPage:true});
    await page.setViewportSize({width:390,height:844});
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,'mobile page has no horizontal overflow');
    assert.equal(await comparison('local-draft.invalid.').locator('.comparison-versions').evaluate(element=>getComputedStyle(element).gridTemplateColumns.split(' ').length),1);
    await page.locator('.comparison-raw summary').focus();await page.keyboard.press('Enter');assert.equal(await page.locator('.comparison-raw').evaluate(element=>element.open),true);await page.keyboard.press('Enter');
    if(process.env.EDITOR_MOBILE_SCREENSHOT)await page.screenshot({path:process.env.EDITOR_MOBILE_SCREENSHOT,fullPage:true});
    await page.setViewportSize({width:1440,height:1100});
    await page.locator('#adopt').click();assert.equal(await page.locator('#rows').getByText('local-draft.invalid.',{exact:true}).count(),0);assert.equal(await page.locator('#rows').getByText('remote-second.invalid.',{exact:true}).count(),1);
    // Failed canonical reload after acknowledgement blocks a new proposal.
    await stage('reload.invalid.','retained');let posted=false;
    await page.route(api,async route=>{if(route.request().method()==='POST'){const response=await route.fetch();posted=true;await route.fulfill({response});}else if(posted)await route.fulfill({status:503,json:{error:'snapshot_unavailable'}});else await route.continue();});
    await submit();await status('Saved; current state could not be loaded');assert.equal(await page.locator('#review').isDisabled(),true);await page.unroute(api);await page.locator('#refresh').click();await status('Current snapshot fetched');
    // Explicit HTTP failures preserve complete draft and use distinct messages.
    for(const [code,http,text] of [['invalid_snapshot_request',400,'proposal is invalid'],['snapshot_too_large',413,'exceeds the size'],['operation_conflict',409,'operation ID conflicts'],['receipt_capacity',409,'ledger is full'],['revision_exhausted',409,'range is exhausted']]){
      await stage('errors.invalid.',code);await page.route(api,route=>route.request().method()==='POST'?route.fulfill({status:http,json:{error:code}}):route.continue());await submit();await status(text);assert.equal(await page.locator('#rows').getByText('errors.invalid.',{exact:true}).count(),1);await page.unroute(api);await page.locator('#refresh').click();await status('Current snapshot fetched');await page.locator('#adopt').click();
    }
    // 503 is uncertain; retries are byte-identical, and a later rejection requires reconciliation.
    await stage('unavailable.invalid.','draft');await page.route(api,route=>route.request().method()==='POST'?route.fulfill({status:503,json:{error:'snapshot_unavailable'}}):route.continue());await submit();await status('outcome is uncertain');const frozen=posts.at(-1);await page.locator('#retry').click();await status('outcome is uncertain');assert.equal(posts.at(-1),frozen);await page.unroute(api);await page.locator('#retry').click();await status('acknowledged and latest');
    // Delayed response.json() completion after disconnect cannot reconnect or replace state.
    await page.evaluate(()=>{const native=window.fetch;window.__restoreFetch=native;window.fetch=async(...args)=>{const response=await native(...args);if((args[1]?.method||'GET')==='GET'){const parse=response.json.bind(response);response.json=async()=>{const data=await parse();window.__bodyReady=true;await new Promise(resolve=>window.__releaseBody=resolve);return data;};}return response;};});
    await page.locator('#refresh').click();await page.waitForFunction(()=>window.__bodyReady);await page.locator('#disconnect').click();await page.evaluate(()=>{window.__releaseBody();window.fetch=window.__restoreFetch;});await page.waitForTimeout(60);assert.equal(await page.locator('#connection').textContent(),'Disconnected');await connect();
    // An earlier GET completing after a successful save cannot regress the current revision.
    let releaseOld, enteredOld, holdOne=true;
    const oldStarted=new Promise(r=>enteredOld=r), oldHeld=new Promise(r=>releaseOld=r);
    await page.route(api,async route=>{if(route.request().method()==='GET'&&holdOne){holdOne=false;const response=await route.fetch();enteredOld();await oldHeld;await route.fulfill({response});}else await route.continue();});
    await page.locator('#refresh').click();await oldStarted;await stage('after-get.invalid.','new');await submit();await status('acknowledged and latest');const newest=await page.locator('#current-version').textContent(), newestComparison=await page.locator('#comparison-revisions').textContent();releaseOld();await page.waitForTimeout(60);assert.equal(await page.locator('#current-version').textContent(),newest);assert.equal(await page.locator('#comparison-revisions').textContent(),newestComparison);await page.unroute(api);
    // An ignored earlier GET must not overwrite a later uncertain-operation warning.
    let releaseIgnored, enteredIgnored, holdIgnored=true;
    const ignoredStarted=new Promise(r=>enteredIgnored=r), ignoredHeld=new Promise(r=>releaseIgnored=r);
    await page.route(api,async route=>{if(route.request().method()==='POST'){await route.abort('failed');}else if(holdIgnored){holdIgnored=false;const response=await route.fetch();enteredIgnored();await ignoredHeld;await route.fulfill({response});}else await route.continue();});
    await page.locator('#refresh').click();await ignoredStarted;await stage('ignored-get.invalid.','preserved');await submit();await status('outcome is uncertain');releaseIgnored();await page.waitForTimeout(80);assert.ok((await page.locator('#status').textContent()).includes('outcome is uncertain'));await page.unroute(api);await page.locator('#retry').click();await status('acknowledged and latest');
    // A malformed success receipt is uncertain even though the real server committed.
    await stage('receipt.invalid.','test');let receiptBody;
    await page.route(api,async route=>{if(route.request().method()==='POST'){receiptBody=route.request().postData();const response=await route.fetch();assert.equal(response.status(),200);await route.fulfill({status:200,json:{operation_id:'wrong',revision:3}});}else await route.continue();});
    await page.locator('#review').click();const countBefore=posts.length;await page.locator('#review-confirm').evaluate(button=>{button.click();button.click();});await status('outcome is uncertain');assert.equal(posts.length,countBefore+1);await page.unroute(api);await page.locator('#retry').click();await status('acknowledged and latest');assert.equal(posts.at(-1),receiptBody);
    // Delete is staged and explicitly confirmed, then full replacement is reviewed.
    await page.locator('#rows tr').filter({hasText:'unavailable.invalid.'}).getByRole('button',{name:/^Delete /}).click();assert.equal(await page.locator('#rows tr').filter({hasText:'unavailable.invalid.'}).count(),0);await submit();await status('acknowledged and latest');
    assert.deepEqual(await page.evaluate(()=>({local:localStorage.length,session:sessionStorage.length,cookies:document.cookie})),{local:0,session:0,cookies:''});assert.equal(await page.locator('#token').inputValue(),'');assert.deepEqual(errors,[]);
    // Identity changes cannot be adopted merely by refreshing or changing revision.
    await stage('identity-draft.invalid.','preserve');await page.route(api,route=>route.request().method()==='POST'?route.fulfill({status:409,json:{error:'identity_conflict'}}):route.continue());await submit();await status('identity or lineage differs');assert.equal(await page.locator('#adopt').isDisabled(),true);assert.equal(await page.locator('#review').isDisabled(),true);await page.unroute(api);
    assert.ok((await page.locator('#comparison-note').textContent()).includes('Identity mismatch. Showing the last accepted snapshots'));
    // Synthetic response metadata confirms readable revisions never pass through Number.
    await page.route(api,async route=>{if(route.request().method()==='GET'){const response=await route.fetch(), data=await response.json();data.revision='9007199254740993';await route.fulfill({status:200,json:data});}else await route.continue();});
    await page.locator('#refresh').click();await status('Current snapshot fetched');assert.ok((await page.locator('#comparison-revisions').textContent()).includes('Observed server revision 9007199254740993'));assert.equal(await page.locator('#adopt').isDisabled(),true);await page.unroute(api);
    console.log('Versioned editor actual API and recovery browser tests passed.');
  } finally {await context.close();await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
