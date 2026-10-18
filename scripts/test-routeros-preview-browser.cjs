// Synthetic localhost only; reuse an existing installed Playwright/Chromium.
const assert=require('node:assert/strict'), crypto=require('node:crypto');
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const fixture='/ip dns static\r\n'+
 'add name=duplicate.invalid type=A address=192.0.2.1 ttl=0 disabled=yes match-subdomain=no comment="<img src=x onerror=alert(1)>"\r\n'+
 'add name=duplicate.invalid address=192.0.2.2 comment="  retained spaces  "\r\n'+
 'add regexp="^host\\\\.invalid\\$" type=FWD forward-to=forward.invalid ttl=1h disabled=no match-subdomain=yes\r\n'+
 'add name=negative.invalid type=NXDOMAIN ttl=1m disabled=no match-subdomain=no\r\n';
const hash=bytes=>crypto.createHash('sha256').update(bytes).digest('hex');
(async()=>{
 const base=process.env.PREVIEW_TEST_URL||'http://127.0.0.1:19086/test-admin/ui/import-preview/';assert.equal(new URL(base).hostname,'127.0.0.1');
 const endpoint=new URL('../../import/routeros/preview',base).href, editorURL=new URL('../',base).href, snapshotURL=new URL('../snapshot',editorURL).href, token='local-browser-test-only';
 const browser=await chromium.launch({headless:true}), context=await browser.newContext({viewport:{width:1440,height:1100}}), page=await context.newPage(), errors=[], requests=[];
 context.on('page',p=>p.on('pageerror',e=>errors.push(e.message)));page.on('pageerror',e=>errors.push(e.message));
 page.on('request',r=>{requests.push({url:r.url(),method:r.method(),body:r.postDataBuffer()});assert.ok(!r.url().includes(token));assert.equal(new URL(r.url()).hostname,'127.0.0.1');});
 const status=async text=>page.locator('#status').filter({hasText:text}).waitFor(), preview=async()=>{await page.locator('#preview').click();await status('Complete preview loaded');};
 const source=async text=>{await page.locator('#mode').selectOption('paste');await page.locator('#source').fill(text);};
 const authorize=async()=>page.locator('#token').fill(token);
 const previewPosts=()=>requests.filter(r=>r.url===endpoint&&r.method==='POST');
 try{
  await page.goto(base);assert.equal(previewPosts().length,0);await authorize();await source(fixture);assert.equal(previewPosts().length,0);await preview();
  assert.equal(await page.locator('.entry').count(),4);assert.equal(await page.locator('#results img').count(),0);assert.ok((await page.locator('#entries').textContent()).includes('<img src=x onerror=alert(1)>'));
  assert.ok((await page.locator('#entries').textContent()).includes('disabled_entry_retained'));assert.ok((await page.locator('#entries').textContent()).includes('source defaults not established'));assert.ok((await page.locator('#entries').textContent()).includes('forward_semantics_not_compiled'));
  assert.deepEqual(await page.locator('.entry').evaluateAll(nodes=>nodes.map(n=>n.dataset.ordinal)),['1','2','3','4']);
  assert.ok((await page.locator('#provenance').textContent()).includes('submitted UTF-8'));
  // Original file bytes (including CRLF) are sent only on explicit submission.
  await page.locator('#mode').selectOption('file');const beforeFile=previewPosts().length, raw=Buffer.from(fixture);
  await page.locator('#file').setInputFiles({name:'<literal-name>.rsc',mimeType:'text/plain',buffer:raw});assert.equal(previewPosts().length,beforeFile);await preview();
  assert.deepEqual(previewPosts().at(-1).body,raw);assert.ok((await page.locator('#hash').textContent()).includes(hash(raw)));assert.ok((await page.locator('#provenance').textContent()).includes('<literal-name>.rsc'));
  // Check size before allocating the file; selecting or clicking cannot upload oversized data.
  await page.evaluate(()=>{window.__nativeArrayBuffer=File.prototype.arrayBuffer;window.__reads=0;File.prototype.arrayBuffer=function(){window.__reads++;return window.__nativeArrayBuffer.call(this);};});
  await page.locator('#file').setInputFiles({name:'oversized.rsc',mimeType:'application/octet-stream',buffer:Buffer.alloc((1<<20)+1)});const beforeLarge=previewPosts().length;
  await page.locator('#preview').click();await status('exceeds 1 MiB');assert.equal(previewPosts().length,beforeLarge);assert.equal(await page.evaluate(()=>window.__reads),0);
  for(const buffer of [Buffer.from([0xff]),Buffer.concat([Buffer.from([0xef,0xbb,0xbf]),raw])]){
   await page.locator('#file').setInputFiles({name:'invalid.rsc',mimeType:'application/octet-stream',buffer});await page.locator('#preview').click();await status('Complete input rejected');assert.equal(await page.locator('#results').isHidden(),true);assert.deepEqual(previewPosts().at(-1).body,buffer);
  }
  // A late old file read cannot send its body after another source completes.
  await page.evaluate(()=>{File.prototype.arrayBuffer=async function(){if(this.name==='slow.rsc'){await new Promise(r=>window.__releaseFile=r);}return window.__nativeArrayBuffer.call(this);};});
  await page.locator('#file').setInputFiles({name:'slow.rsc',mimeType:'text/plain',buffer:raw});await page.locator('#preview').click();await page.waitForFunction(()=>!!window.__releaseFile);
  const newer=Buffer.from('/ip dns static\nadd name=newer.invalid\n');await page.locator('#file').setInputFiles({name:'newer.rsc',mimeType:'text/plain',buffer:newer});await preview();const afterNewer=previewPosts().length;await page.evaluate(()=>window.__releaseFile());await page.waitForTimeout(80);assert.equal(previewPosts().length,afterNewer);assert.ok((await page.locator('#hash').textContent()).includes(hash(newer)));
  await page.evaluate(()=>{File.prototype.arrayBuffer=window.__nativeArrayBuffer;});
  // Parser rejection never exposes preceding valid entries as a partial result.
  await source('/ip dns static\nadd name=first.invalid\nadd unknown=never-reflect-this\n');await page.locator('#preview').click();await status('Complete input rejected');assert.equal(await page.locator('#results').isHidden(),true);assert.ok(!(await page.locator('#status').textContent()).includes('never-reflect-this'));
  await source(fixture);
  // HTTP redirects must fail rather than follow with source bytes.
  let sinkHits=0;await page.route('**/redirect-sink',route=>{sinkHits++;return route.fulfill({status:200,body:'unexpected'});});
  await page.route(endpoint,route=>route.fulfill({status:307,headers:{Location:new URL('/redirect-sink',base).href}}));await page.locator('#preview').click();await status('Preview failed');assert.equal(sinkHits,0);await page.unroute(endpoint);await page.unroute('**/redirect-sink');
  // Authentication status is authoritative even with a malformed JSON body.
  for(const code of [401,403]){
   await page.route(endpoint,route=>route.fulfill({status:code,contentType:'application/json',body:'{"error":'}));await page.locator('#preview').click();await status('Authentication rejected');assert.equal(await page.locator('#token').inputValue(),'');assert.equal(await page.locator('#authentication').textContent(),'Token not verified');assert.equal(await page.locator('#source').inputValue(),fixture.replaceAll('\r\n','\n'));
   await page.unroute(endpoint);const count=previewPosts().length;await authorize();assert.equal(previewPosts().length,count);await preview();
  }
  // An old401 resolving after a newly captured token cannot clear that session.
  await page.evaluate(()=>{window.__nativeFetch=window.fetch;let first=true;window.fetch=(...args)=>{if(first){first=false;return new Promise(r=>window.__releaseAuth=()=>r(new Response('{',{status:401})));}return window.__nativeFetch(...args);};});
  await page.locator('#preview').click();await page.waitForFunction(()=>!!window.__releaseAuth);await authorize();await preview();await page.evaluate(()=>{window.__releaseAuth();window.fetch=window.__nativeFetch;});await page.waitForTimeout(80);assert.equal(await page.locator('#authentication').textContent(),'Last preview authenticated');await preview();
  // Delayed body completion after disconnect is ignored, including status updates.
  await page.evaluate(()=>{window.__nativeFetch=window.fetch;window.fetch=async(...args)=>{const r=await window.__nativeFetch(...args),body=await r.text();return new Response(new ReadableStream({start(c){window.__releaseBody=()=>{c.enqueue(new TextEncoder().encode(body));c.close();};}}),{status:r.status});};});
  await page.locator('#preview').click();await page.waitForFunction(()=>!!window.__releaseBody);await page.locator('#disconnect').click();await page.evaluate(()=>{window.__releaseBody();window.fetch=window.__nativeFetch;});await page.waitForTimeout(80);assert.equal(await page.locator('#results').isHidden(),true);assert.equal(await page.locator('#authentication').textContent(),'Token not verified');assert.ok((await page.locator('#status').textContent()).startsWith('Disconnected'));
  await authorize();
  // A body from an earlier source cannot replace a cleared or newer preview.
  for(const action of ['clear','source']){
   await page.evaluate(()=>{window.__nativeFetch=window.fetch;let first=true;window.fetch=async(...args)=>{const r=await window.__nativeFetch(...args);if(!first)return r;first=false;const body=await r.text();return new Response(new ReadableStream({start(c){window.__releaseStaleBody=()=>{c.enqueue(new TextEncoder().encode(body));c.close();};}}),{status:r.status});};});
   await source(fixture);await page.locator('#preview').click();await page.waitForFunction(()=>!!window.__releaseStaleBody);
   if(action==='clear'){await page.locator('#clear').click();}else{await source('/ip dns static\nadd name=body-newer.invalid\n');await preview();}
   const retainedStatus=await page.locator('#status').textContent(),retainedHash=await page.locator('#hash').textContent();await page.evaluate(()=>{window.__releaseStaleBody();delete window.__releaseStaleBody;window.fetch=window.__nativeFetch;});await page.waitForTimeout(80);
   assert.equal(await page.locator('#status').textContent(),retainedStatus);assert.equal(await page.locator('#hash').textContent(),retainedHash);if(action==='clear')assert.equal(await page.locator('#results').isHidden(),true);
  }
  await source(fixture);
  // Malformed success cannot enable an apply path or render a partial response.
  await page.route(endpoint,route=>route.fulfill({status:200,json:{source_sha256:'a'.repeat(64),entries:[],can_apply:true}}));await page.locator('#preview').click();await status('Invalid preview response');assert.equal(await page.locator('#results').isHidden(),true);await page.unroute(endpoint);
  const many='/ip dns static\n'+Array.from({length:55},(_,i)=>'add name=n'+i+'.invalid').join('\n');await source(many);await preview();assert.equal(await page.locator('.entry').count(),50);await page.locator('#next').focus();await page.keyboard.press('Enter');assert.equal(await page.locator('.entry').count(),5);assert.equal(await page.locator('.entry').first().getAttribute('data-ordinal'),'51');assert.equal(await page.locator('#next').isDisabled(),true);await page.locator('#previous').click();assert.equal(await page.locator('.entry').first().getAttribute('data-ordinal'),'1');
  await source(fixture.replace('retained spaces','x'.repeat(200)));await preview();
  if(process.env.PREVIEW_SCREENSHOT)await page.screenshot({path:process.env.PREVIEW_SCREENSHOT,fullPage:true});await page.setViewportSize({width:390,height:844});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,'mobile page must not overflow');await page.locator('#preview').focus();await page.keyboard.press('Tab');await page.keyboard.press('Shift+Tab');assert.equal(await page.locator('#preview').evaluate(e=>e.matches(':focus-visible')),true,'keyboard navigation shows focus');
  if(process.env.PREVIEW_MOBILE_SCREENSHOT)await page.screenshot({path:process.env.PREVIEW_MOBILE_SCREENSHOT,fullPage:true});
  assert.equal(requests.filter(r=>r.method!=='GET'&&r.url!==endpoint).length,0,'preview page never writes records/snapshots');
  // Opening the separate page preserves both an unfinished form and a pending exact retry.
  const editor=await context.newPage();editor.on('dialog',d=>d.accept());await editor.goto(editorURL);await editor.locator('#token').fill(token);await editor.locator('#connect').click();await editor.waitForFunction(()=>document.querySelector('#connection').textContent.startsWith('Connected'));
  await editor.locator('#name').fill('unfinished.invalid.');const oldURL=editor.url();
  let popupPromise=context.waitForEvent('page');await editor.getByRole('link',{name:'RouterOS import preview',exact:true}).click();let popup=await popupPromise;await popup.waitForLoadState();assert.equal(await popup.evaluate(()=>window.opener===null),true);assert.equal(editor.url(),oldURL);assert.equal(await editor.locator('#name').inputValue(),'unfinished.invalid.');assert.equal(await editor.locator('#review').isDisabled(),true);await popup.close();
  await editor.locator('#type').selectOption('TXT');await editor.getByLabel('Record value',{exact:true}).fill('draft');await editor.locator('#stage').click();const editorBodies=[];
  await editor.route(snapshotURL,route=>{if(route.request().method()==='POST'){editorBodies.push(route.request().postData());return route.fulfill({status:503,json:{error:'snapshot_unavailable'}});}return route.continue();});
  await editor.locator('#review').click();await editor.locator('#review-confirm').click();await editor.locator('#status').filter({hasText:'outcome is uncertain'}).waitFor();
  popupPromise=context.waitForEvent('page');await editor.getByRole('link',{name:'RouterOS import preview',exact:true}).click();popup=await popupPromise;await popup.waitForLoadState();await popup.locator('#token').fill(token);await popup.locator('#source').fill(fixture);await popup.locator('#preview').click();await popup.locator('#status').filter({hasText:'Complete preview loaded'}).waitFor();assert.equal(editorBodies.length,1);assert.ok((await editor.locator('#status').textContent()).includes('outcome is uncertain'));await popup.close();await editor.locator('#retry').click();await editor.locator('#status').filter({hasText:'outcome is uncertain'}).waitFor();assert.equal(editorBodies.length,2);assert.equal(editorBodies[0],editorBodies[1]);await editor.close();
  assert.deepEqual(await page.evaluate(()=>({local:localStorage.length,session:sessionStorage.length,cookie:document.cookie})),{local:0,session:0,cookie:''});assert.deepEqual(errors,[]);
  console.log('RouterOS preview actual localhost browser tests passed.');
 }finally{await context.close();await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
