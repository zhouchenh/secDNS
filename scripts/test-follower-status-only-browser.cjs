const assert=require('node:assert/strict');
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
(async()=>{
 const url=process.env.FOLLOWER_ONLY_URL,origin=new URL(url).origin;
 const browser=await chromium.launch({headless:true});
 try {
  const context=await browser.newContext(),page=await context.newPage(),requests=[],errors=[];
  page.on('pageerror',e=>errors.push(e.message));
  page.on('request',r=>{assert.equal(new URL(r.url()).origin,origin);requests.push({path:new URL(r.url()).pathname,method:r.method()});});
  await page.goto(url);assert(page.url().endsWith('/owned-static/ui/followers/'));
  await page.getByRole('heading',{name:'Replication status'}).waitFor();
  assert.equal(await page.getByRole('link',{name:'Record workspace'}).count(),0);
  assert.equal(await page.locator('script[src*="auth/"]').count(),0);
  assert.equal(requests.filter(r=>r.path.endsWith('/followers')).length,0);
  await page.locator('#token').fill('synthetic-admin');await page.getByRole('button',{name:'Connect',exact:true}).click();
  await page.getByText('Read-only local worker sample received.',{exact:true}).waitFor();
  assert((await page.locator('#rows').textContent()).includes('test-node'));
  assert((await page.locator('#rows').textContent()).includes('None accepted'));await page.evaluate(()=>new Promise(r=>requestAnimationFrame(()=>requestAnimationFrame(r))));if(process.env.WORKSPACE_SCREENSHOT_DIR)await page.screenshot({path:require('node:path').join(process.env.WORKSPACE_SCREENSHOT_DIR,'follower-status.png')});
  assert.equal(await page.locator('#token').inputValue(),'');
  await page.waitForTimeout(200);assert.equal(requests.filter(r=>r.path.endsWith('/followers')).length,1);
  await page.locator('#refresh').click();await page.getByText('Read-only local worker sample received.',{exact:true}).waitFor();
  assert.equal(requests.filter(r=>r.path.endsWith('/followers')).length,2);
  await page.locator('#disconnect').click();assert.equal(await page.locator('#rows').textContent(),'');
  await page.locator('#token').fill('wrong');await page.getByRole('button',{name:'Connect',exact:true}).click();
  await page.getByText('Sign in with an account or token that can view replication status.',{exact:true}).waitFor();
  assert.equal(await page.locator('#rows').textContent(),'');assert.equal(await page.locator('#token').evaluate(e=>e===document.activeElement),true,'rejected token returns focus for correction');assert.equal(await page.locator('#refresh').isDisabled(),true);assert.equal(await page.evaluate(()=>localStorage.length+sessionStorage.length),0);
  assert(requests.every(r=>r.method==='GET'&&!/\/(records|snapshot|auth)\b/.test(r.path)));
  await page.reload();assert.equal(await page.locator('#token').inputValue(),'');assert.equal(await page.locator('#rows').textContent(),'');
  assert.deepEqual(errors,[]);console.log('PASS actual status-only mux: landing, no editor/auth assets, manual GET/token, denial, disconnect, no persistence or mutation');
  await context.close();
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
