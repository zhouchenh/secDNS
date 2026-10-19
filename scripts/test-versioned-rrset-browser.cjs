'use strict';
// Opt-in synthetic loopback stores, launched by the Go integration fixture.
const assert=require('node:assert/strict');
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
(async()=>{
 const root=process.env.RRSET_BROWSER_URL;assert.equal(new URL(root).hostname,'127.0.0.1');
 const browser=await chromium.launch({headless:true});const context=await browser.newContext();const page=await context.newPage();const posts=[],errors=[];
 page.on('pageerror',e=>errors.push(e.message));page.on('dialog',d=>d.accept());page.on('request',r=>{assert.equal(new URL(r.url()).origin,root);if(r.method()==='POST')posts.push({url:r.url(),body:r.postData()});});
 const status=async text=>page.locator('#status').filter({hasText:text}).waitFor();
 const connect=async path=>{await page.goto(root+path+'/ui/');await page.locator('#token').fill('local-browser-test-only');await page.locator('#connect').click();await page.waitForFunction(()=>document.querySelector('#connection').textContent.startsWith('Records loaded'));};
 const stage=async name=>{await page.locator('#new-record').click();await page.locator('#name').fill(name);await page.locator('#type').selectOption('TXT');await page.getByLabel('Record value',{exact:true}).fill('same');await page.locator('#ttl').fill('0');await page.locator('#stage').click();await status('staged locally');};
 const review=async title=>{await page.locator('#review').click();assert.equal(await page.locator('#review-title').textContent(),title);};
 try{
  await connect('/old');await stage('old.invalid.');await review('Apply record changes?');await page.locator('#review-confirm').click();await status('acknowledged and latest');assert.equal(posts.at(-1).url,root+'/old/snapshot');assert.ok(JSON.parse(posts.at(-1).body).records);
  await connect('/new');await stage('new.invalid.');await review('Apply one record change?');assert.match(await page.locator('#review-scope').textContent(),/Other records remain unchanged/);
  let lost=true;await page.route(root+'/new/snapshot/rrset',async route=>{if(lost){lost=false;const r=await route.fetch();assert.equal(r.status(),200);await route.abort('failed');}else await route.continue();});
  await page.locator('#review-confirm').click();await status('Could not confirm whether the change was saved');const original=posts.at(-1);assert.equal(JSON.parse(original.body).action,'upsert');assert.equal(JSON.parse(original.body).record.ttl_seconds,0);
  // A capability refresh cannot retarget an uncertain frozen operation.
  await page.route(root+'/new/snapshot',async route=>{const r=await route.fetch();const headers={...r.headers()};delete headers['secdns-rrset-mutations'];await route.fulfill({response:r,headers});});
  await page.locator('#refresh').click();await status('Current snapshot fetched');await page.locator('#retry').click();await status('acknowledged and latest');assert.deepEqual(posts.at(-1),original);await page.unroute(root+'/new/snapshot');await page.unroute(root+'/new/snapshot/rrset');
  await page.locator('#refresh').click();await status('Current snapshot fetched');await stage('two.invalid.');await stage('three.invalid.');await review('Apply record changes?');await page.locator('#review-confirm').click();await status('acknowledged and latest');assert.equal(posts.at(-1).url,root+'/new/snapshot');
  await page.locator('#rows tr').filter({hasText:'new.invalid.'}).getByRole('button',{name:/^Delete /}).click();await review('Apply one record change?');await page.locator('#review-confirm').click();await status('acknowledged and latest');assert.equal(JSON.parse(posts.at(-1).body).action,'delete');
  await stage('refused.invalid.');const count=posts.length;await page.route(root+'/new/snapshot/rrset',route=>route.fulfill({status:409,json:{error:'rrset_schema_required'}}));await review('Apply one record change?');await page.locator('#review-confirm').click();await status('no longer supports targeted edits');assert.equal(posts.length,count+1);assert.equal(await page.locator('#rows').getByText('refused.invalid.',{exact:true}).count(),1);assert.equal(await page.locator('#retry').isVisible(),false);assert.deepEqual(errors,[]);
  console.log('PASS schema3 replacement, schema4 targeted/multiple/delete, immutable uncertain retry and refusal without fallback');
 }finally{await context.close();await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
