'use strict';
const assert=require('node:assert/strict');const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
(async()=>{const url=process.env.NODE_QA_URL;assert.equal(new URL(url).hostname,'127.0.0.1');const b=await chromium.launch({headless:true});const c=await b.newContext({ignoreHTTPSErrors:true,viewport:{width:1440,height:900}});const p=await c.newPage();const errors=[];p.on('pageerror',e=>errors.push(e.message));try{
 await c.addCookies([{name:'__Host-secdns_session',value:process.env.NODE_QA_COOKIE,url,secure:true,httpOnly:true,sameSite:'Strict'}]);
 await p.goto(url+'/admin/ui/nodes/');await p.waitForFunction(()=>window.secDNSAgent?.kind==='human');await p.getByText('All nodes checked.',{exact:false}).waitFor();assert.equal(await p.locator('.node-card').count(),3);
 await p.getByRole('link',{name:'DNS health',exact:true}).click();await p.getByText('All nodes checked.',{exact:false}).waitFor();assert.equal(await p.locator('.node-table').count(),3);assert.ok((await p.locator('main').innerText()).includes('Passing'));
 await p.getByRole('link',{name:'Routing',exact:true}).click();await p.getByText('All nodes checked.',{exact:false}).waitFor();assert.equal(await p.locator('.node-table').count(),6);
 if(process.env.NODE_QA_REAL_EXECUTABLE){assert.equal(await p.locator('.node-card').count(),3);assert.equal(await p.locator('.node-error').count(),0);if(process.env.NODE_QA_SCREENSHOT)await p.screenshot({path:process.env.NODE_QA_SCREENSHOT,fullPage:true});console.log('Real candidate backend read-only Routing browser PASS');return;} 
 await p.getByRole('button',{name:'Drain node',exact:true}).first().click();await p.getByRole('button',{name:'Cancel',exact:true}).click();assert.equal(await p.locator('dialog').isVisible(),false);assert.equal(await p.getByRole('button',{name:'Drain node',exact:true}).count(),3);
 await p.getByRole('button',{name:'Drain node',exact:true}).first().click();await p.locator('#apply-maintenance').click();await p.getByText('Verified: amd103 announcements withdrawn.',{exact:true}).waitFor();
 await p.getByRole('button',{name:'Resume announcements',exact:true}).click();await p.locator('#apply-maintenance').click();await p.getByText('Verified: amd103 announcements resumed.',{exact:true}).waitFor();
 await p.route('**/admin/nodes/cix106',r=>r.fulfill({status:503,contentType:'application/json',body:'{"error":"unavailable"}'}));await p.getByRole('button',{name:'Refresh all',exact:true}).click();await p.getByText('Some nodes could not be refreshed.',{exact:false}).waitFor();const card=p.locator('.node-card').filter({hasText:'CIX ARM64'});assert.ok((await card.innerText()).includes('Unknown (stale)'));assert.equal(await card.getByRole('button',{name:'Drain node'}).isDisabled(),true);
 await p.setViewportSize({width:390,height:844});assert.equal(await p.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);assert.deepEqual(errors,[]);console.log('Nodes/health/routing human-session browser: navigation, drain cancel/confirm, resume readback, stale isolation, mobile PASS');
 }finally{await c.close();await b.close();}})().catch(e=>{console.error(e.stack);process.exitCode=1});


