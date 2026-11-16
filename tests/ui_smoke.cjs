// Run in the Playwright Docker image sharing the disconnected app container network.
// All API responses are mocked: this test never contacts a VPN gateway.
const {chromium}=require('/app/node_modules/playwright');
const assert=require('node:assert/strict');
(async()=>{
 const browser=await chromium.launch({headless:true,channel:'chromium',args:['--no-sandbox']});
 const page=await browser.newPage({viewport:{width:1360,height:1000}});
 const errors=[];page.on('pageerror',e=>errors.push(e.message));
 let state='disconnected', submitted, profile={}, gatewayReachable=true;
 const snapshot=()=>({state,message:state==='connected'?'Tunnel connected. Proxy traffic is restricted to the VPN.':'Ready to connect.',connected_at:state==='connected'?new Date().toISOString():null,interface:state==='connected'?'ppp0':null,proxies:{socks:'127.0.0.1:1080',http:'127.0.0.1:8888'}});
 await page.route('**/api/**',async route=>{
  const req=route.request(), path=new URL(req.url()).pathname;
  if(path==='/api/test-gateway'){
   const data=req.postDataJSON();assert.deepEqual(Object.keys(data).sort(),['host','port']);
   await route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({reachable:gatewayReachable,message:gatewayReachable?'Gateway TCP port is reachable. VPN login and TLS were not tested.':'Gateway TCP port could not be reached.'})});return;
  }
  if(path==='/api/profile'){
   if(req.method()==='POST'){
    profile=req.postDataJSON();assert.equal(Object.hasOwn(profile,'password'),false);assert.equal(Object.hasOwn(profile,'otp'),false);
   }
   await route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(profile)});return;
  }
  if(path==='/api/connect'){submitted=req.postDataJSON();assert.equal(req.headers()['x-fortiproxy-request'],'1');state='connecting';}
  if(path==='/api/disconnect')state='disconnected';
  await route.fulfill({status:path==='/api/connect'?202:200,contentType:'application/json',body:JSON.stringify(snapshot())});
 });
 await page.goto('http://127.0.0.1:8787');
 await page.locator('#status-badge[data-state="disconnected"]').waitFor();
 await page.screenshot({path:'/artifacts/desktop.png',fullPage:true});
 await page.getByLabel('Remote gateway',{exact:true}).fill('vpn.example.test');
 await page.getByLabel('Username',{exact:true}).fill('test-user');
 await page.getByRole('button',{name:'Test gateway',exact:true}).click();
 await page.locator('#gateway-test-message[data-result="success"]').waitFor();
 gatewayReachable=false;
 await page.getByRole('button',{name:'Test gateway',exact:true}).click();
 await page.locator('#gateway-test-message[data-result="error"]').waitFor();
 await page.getByLabel('Password',{exact:true}).fill('not-a-real-password');
 await page.getByText('Additional settings',{exact:true}).click();
 await page.getByLabel('One-time code',{exact:false}).fill('654321');
 await page.getByLabel('Realm',{exact:false}).fill('staff');
 await page.getByLabel('Trusted certificate fingerprint',{exact:false}).fill('a'.repeat(64));
 await page.getByLabel('Connection name',{exact:false}).fill('Office test');
 await page.getByLabel('Port',{exact:true}).fill('10443');
 await page.waitForFunction(()=>document.querySelector('#profile-message').textContent.startsWith('Settings saved'));
 await page.reload();
 await page.locator('#status-badge[data-state="disconnected"]').waitFor();
 assert.equal(await page.locator('#host').inputValue(),'vpn.example.test');
 assert.equal(await page.locator('#username').inputValue(),'test-user');
 assert.equal(await page.locator('#name').inputValue(),'Office test');
 assert.equal(await page.locator('#realm').inputValue(),'staff');
 assert.equal(await page.locator('#trusted_cert').inputValue(),'a'.repeat(64));
 assert.equal(await page.locator('#password').inputValue(),'');
 assert.equal(await page.locator('#otp').inputValue(),'');
 await page.getByLabel('Password',{exact:true}).fill('not-a-real-password');
 await page.getByRole('button',{name:'Show password',exact:true}).click();
 assert.equal(await page.locator('#password').getAttribute('type'),'text');
 await page.getByRole('button',{name:'Hide password',exact:true}).click();
 await page.getByRole('button',{name:'Connect VPN',exact:true}).click();
 await page.locator('#status-badge[data-state="connecting"]').waitFor();
 assert.equal(submitted.host,'vpn.example.test');assert.equal(submitted.port,10443);
 assert.equal(await page.locator('#password').inputValue(),'');
 assert.equal(await page.evaluate(()=>localStorage.length),0);
 state='connected';
 await page.locator('#status-badge[data-state="connected"]').waitFor();
 assert.equal(await page.locator('#proxy-availability').textContent(),'Ready to use');
 state='disconnecting';
 await page.locator('#status-badge[data-state="disconnecting"]').waitFor();
 assert.equal(await page.locator('#connect-button').isDisabled(),true);
 assert.equal(await page.locator('#disconnect-button').isDisabled(),true);
 state='connected';
 await page.locator('#status-badge[data-state="connected"]').waitFor();
 await page.getByRole('button',{name:'Disconnect VPN',exact:true}).click();
 await page.locator('#status-badge[data-state="disconnected"]').waitFor();
 state='error';
 await page.locator('#status-badge[data-state="error"]').waitFor();
 assert.equal(await page.getByRole('button',{name:'Connect VPN',exact:true}).isEnabled(),true);
 state='disconnected';
 await page.locator('#status-badge[data-state="disconnected"]').waitFor();
 await page.setViewportSize({width:390,height:844});
 await page.screenshot({path:'/artifacts/mobile.png',fullPage:true});
 assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth),true);
 await page.getByText('Additional settings',{exact:true}).click();
 await page.getByLabel('Trusted certificate fingerprint',{exact:false}).fill('a'.repeat(64));
 assert.equal(await page.locator('#trusted_cert').evaluate(el=>el.checkValidity()),true);
 assert.deepEqual(errors,[]);
 console.log('PASS: saved settings restored after reload; secret fields excluded; desktop/mobile layout, connect/disconnect/error states, password clearing, request contract, no localStorage secrets, optional certificate input; API was mocked, no gateway contacted.');
 await browser.close();
})().catch(e=>{console.error(e);process.exit(1)});
