"""Popup UI with mocked extension APIs."""
from playwright.sync_api import sync_playwright
from pg_harness import EXT, OUT

OUT.mkdir(exist_ok=True)
html = (EXT / 'popup.html').read_text(encoding='utf-8').replace('<link rel="stylesheet" href="popup.css">', '') \
    .replace('<script src="rules.js"></script>', '').replace('<script src="popup.js"></script>', '')
mock = r'''(() => {
 window.__store={whitelist:[],scanHistory:[],protectionEnabled:true};window.__sent=[];window.__copied='';window.__mailto='';
 HTMLAnchorElement.prototype.click=function(){window.__mailto=this.href;};
 Object.defineProperty(navigator,'clipboard',{configurable:true,value:{writeText:async x=>{window.__copied=x;}}});
 const u='https://fast.com/';
 const url={ok:true,domain:'fast.com',url:u,score:0,signals:[],checked:['transport','domain','identity','structure','wording']};
 const page={ok:true,checked:['credentials','submission','pressure'],signals:[],hasPassword:true,destinations:[
   {host:'auth.example.com',protocol:'https:',relation:'external',password:true},
   {host:'Page script',protocol:'script:',relation:'script',password:true}]};
 window.__lastResponse={ok:true,urlResult:url,pageResult:page,score:0,full:true,enabled:true,trusted:false};
 window.chrome={
  runtime:{lastError:null,sendMessage:(m,cb)=>{window.__sent.push(m.type);
   if(m.type==='FULL_SCAN')setTimeout(()=>cb({...window.__lastResponse,enabled:window.__store.protectionEnabled!==false,trusted:window.__store.whitelist.includes('fast.com')}),200);
   else cb({ok:true});}},
  tabs:{query:(q,cb)=>cb([{id:5,url:u}]),sendMessage:(id,m,cb)=>{window.__sent.push(m.type);if(cb)cb({ok:true});},create:async o=>{window.__opened=o.url;}},
  scripting:{executeScript:async()=>{}},
  storage:{local:{get:async keys=>{
   const out={};for(const k of (Array.isArray(keys)?keys:[keys]))out[k]=window.__store[k];return out;
  },set:async v=>Object.assign(window.__store,v)}}
 };
})();'''
with sync_playwright() as p:
    b = p.chromium.launch(args=['--disable-dev-shm-usage'])
    page = b.new_page(viewport={'width': 640, 'height': 536}, device_scale_factor=1)
    errors = []; page.on('pageerror', lambda exc: errors.append(str(exc)))
    page.set_content(html); page.evaluate(mock)
    page.add_style_tag(content=(EXT / 'popup.css').read_text(encoding='utf-8'))
    page.add_script_tag(content=(EXT / 'rules.js').read_text(encoding='utf-8'))
    page.add_script_tag(content=(EXT / 'popup.js').read_text(encoding='utf-8'))
    assert page.locator('#verTitle').inner_text() == 'SCANNING…'
    assert 'SCANNING' in page.locator('#scanTag').inner_text()
    page.wait_for_function("document.getElementById('coverageNum').textContent==='8'", timeout=5000)
    assert page.locator('#verTitle').inner_text() == 'LOW RISK'
    assert page.locator('#wlLabel').inner_text() == 'On'
    assert page.locator('#confNum').inner_text() == 'Broader scan'
    page.locator('#btnRescan').click()
    assert page.locator('#verTitle').inner_text() == 'SCANNING…', 'Rescan needs visible progress'
    page.wait_for_function("document.getElementById('coverageNum').textContent==='8'")
    assert page.evaluate('document.body.scrollWidth <= 640')
    assert page.evaluate('document.querySelector(".main").scrollWidth <= document.querySelector(".main").clientWidth')
    page.screenshot(path=str(OUT / 'overview.png'))
    page.locator('#wlToggle').uncheck(force=True)
    page.wait_for_function("window.__store.protectionEnabled===false")
    assert page.locator('#wlLabel').inner_text() == 'Off'
    assert page.evaluate('window.__store.whitelist.length===0'), 'Toggling global protection must NOT trust the website'
    page.locator('#wlToggle').check(force=True)
    page.wait_for_function('window.__store.protectionEnabled===true')
    page.locator('#btnQuickTrust').click()
    page.locator('#dialogConfirm').click()
    page.wait_for_function("window.__store.whitelist.includes('fast.com')")
    assert page.locator('#wlLabel').inner_text() == 'On', 'Trusting site must NOT change global switch'
    assert page.locator('#btnQuickTrust').inner_text() == 'Remove trust'
    page.locator('#btnQuickTrust').click()
    page.wait_for_function('window.__store.whitelist.length===0')
    page.wait_for_function("document.getElementById('coverageNum').textContent==='8'")
    page.locator('[data-view="analysis"]').click()
    assert page.locator('#destinationList .destination-row').count() == 2
    dest = page.locator('#destinationList').inner_text()
    assert 'auth.example.com' in dest and "Handled by the page's JavaScript" in dest
    assert page.locator('#explainGrid .done').count() == 8
    page.screenshot(path=str(OUT / 'analysis.png'))
    page.locator('#btnExport').click()
    page.wait_for_function('window.__copied.includes("Coverage: 8/8") && window.__copied.includes("PhishGuard 3.5.1")')
    page.locator('#btnReport').click()
    assert page.locator('#cMsg').input_value().startswith('Possible false positive')
    page.locator('#cMsg').fill(''); page.locator('#btnContact').click()
    assert 'Please describe' in page.locator('#contactError').inner_text()
    page.locator('#cMsg').fill('Test message'); page.locator('#cEmail').fill('tester@example.org'); page.locator('#btnContact').click()
    assert page.evaluate('window.__mailto.startsWith("mailto:its.yugi.itadori@gmail.com?")')
    # URL scanner now runs the shared rules locally in the popup.
    page.locator('[data-view="scanner"]').click()
    page.locator('#manualUrl').fill('https://sbi.bank.in/'); page.locator('#btnScan').click()
    assert 'LOW URL RISK' in page.locator('#manualOut').inner_text()
    page.locator('#manualUrl').fill('https://paypa1-secure.xyz/login'); page.locator('#btnScan').click()
    assert 'HIGH RISK' in page.locator('#manualOut').inner_text()
    page.locator('[data-view="settings"]').click()
    assert page.get_by_text('Why these permissions?').count() == 1
    assert page.locator('.permission-grid>div').count() == 3, 'tabs permission removed'
    page.locator('#trustHostInput').fill('https://accounts.example.com/path')
    page.locator('#btnAddTrust').click(); page.locator('#dialogConfirm').click()
    page.wait_for_function("window.__store.whitelist.includes('accounts.example.com')")
    assert page.evaluate('window.__store.protectionEnabled') is True
    page.locator('#trustHostInput').fill('*.example.com'); page.locator('#btnAddTrust').click()
    assert len(page.evaluate('window.__store.whitelist')) == 1
    page.screenshot(path=str(OUT / 'settings.png'))
    page.locator('#btnClearWl').click(); page.locator('#dialogConfirm').click()
    page.wait_for_function('window.__store.whitelist.length===0')
    page.locator('#btnUpdates').click(); assert page.locator('#dialogTitle').inner_text() == 'Update PhishGuard'
    page.locator('#dialogClose').click()
    page.locator('[data-view="history"]').click()
    page.wait_for_function('window.__store.scanHistory.length>0')
    page.locator('#btnClearHist').click(); page.locator('#dialogConfirm').click()
    page.wait_for_function('window.__store.scanHistory.length===0')
    # Explicit partial evidence when page inspection is unavailable.
    page.locator('[data-view="overview"]').click()
    page.evaluate('window.__lastResponse={...window.__lastResponse,pageResult:null,full:false}')
    page.locator('#btnRescan').click()
    assert page.locator('#verTitle').inner_text() == 'SCANNING…'
    page.wait_for_function("document.getElementById('coverageNum').textContent==='5'")
    assert page.locator('#confNum').inner_text() == 'URL-only'
    assert page.locator('#verTitle').inner_text() == 'PARTIAL SCAN'
    # Score 55 is HIGH RISK in the popup, matching the badge and the page banner.
    page.evaluate("window.__lastResponse={...window.__lastResponse,urlResult:{...window.__lastResponse.urlResult,signals:[{id:'x',title:'x',desc:'x',severity:'High',pts:55,source:'url'}]},pageResult:{ok:true,checked:['credentials','submission','pressure'],signals:[],hasPassword:false,destinations:[]},full:true}")
    page.locator('#btnRescan').click()
    page.wait_for_function("document.getElementById('scoreNum').textContent==='55'")
    assert page.locator('#verTitle').inner_text() == 'HIGH RISK'
    assert not errors, errors
    print('PASS popup: visible scanning, 8/8, no overflow, global switch independent of trust, exact-host trust, '
          'script-handled destination label, report 3.5.1, contact, local URL scanner, 3 permissions, history, dialogs, 55 = HIGH')
    b.close()
