const VOLC_ENDPOINT = 'https://visual.volcengineapi.com';
const VOLC_HOST = 'visual.volcengineapi.com';
const REGION = 'cn-north-1';
const SERVICE = 'cv';
const ACTION = 'OCRNormal';
const VERSION = '2020-08-26';

function corsHeaders(request, env) {
  const origin = request.headers.get('Origin') || '*';
  const allowed = String(env.ALLOWED_ORIGIN || '*').trim();
  const value = allowed === '*' || allowed === origin ? origin : allowed;
  return {
    'Access-Control-Allow-Origin': value || '*',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin',
  };
}

function json(data, status, request, env) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {'Content-Type':'application/json; charset=utf-8', ...corsHeaders(request, env)},
  });
}

const te = new TextEncoder();
function hex(bytes) { return [...new Uint8Array(bytes)].map(b => b.toString(16).padStart(2,'0')).join(''); }
async function sha256Bytes(value) { return crypto.subtle.digest('SHA-256', typeof value === 'string' ? te.encode(value) : value); }
async function sha256Hex(value) { return hex(await sha256Bytes(value)); }
async function hmac(key, data) {
  const rawKey = typeof key === 'string' ? te.encode(key) : key;
  const k = await crypto.subtle.importKey('raw', rawKey, {name:'HMAC', hash:'SHA-256'}, false, ['sign']);
  return crypto.subtle.sign('HMAC', k, typeof data === 'string' ? te.encode(data) : data);
}

function volcDate(date = new Date()) {
  const iso = date.toISOString().replace(/[:-]|\.\d{3}/g, '');
  return iso.slice(0, 15) + 'Z';
}

async function buildVolcHeaders(body, accessKey, secretKey) {
  const xDate = volcDate();
  const shortDate = xDate.slice(0,8);
  const contentType = 'application/x-www-form-urlencoded';
  const payloadHash = await sha256Hex(body);
  const query = `Action=${ACTION}&Version=${VERSION}`;
  const signedHeaders = 'content-type;host;x-content-sha256;x-date';
  const canonicalHeaders =
    `content-type:${contentType}\n` +
    `host:${VOLC_HOST}\n` +
    `x-content-sha256:${payloadHash}\n` +
    `x-date:${xDate}\n`;
  const canonicalRequest = ['POST','/',query,canonicalHeaders,signedHeaders,payloadHash].join('\n');
  const credentialScope = `${shortDate}/${REGION}/${SERVICE}/request`;
  const stringToSign = ['HMAC-SHA256',xDate,credentialScope,await sha256Hex(canonicalRequest)].join('\n');
  const kDate = await hmac(secretKey, shortDate);
  const kRegion = await hmac(kDate, REGION);
  const kService = await hmac(kRegion, SERVICE);
  const kSigning = await hmac(kService, 'request');
  const signature = hex(await hmac(kSigning, stringToSign));
  const authorization = `HMAC-SHA256 Credential=${accessKey}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
  return {
    'Content-Type': contentType,
    'X-Date': xDate,
    'X-Content-Sha256': payloadHash,
    'Authorization': authorization,
  };
}

function stripDataUrl(dataUrl) {
  const s = String(dataUrl || '').trim();
  const comma = s.indexOf(',');
  return comma >= 0 ? s.slice(comma + 1) : s;
}

function normText(s) {
  return String(s || '')
    .replace(/[‐‑‒–—﹣－~～]/g,'-')
    .replace(/[：]/g,':')
    .replace(/\s+/g,' ')
    .trim();
}
function normAlias(s) {
  return normText(s).toLowerCase().replace(/\.mp3\b/ig,'').replace(/白珺珩/g,'').replace(/[\s·•,，。.!！?？:：;；“”"'《》【】()[\]{}<>〈〉_\-]/g,'');
}
function cjkCount(s) { return (String(s||'').match(/[\u3400-\u9fff]/g) || []).length; }
function levenshtein(a,b) {
  a=[...a]; b=[...b]; const m=a.length,n=b.length;
  if(!m)return n;if(!n)return m;
  const prev=Array.from({length:n+1},(_,i)=>i),cur=new Array(n+1);
  for(let i=1;i<=m;i++){
    cur[0]=i;
    for(let j=1;j<=n;j++)cur[j]=Math.min(cur[j-1]+1,prev[j]+1,prev[j-1]+(a[i-1]===b[j-1]?0:1));
    for(let j=0;j<=n;j++)prev[j]=cur[j];
  }
  return prev[n];
}
function matchKnownAlias(raw, books) {
  const nr = normAlias(raw); if(!nr)return '';
  let best='',bestScore=0;
  for(const b of Array.isArray(books)?books:[]) {
    const alias=String(b?.alias||'').trim(); const na=normAlias(alias); if(!na)continue;
    if(nr===na)return alias;
    if((nr.includes(na) && na.length>=2) || (na.includes(nr) && nr.length>=2)) {
      const score=0.92 + Math.min(0.07, Math.min(nr.length,na.length)/100);
      if(score>bestScore){bestScore=score;best=alias;} continue;
    }
    const common=[...new Set([...nr])].filter(ch=>na.includes(ch) && /[\u3400-\u9fff]/.test(ch)).length;
    const dist=levenshtein(nr,na), maxLen=Math.max(nr.length,na.length), sim=maxLen?1-dist/maxLen:0;
    if(common>=1 && ((dist<=1 && maxLen<=8) || sim>=0.72) && sim>bestScore){bestScore=sim;best=alias;}
  }
  return best;
}
function extractRange(text) {
  const t=normText(text);
  const m=t.match(/(^|\D)(\d{1,4})\s*-\s*(\d{1,4})(?!\d)/);
  if(!m)return null;
  const a=Number(m[2]),b=Number(m[3]);
  if(a<1||b<a||b-a>5000)return null;
  return {start:a,end:b,index:m.index+(m[1]?.length||0),raw:m[0].slice(m[1]?.length||0)};
}
function extractDuration(text) {
  const t=normText(text);
  const m=t.match(/(?:时长\s*:?\s*)?(\d{1,2}:\d{2}:\d{2}|\d{1,3}:\d{2})(?!\d)/);
  if(!m)return '';
  const parts=m[1].split(':').map(Number);
  if(parts.some(x=>!Number.isFinite(x)))return '';
  let h=0,mi=0,s=0;
  if(parts.length===3){[h,mi,s]=parts;}else{[mi,s]=parts;}
  if(mi>59||s>59||h>99)return '';
  return `${String(h).padStart(2,'0')}:${String(mi).padStart(2,'0')}:${String(s).padStart(2,'0')}`;
}
function isRetake(text) { return /(返音|反音|返言|返咅|反咅)/.test(normText(text)); }
function rectCenter(rect) {
  const r=rect||{}; return {x:Number(r.x||0)+Number(r.width||0)/2,y:Number(r.y||0)+Number(r.height||0)/2};
}
function cleanAliasFromFilename(text, range) {
  let before=normText(text).slice(0,range?.index ?? normText(text).length);
  before=before.replace(/^[^\u3400-\u9fffA-Za-z0-9]+/,'').replace(/(?:音频|mp3|MP3)\s*/g,'').trim();
  return before.replace(/[\s._-]+$/,'').trim();
}
function looksLikeFileLine(line) {
  const t=normText(line.text); const range=extractRange(t);
  if(!range)return false;
  if(/时长|大小|KB\b|MB\b/i.test(t))return false;
  if(/\.mp3\b/i.test(t)||/白珺珩/.test(t))return true;
  return t.length<=60 && (cjkCount(t)>=1 || /[A-Za-z]{2,}/.test(t));
}

function parseOcrLines(lines, books=[]) {
  const normalized=(Array.isArray(lines)?lines:[]).map((l,i)=>{
    const rect=l?.rect||{}; const c=rectCenter(rect);
    return {i,text:normText(l?.text),prob:Number(l?.prob||0),rect:{x:Number(rect.x||0),y:Number(rect.y||0),width:Number(rect.width||0),height:Number(rect.height||0)},cx:c.x,cy:c.y};
  }).filter(l=>l.text);

  let files=normalized.filter(looksLikeFileLine).map(l=>({...l,range:extractRange(l.text)})).sort((a,b)=>a.cy-b.cy||a.rect.x-b.rect.x);
  const dedup=[];
  for(const f of files){
    const same=dedup.find(d=>d.range.start===f.range.start&&d.range.end===f.range.end&&Math.abs(d.cy-f.cy)<=Math.max(5,(d.rect.height+f.rect.height)/2));
    if(!same)dedup.push(f); else if(f.prob>same.prob)Object.assign(same,f);
  }
  files=dedup;
  const durations=normalized.filter(l=>extractDuration(l.text)).map(l=>({...l,duration:extractDuration(l.text)}));
  const records=[];
  for(let i=0;i<files.length;i++){
    const f=files[i],prev=files[i-1],next=files[i+1];
    const top=prev?(prev.cy+f.cy)/2:-Infinity, bottom=next?(f.cy+next.cy)/2:Infinity;
    let duration=extractDuration(f.text);
    if(!duration){
      const candidates=durations.filter(d=>d.cy>=top&&d.cy<bottom&&d.i!==f.i).sort((a,b)=>{
        const ar=(a.rect.x>=f.rect.x?0:40)+Math.abs(a.cy-f.cy); const br=(b.rect.x>=f.rect.x?0:40)+Math.abs(b.cy-f.cy); return ar-br;
      });
      duration=candidates[0]?.duration||'';
    }
    const rawAlias=cleanAliasFromFilename(f.text,f.range);
    const matched=matchKnownAlias(rawAlias,books);
    const ignored=isRetake(f.text)||isRetake(rawAlias);
    const complete=!!rawAlias&&!!f.range&&!!duration;
    const confidence=(f.prob>=0.88&&complete)?'high':(f.prob>=0.65&&(f.range||duration))?'medium':'low';
    records.push({
      raw_filename:f.text,
      raw_alias:rawAlias,
      matched_alias:matched,
      episode_start:f.range.start,
      episode_end:f.range.end,
      duration,
      ignored,
      ignore_reason:ignored?'返音/反音':'' ,
      confidence,
    });
  }
  return records;
}


function median(values){const a=values.filter(Number.isFinite).sort((x,y)=>x-y);if(!a.length)return 16;const m=Math.floor(a.length/2);return a.length%2?a[m]:(a[m-1]+a[m])/2;}
function cleanNumber(text){const m=String(text||'').replace(/,/g,'').match(/-?\d+(?:\.\d+)?/);return m?Number(m[0]):NaN;}
function cleanDate(text){const m=String(text||'').match(/20\d{2}[-/.]\d{1,2}[-/.]\d{1,2}/);return m?m[0].replace(/[/.]/g,'-').split('-').map((x,i)=>i?String(Number(x)).padStart(2,'0'):x).join('-'):'';}
function cleanDateRange(text){const all=String(text||'').match(/20\d{2}[-/.]\d{1,2}[-/.]\d{1,2}/g)||[];if(!all.length)return '';const ds=all.slice(0,2).map(x=>x.replace(/[/.]/g,'-').split('-').map((v,i)=>i?String(Number(v)).padStart(2,'0'):v).join('-'));return ds.length>1?`${ds[0]} ~ ${ds[1]}`:ds[0];}
function guaguaHeaderKey(text){const t=normText(text).replace(/\s+/g,'');const pairs=[['serial','序号'],['income_source','收入来源'],['book_name','书籍名称'],['work_type','工作类型'],['workload_hours','工作量'],['rate','单价'],['amount','金额'],['settlement_method','结算方式'],['settlement_range','结算范围'],['settlement_date','结算日期']];for(const [k,label] of pairs)if(t.includes(label))return k;return '';}
function clusterByRow(lines,threshold){
  const sorted=lines.slice().sort((a,b)=>a.cy-b.cy||a.rect.x-b.rect.x),rows=[];
  for(const line of sorted){let row=rows[rows.length-1];if(!row||Math.abs(line.cy-row.cy)>threshold){row={cy:line.cy,items:[line]};rows.push(row);}else{row.items.push(line);row.cy=row.items.reduce((a,x)=>a+x.cy,0)/row.items.length;}}
  return rows.map(r=>({...r,items:r.items.sort((a,b)=>a.rect.x-b.rect.x)}));
}
function parseGuaguaJoinedText(text){
  const t=String(text||'').replace(/[：]/g,':').replace(/[～—–−]/g,'~').replace(/\s+/g,' ').trim();
  if(!t)return null;
  const dateMatches=t.match(/20\d{2}[-/.]\d{1,2}[-/.]\d{1,2}/g)||[];
  if(dateMatches.length<1)return null;
  const methodMatch=t.match(/自动月结|手动结算|自动结算|月结|结算/);
  if(!methodMatch)return null;
  const method=methodMatch[0],methodIndex=t.indexOf(method);
  const before=t.slice(0,methodIndex).trim(),after=t.slice(methodIndex+method.length).trim();
  const tokens=before.split(' ').filter(Boolean);
  if(tokens.length<7)return null;
  const serial=Number(tokens[0]);if(!Number.isFinite(serial))return null;
  // 从结算方式前向前取 金额 / 单价 / 工作量，避免书名中的数字干扰。
  const nums=[];let cut=tokens.length;
  for(let i=tokens.length-1;i>=1&&nums.length<3;i--){if(/^\d+(?:\.\d+)?$/.test(tokens[i])){nums.unshift(Number(tokens[i]));cut=i;}else if(nums.length)break;}
  if(nums.length<3)return null;
  const [workload,rate,amount]=nums;
  const prefix=tokens.slice(1,cut);if(prefix.length<3)return null;
  const workTypeIndex=prefix.findIndex(x=>/^(对白|旁白|演播|角色|后期|审听|校对|其他)$/.test(x));
  if(workTypeIndex<1)return null;
  const sourceName=prefix[0],bookName=prefix.slice(1,workTypeIndex).join(' '),workType=prefix[workTypeIndex];
  const range=cleanDateRange(after),settlementDate=cleanDate(dateMatches[dateMatches.length-1]);
  return {serial,income_source:sourceName,book_name:bookName,work_type:workType,workload_hours:workload,rate,amount,settlement_method:method,settlement_range:range,settlement_date:settlementDate,confidence:'medium',raw_cells:[t]};
}
function parseGuaguaLines(lines){
  const normalized=(Array.isArray(lines)?lines:[]).map((l,i)=>{const rect=l?.rect||{},c=rectCenter(rect);return {i,text:normText(l?.text),prob:Number(l?.prob||0),rect:{x:Number(rect.x||0),y:Number(rect.y||0),width:Number(rect.width||0),height:Number(rect.height||0)},cx:c.x,cy:c.y};}).filter(l=>l.text);
  if(!normalized.length)return [];
  const headerTokens=normalized.map(l=>({...l,key:guaguaHeaderKey(l.text)})).filter(l=>l.key);
  const headerY=headerTokens.length?median(headerTokens.map(x=>x.cy)):-Infinity;
  const centers={};for(const h of headerTokens){if(!centers[h.key]||h.prob>(centers[h.key].prob||0))centers[h.key]={x:h.rect.x,prob:h.prob};}
  const orderedKeys=['serial','income_source','book_name','work_type','workload_hours','rate','amount','settlement_method','settlement_range','settlement_date'];
  const centerPairs=orderedKeys.filter(k=>centers[k]).map(k=>[k,centers[k].x]).sort((a,b)=>a[1]-b[1]);
  const heights=normalized.map(x=>x.rect.height).filter(x=>x>0),threshold=Math.max(10,Math.min(34,median(heights)*1.25));
  const dataLines=normalized.filter(l=>l.cy>headerY+threshold*.3 && !guaguaHeaderKey(l.text));
  const clusters=clusterByRow(dataLines,threshold);
  const rows=[];
  for(const row of clusters){
    if(row.items.length===1){const joined=parseGuaguaJoinedText(row.items[0].text);if(joined){rows.push(joined);continue;}}
    let cells={};
    if(centerPairs.length>=6){
      for(const item of row.items){let best=null;for(const [key,x] of centerPairs){const d=Math.abs(item.rect.x-x);if(!best||d<best.d)best={key,d};}if(best){cells[best.key]=[cells[best.key],item.text].filter(Boolean).join(' ').trim();}}
    }else{
      const arr=row.items.map(x=>x.text).filter(Boolean);if(arr.length<5)continue;
      // 表格默认列序与呱呱账单一致；仅作为找不到表头时的兜底。
      for(let i=0;i<Math.min(arr.length,orderedKeys.length);i++)cells[orderedKeys[i]]=arr[i];
    }
    const rawCells=orderedKeys.map(k=>cells[k]||'');
    const serial=cleanNumber(cells.serial),workload=cleanNumber(cells.workload_hours),rate=cleanNumber(cells.rate),amount=cleanNumber(cells.amount);
    const bookName=String(cells.book_name||'').trim(),sourceName=String(cells.income_source||'').trim();
    if(!bookName && !Number.isFinite(amount))continue;
    if(Number.isFinite(serial)&&serial>9999)continue;
    if(!Number.isFinite(rate)&&!Number.isFinite(amount)&&!Number.isFinite(workload))continue;
    const confidence=bookName&&Number.isFinite(rate)&&Number.isFinite(amount)?'high':bookName&&Number.isFinite(amount)?'medium':'low';
    rows.push({
      serial:Number.isFinite(serial)?serial:null,
      income_source:sourceName,
      book_name:bookName,
      work_type:String(cells.work_type||'').trim(),
      workload_hours:Number.isFinite(workload)?workload:0,
      rate:Number.isFinite(rate)?rate:0,
      amount:Number.isFinite(amount)?amount:0,
      settlement_method:String(cells.settlement_method||'').trim(),
      settlement_range:cleanDateRange(cells.settlement_range||''),
      settlement_date:cleanDate(cells.settlement_date||''),
      confidence,
      raw_cells:rawCells,
    });
  }
  // 去除同一截图内 OCR 重复行。
  const seen=new Set();return rows.filter(r=>{const k=[r.serial,r.income_source,r.book_name,r.amount,r.settlement_range,r.settlement_date].join('|');if(seen.has(k))return false;seen.add(k);return true;});
}

async function callVolcOcr(imageBase64, env) {
  const body = new URLSearchParams({
    image_base64: imageBase64,
    mode: 'default',
    filter_thresh: String(env.VOLC_FILTER_THRESH || '55'),
    half_to_full: 'false',
  }).toString();
  if (body.length > 8_000_000) throw new Error('图片编码后超过火山 OCR 8MB 限制');
  const headers = await buildVolcHeaders(body, env.VOLC_ACCESS_KEY_ID, env.VOLC_SECRET_ACCESS_KEY);
  const resp = await fetch(`${VOLC_ENDPOINT}/?Action=${ACTION}&Version=${VERSION}`, {method:'POST', headers, body});
  const raw = await resp.json().catch(()=>({}));
  if(!resp.ok || Number(raw?.code)!==10000) {
    const message = raw?.message || raw?.ResponseMetadata?.Error?.Message || `火山 OCR HTTP ${resp.status}`;
    throw new Error(String(message));
  }
  const texts=raw?.data?.line_texts||[], rects=raw?.data?.line_rects||[], probs=raw?.data?.line_probs||[];
  const lines=texts.map((text,i)=>({text,rect:rects[i]||{},prob:probs[i]??0}));
  return {raw,lines};
}

export { parseOcrLines, parseGuaguaLines, parseGuaguaJoinedText, extractRange, extractDuration, matchKnownAlias, buildVolcHeaders };

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') return new Response(null, {status:204, headers:corsHeaders(request, env)});
    const url = new URL(request.url);

    if (url.pathname === '/health' && request.method === 'GET') {
      const configured=!!(env.VOLC_ACCESS_KEY_ID&&env.VOLC_SECRET_ACCESS_KEY);
      return json({ok:configured, provider:'火山引擎通用文字识别', model:'OCRNormal', version:'0.9', features:['au','guagua'], configured}, configured?200:500, request, env);
    }
    if (url.pathname !== '/ocr' || request.method !== 'POST') return json({ok:false,error:'Not found'},404,request,env);
    if (!env.VOLC_ACCESS_KEY_ID || !env.VOLC_SECRET_ACCESS_KEY) return json({ok:false,error:'Worker 未配置 VOLC_ACCESS_KEY_ID / VOLC_SECRET_ACCESS_KEY'},500,request,env);

    let body;
    try { body = await request.json(); } catch { return json({ok:false,error:'请求格式错误'},400,request,env); }
    const imageDataUrl=String(body?.image_data_url||'');
    if(!imageDataUrl.startsWith('data:image/')) return json({ok:false,error:'没有收到有效图片'},400,request,env);
    const imageBase64=stripDataUrl(imageDataUrl);
    if(!imageBase64) return json({ok:false,error:'图片为空'},400,request,env);

    try {
      const result=await callVolcOcr(imageBase64,env);
      if(String(body?.mode||'').toLowerCase()==='guagua'){
        const statement_rows=parseGuaguaLines(result.lines);
        return json({ok:true,provider:'火山引擎通用文字识别',model:'OCRNormal',mode:'guagua',statement_rows,raw_line_count:result.lines.length},200,request,env);
      }
      const records=parseOcrLines(result.lines,body?.books||[]);
      const ignored_count=records.filter(r=>r.ignored).length;
      return json({ok:true,provider:'火山引擎通用文字识别',model:'OCRNormal',mode:'au',records,ignored_count,raw_line_count:result.lines.length},200,request,env);
    } catch (e) {
      return json({ok:false,error:String(e?.message||'火山 OCR 调用失败')},502,request,env);
    }
  },
};
