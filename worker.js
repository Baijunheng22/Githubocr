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

export { parseOcrLines, extractRange, extractDuration, matchKnownAlias, buildVolcHeaders };

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') return new Response(null, {status:204, headers:corsHeaders(request, env)});
    const url = new URL(request.url);

    if (url.pathname === '/health' && request.method === 'GET') {
      const configured=!!(env.VOLC_ACCESS_KEY_ID&&env.VOLC_SECRET_ACCESS_KEY);
      return json({ok:configured, provider:'火山引擎通用文字识别', model:'OCRNormal', version:'0.6', configured}, configured?200:500, request, env);
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
      const records=parseOcrLines(result.lines,body?.books||[]);
      const ignored_count=records.filter(r=>r.ignored).length;
      return json({ok:true,provider:'火山引擎通用文字识别',model:'OCRNormal',records,ignored_count,raw_line_count:result.lines.length},200,request,env);
    } catch (e) {
      return json({ok:false,error:String(e?.message||'火山 OCR 调用失败')},502,request,env);
    }
  },
};
