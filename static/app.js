const $=id=>document.getElementById(id);
const scan=$('scan'),input=$('url'),error=$('error'),result=$('result');
function safeText(el,value){el.textContent=value}
async function analyze(){
 error.textContent=''; const url=input.value.trim();
 if(!url){error.textContent='Paste a URL first.';input.focus();return}
 scan.disabled=true;scan.textContent='Analyzing URL…';
 try{
  const r=await fetch('/api/analyze',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url})});
  const d=await r.json(); if(!r.ok) throw new Error(d.error||'Analysis failed.');
  safeText($('score'),d.score); safeText($('badge'),d.label); safeText($('message'),d.message);
  $('verdict').className='verdict '+d.level; $('meter').className=d.level; $('meter').style.width=d.score+'%';
  safeText($('combined'),d.combined_probability.toFixed(2)+'%');
  safeText($('rf'),d.random_forest_probability.toFixed(2)+'%'); safeText($('xgb'),d.xgboost_probability.toFixed(2)+'%');
  safeText($('rfms'),'This request: '+d.rf_ms+' ms'); safeText($('xgbms'),'This request: '+d.xgb_ms+' ms');
  safeText($('normalized'),d.normalized_url);
  const f=$('features');f.innerHTML='';
  Object.entries(d.features).forEach(([k,v])=>{const x=document.createElement('div'),s=document.createElement('span'),b=document.createElement('b');s.textContent=k;b.textContent=typeof v==='number'?String(Math.round(v*10000)/10000):String(v);x.append(s,b);f.appendChild(x)});
  result.classList.remove('hidden');result.scrollIntoView({behavior:'smooth',block:'start'});
 }catch(e){error.textContent=e.message}
 finally{scan.disabled=false;scan.textContent='Analyze URL'}
}
scan.addEventListener('click',analyze);
input.addEventListener('keydown',e=>{if(e.key==='Enter')analyze()});
$('toggle')?.addEventListener('click',()=>{const f=$('features');f.classList.toggle('hidden');$('toggle').textContent=f.classList.contains('hidden')?'View 22 Extracted Features':'Hide Extracted Features'});
