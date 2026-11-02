/* Breeze in HomeOn - clearer AC page:
   big room temperature next to the target, dial colour by mode, swing only in the settings,
   quick off-timer on the main page, profiles as a short row of buttons. */
(function(){
if(!window.BZ)return;
const B=window.BZ;
const MODE_COL={heat:'#ff9a3d',cool:'#5ac8fa',auto:'#ff9a3d',dry:'#64d2c8',fan:'#aeb4bf'};
document.head.insertAdjacentHTML('beforeend',`<style>
.room2{display:flex;align-items:center;justify-content:center;gap:6px;margin-top:8px;font-size:1.05rem;font-weight:600;color:var(--fg)}
.room2 .rv{font-size:1.35rem;font-weight:700}
.room2 .tr{font-size:.85rem;font-weight:500;color:var(--muted)}
.room2 svg{width:16px;height:16px;flex:none}
#indoor{display:none!important}
.ac-product{display:none!important}
.ctl-row .air{display:none!important}
.qt{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.qt .ql{font-size:.9rem;color:var(--muted);margin-inline-end:2px}
.qt button{flex:1;min-height:44px;min-width:64px;border-radius:999px;background:var(--surface-2,#2c2c2e);border:1px solid var(--line);color:var(--fg);font:inherit;font-size:.92rem;font-weight:600}
.qt button[aria-pressed="true"]{color:#6fa8ff;background:#3d8bff26;border-color:#3d8bff66}
.qt[hidden]{display:none!important}
.profiles{display:flex!important;gap:8px!important;overflow-x:auto;flex-wrap:nowrap!important;grid-template-columns:none!important;padding-bottom:4px}
.prof{flex:0 0 auto!important;flex-direction:row!important;align-items:center!important;gap:8px!important;padding:10px 16px!important;min-width:0!important;min-height:46px;border-radius:999px!important}
.prof svg{width:19px!important;height:19px!important}
.prof b{font-size:.95rem!important;white-space:nowrap}
</style>`);

/* swing: the same switches already live in "more settings" (פונקציות / כיוון אנכי), so the buttons beside the dial go */
/* room temperature line */
const center=document.querySelector('#dial .center');
const room=document.createElement('div');room.className='room2';room.setAttribute('role','status');
center&&center.insertBefore(room,document.getElementById('dialTimer'));

/* quick off-timer */
const pr=document.querySelector('.power-row');
const qt=document.createElement('div');qt.className='qt';qt.setAttribute('role','group');qt.setAttribute('aria-label','כיבוי אוטומטי');
qt.innerHTML='<span class="ql" aria-hidden="true">כיבוי בעוד</span>'+[[.5,'חצי שעה'],[1,'שעה'],[2,'שעתיים']].map(([h,t])=>`<button data-qh="${h}" aria-label="כיבוי בעוד ${t}">${t}</button>`).join('')+'<button data-qh="0" id="qtX" aria-label="ביטול הטיימר">ביטול</button>';
pr&&pr.after(qt);
qt.onclick=e=>{const b=e.target.closest('[data-qh]');if(!b)return;B.buzz();const h=+b.dataset.qh;
  B.setTimer(h,false);B.toast(h?'יכבה בעוד '+b.textContent:'הטיימר בוטל')};

const ARR_UP='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M12 19V5M6 11l6-6 6 6"/></svg>';
const ARR_DN='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M12 5v14M6 13l6 6 6-6"/></svg>';
const OK='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="m5 12 5 5 9-10"/></svg>';

(window.__acAfter=window.__acAfter||[]).push(function(){
  const S=B.S,CAP=B.CAP;
  const fanOnly=S.mode==='fan',col=S.power?(MODE_COL[S.mode]||'#ff9a3d'):null;
  const va=document.getElementById('valArc'),kn=document.getElementById('knob'),ml=document.getElementById('modeLbl');
  const imp=(e,k)=>{if(!e)return;col?e.style.setProperty(k,col,'important'):e.style.removeProperty(k)};imp(va,'stroke');imp(kn,'stroke');imp(ml,'color');
  if(S.indoor!=null&&(!CAP||CAP.indoor)){
    const d=S.indoor-S.temp;let ic='',tr='',say='';
    if(S.power&&!fanOnly&&S.mode!=='dry'){
      if(Math.abs(d)<1){ic=OK;tr='הגיע';say='הגיע לטמפרטורה'}
      else if(d>0&&(S.mode==='cool'||S.mode==='auto')){ic=ARR_DN;tr='מתקרר';say='מתקרר עד '+S.temp}
      else if(d<0&&(S.mode==='heat'||S.mode==='auto')){ic=ARR_UP;tr='מתחמם';say='מתחמם עד '+S.temp}}
    room.hidden=false;
    room.innerHTML=`<span aria-hidden="true">בחדר</span> <span class="rv" aria-hidden="true">${S.indoor}°</span>${ic?`<span aria-hidden="true" style="color:${col}">${ic}</span><span class="tr" aria-hidden="true">${tr}</span>`:''}`;
    room.setAttribute('aria-label',`בחדר ${S.indoor} מעלות${say?', '+say:''}`);
  }else room.hidden=true;
  const left=B.timerLeftMin();qt.hidden=!S.power&&!left;
  document.getElementById('qtX').hidden=!left;
  qt.querySelectorAll('[data-qh]').forEach(b=>{const h=+b.dataset.qh;b.setAttribute('aria-pressed',!!h&&!!left&&Math.abs(left-h*60)<=3)});
});
B.render();
})();
