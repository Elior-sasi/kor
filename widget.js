// Breeze widget body - loaded by the small loader script in Scriptable (API, K, D come from the loader)
const MODE={cold:["קירור","#5ec8ff"],hot:["חימום","#ff9a52"],wet:["ייבוש","#b7a3ff"],wind:["אוורור","#6fe0b2"],auto:["אוטו","#e6cf72"]};
const FAN={strong:"חזק",auto:"אוטו",low:"נמוך",middle:"בינוני",high:"גבוה",mute:"שקט"};
let s=null;try{const r=new Request(API+"/state?k="+encodeURIComponent(K)+"&d="+encodeURIComponent(D));r.timeoutInterval=20;s=await r.loadJSON();if(!s.ok)s=null}catch(e){s=null}
const st=s?s.status:{};
const on=!!st.switch, m=MODE[st.mode]||["","#8e8e93"], acc=on?m[1]:"#8e8e93";
const hhmm=t=>{const d=new Date(t*1000);return("0"+d.getHours()).slice(-2)+":"+("0"+d.getMinutes()).slice(-2)};
const fam=config.widgetFamily||"medium";
const w=new ListWidget();
const g=new LinearGradient();g.colors=[new Color("#16171a"),new Color(on?acc:"#16171a",on?0.28:1)];g.locations=[0.35,1];g.startPoint=new Point(0,0);g.endPoint=new Point(1,1);w.backgroundGradient=g;
w.setPadding(14,16,14,16);w.refreshAfterDate=new Date(Date.now()+5*60*1000);
const txt=(stack,t,size,color,weight)=>{const x=stack.addText(t);x.font=weight==="b"?Font.boldSystemFont(size):weight==="l"?Font.lightRoundedSystemFont(size):Font.mediumSystemFont(size);x.textColor=new Color(color||"#ffffff");x.rightAlignText();x.lineLimit=1;x.minimumScaleFactor=0.6;return x};
const row=w.addStack();row.layoutHorizontally();row.topAlignContent();
let side=null;
if(fam!=="small"){side=row.addStack();side.layoutVertically();row.addSpacer()}else{row.addSpacer()}
const info=row.addStack();info.layoutVertically();
const top=info.addStack();top.layoutHorizontally();top.centerAlignContent();
txt(top,"Breeze",12,"#ffffffaa","b");top.addSpacer(5);
const dot=top.addText("●");dot.font=Font.systemFont(9);dot.textColor=new Color(s?(on?"#30d158":"#8e8e93"):"#ff453a");
info.addSpacer(4);
const ev=s?(s.timer?((s.timer.power?"הדלקה ":"כיבוי ")+hhmm(s.timer.at)):s.next?((s.next.power?"הדלקה ":"כיבוי ")+hhmm(s.next.at)):""):"";
if(!s){txt(info,"אין חיבור",18,"#ffffff","b");txt(info,"בדוק אינטרנט",11,"#ffffff99")}
else{
  txt(info,on?(st.temp_set+"°"):"כבוי",on?40:30,"#ffffff","l");
  if(on)txt(info,m[0]+(fam==="small"&&FAN[st.fan_speed_enum]?" · "+FAN[st.fan_speed_enum]:""),13,acc,"b");
  info.addSpacer(2);
  if(st.temp_current!=null)txt(info,"בחדר "+st.temp_current+"°",12,"#ffffffcc");
  if(fam==="small"&&ev)txt(info,"⏱ "+ev,11,"#ffffff99");
  if(s.fault&&s.fault.length)txt(info,"⚠ תקלה "+s.fault.join(","),11,"#ff6b6b","b");
}
if(side&&s){
  const item=(label,val,color)=>{const b=side.addStack();b.layoutVertically();txt(b,label,10,"#ffffff77");txt(b,val,15,color||"#ffffff","b");side.addSpacer(7)};
  side.addSpacer(2);
  if(on&&FAN[st.fan_speed_enum])item("מאוורר",FAN[st.fan_speed_enum]);
  item(s.timer?"טיימר":"הבא",ev||"אין",ev?"#ffffff":"#ffffff66");
  item("עודכן",hhmm(s.t||Date.now()/1000),"#ffffff99");
}
w.addSpacer();
w.url="https://elior-sasi.github.io/kor/";
if(config.runsInWidget)Script.setWidget(w);else if(fam==="small")await w.presentSmall();else await w.presentMedium();
Script.complete();
