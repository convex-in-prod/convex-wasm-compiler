import {writeFileSync} from 'node:fs';
import {runInNewContext} from 'node:vm';
const root=new URL('./',process.env.INTL_EXPERIMENT_URL);
const locales=['en-US','en-GB','de-DE','fr-FR','ja-JP','ar-EG','hi-IN','zh-CN','th-TH','pl-PL'];
const dates=[0,Date.UTC(2024,1,29,12,34,56),Date.UTC(2024,2,10,6,59,59),Date.UTC(2024,2,10,7),Date.UTC(2024,10,3,5,59,59),Date.UTC(2024,10,3,6)];
const dateProfiles=[
 {timeZone:'UTC',year:'numeric',month:'2-digit',day:'2-digit'},
 {timeZone:'UTC',month:'long',day:'numeric'},
 {timeZone:'UTC',minute:'2-digit'},
 {timeZone:'America/New_York',weekday:'long',year:'numeric',month:'long',day:'numeric',hour:'numeric',minute:'2-digit',timeZoneName:'short'},
 {timeZone:'Europe/London',hour:'2-digit',minute:'2-digit',second:'2-digit',hourCycle:'h23'},
 {timeZone:'Australia/Sydney',dateStyle:'full',timeStyle:'long'},
 {timeZone:'Pacific/Chatham',year:'numeric',month:'numeric',day:'numeric',hour:'numeric',minute:'numeric',hourCycle:'h24'},
 {timeZone:'UTC',calendar:'japanese',era:'short',year:'numeric',month:'long',day:'numeric'},
 {timeZone:'UTC',numberingSystem:'arab',year:'numeric',month:'numeric',day:'numeric'},
];
const numberProfiles=[{}, {maximumFractionDigits:3}, {minimumFractionDigits:2,maximumFractionDigits:2},
 {useGrouping:false,maximumFractionDigits:5}, {style:'percent',maximumFractionDigits:2},
 {style:'currency',currency:'USD'}, {style:'currency',currency:'JPY',currencyDisplay:'name'},
 {style:'unit',unit:'kilometer-per-hour',unitDisplay:'long'}, {notation:'scientific'}, {notation:'compact'},
 {signDisplay:'always',minimumSignificantDigits:3,maximumSignificantDigits:5}, {numberingSystem:'arab'},
];
const numbers=[0,-0,1.005,1234567.89,-1234.5,1e21];
const cases=[];
for(const locale of locales){
 for(let profile=0;profile<dateProfiles.length;profile++) for(let i=0;i<dates.length;i++)cases.push({id:`date/${locale}/${profile}/${i}`,family:'DateTimeFormat',locale,options:dateProfiles[profile],value:dates[i]});
 for(let profile=0;profile<numberProfiles.length;profile++) for(let i=0;i<numbers.length;i++)cases.push({id:`number/${locale}/${profile}/${i}`,family:'NumberFormat',locale,options:numberProfiles[profile],value:numbers[i],negativeZero:Object.is(numbers[i],-0)});
}
cases.push({id:'locale-fallback',family:'DateTimeFormat',locale:['zz-ZZ','de-DE'],options:{timeZone:'UTC',month:'long'},value:0});
cases.push({id:'exact-integer-string',family:'NumberFormat',locale:'en-US',options:{maximumFractionDigits:0},value:'9007199254740993'});
cases.push({id:'bigint',family:'NumberFormat',locale:'en-US',options:{maximumFractionDigits:0},value:'9007199254740993',bigint:true});
const evaluate=String(function run(cases){
 const rows=[];
 for(const row of cases){
  try{
   const ctor=Intl[row.family];const f=new ctor(row.locale,row.options);const value=row.bigint?BigInt(row.value):row.negativeZero?-0:row.value;
   rows.push({id:row.id,format:f.format(value),parts:f.formatToParts(value),resolved:f.resolvedOptions()});
  }catch(error){rows.push({id:row.id,error:{name:error.name,message:error.message}});}
 }
 print(JSON.stringify({capabilities:{dateParts:typeof Intl.DateTimeFormat.prototype.formatToParts,numberParts:typeof Intl.NumberFormat.prototype.formatToParts,dateRange:typeof Intl.DateTimeFormat.prototype.formatRange,numberRange:typeof Intl.NumberFormat.prototype.formatRange},rows}));
});
const render=rows=>`(${evaluate})(${JSON.stringify(rows)});\n`;
writeFileSync(new URL('corpus.json',root),JSON.stringify({versions:process.versions,cases},null,2)+'\n');
writeFileSync(new URL('probe.js',root),render(cases));
const smoke=[cases[6],cases.find(c=>c.id==='number/de-DE/5/3'),cases.find(c=>c.id==='date/ar-EG/0/1'),cases.find(c=>c.id==='number/hi-IN/0/3'),cases.find(c=>c.id==='date/en-US/2/0')];
writeFileSync(new URL('smoke.js',root),render(smoke));
for(const [name,rows] of [['reference',cases],['smoke-reference',smoke]])runInNewContext(render(rows),{print:line=>writeFileSync(new URL(name+'.json',root),line+'\n')});
console.log(JSON.stringify({cases:cases.length,smoke:smoke.length,node:process.versions.node,icu:process.versions.icu}));
