import {readFileSync,writeFileSync} from 'node:fs';
import {isDeepStrictEqual} from 'node:util';
const root=new URL('./',process.env.INTL_EXPERIMENT_URL);
const name=process.argv[2]??'probe';
const expected=JSON.parse(readFileSync(new URL(name==='smoke'?'smoke-reference.json':'reference.json',root)));
const actual=JSON.parse(readFileSync(new URL(name+'-actual.json',root)));
if(actual.rows.length!==expected.rows.length)throw new Error('Case count differs');
const totals={cases:actual.rows.length,format:0,parts:0,resolved:0,raw:0,errors:0};
const groups={};const differences=[];
for(let i=0;i<expected.rows.length;i++){
 const want=expected.rows[i],got=actual.rows[i];
 if(want.id!==got.id)throw new Error('Case identity differs');
 const ok={
  format:want.error||got.error?false:want.format===got.format,
  parts:want.error||got.error?false:isDeepStrictEqual(want.parts,got.parts),
  resolved:want.error||got.error?false:isDeepStrictEqual(want.resolved,got.resolved),
  raw:JSON.stringify(want)===JSON.stringify(got),
 };
 const key=got.id.includes('/')?got.id.split('/').filter((_,i)=>i!==1&&i!==3).join('/'):got.id;
 groups[key]??={cases:0,format:0,parts:0,resolved:0,raw:0,errors:0};
 for(const count of [totals,groups[key]]){
  if(count!==totals)count.cases++;
  for(const metric of ['format','parts','resolved','raw'])count[metric]+=Number(ok[metric]);
  count.errors+=Number(Boolean(got.error));
 }
 if(!Object.values(ok).every(Boolean))differences.push({id:got.id,match:ok,expected:want,actual:got});
}
const summary={referenceCapabilities:expected.capabilities,actualCapabilities:actual.capabilities,totals,groups};
writeFileSync(new URL(name+'-comparison.json',root),JSON.stringify({...summary,differences},null,2)+'\n');
console.log(JSON.stringify(summary,null,2));
if(process.argv.includes('--require-parity')&&differences.length!==0)process.exitCode=1;
