/* Offline URL-only benchmarking on the PhiUSIIL dataset; never requests or visits any URL.
 * Obtain the CSV from https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset
 * Usage: node tests/evaluate_uci_csv.js /path/to/PhiUSIIL_Phishing_URL_Dataset.csv
 * Source label 0=phishing, 1=legitimate. Independent dataset labels are not current live status.
 */
const fs=require('fs'),path=require('path'),readline=require('readline');
if(!process.argv[2]){console.error('Usage: node tests/evaluate_uci_csv.js /path/to/PhiUSIIL_Phishing_URL_Dataset.csv');process.exit(2);}
const csv=path.resolve(process.argv[2]);
if(!fs.existsSync(csv)){console.error('CSV not found:',csv);process.exit(2);}
// Standard CSV quoted-field parsing for a line containing no embedded newline.
function cells(row){const out=[];let value='',inside=false;for(let i=0;i<row.length;i++){
 const ch=row[i];if(ch==='"'){if(inside&&row[i+1]==='"'){value+='"';i++;}else inside=!inside;}
 else if(ch===','&&!inside){out.push(value);value='';}else value+=ch;
}out.push(value);return out;}
const {rules:R}=require('./load_rules').loadExtension();
const scan=url=>R.urlScore(url);
// Deterministic balanced reservoir sample: do not favor first rows when the CSV is sorted.
let seed=1701;const rand=()=>{seed=(seed*1664525+1013904223)>>>0;return seed/4294967296;};
const keep=1000,pools=[[],[]],seen=[0,0];let header=null,uIdx=-1,yIdx=-1,parsed=0,skipped=0;
(async()=>{
 const stream=readline.createInterface({input:fs.createReadStream(csv,{encoding:'utf8'}),crlfDelay:Infinity});
 for await (const row of stream){
   if(header===null){header=cells(row.replace(/^\uFEFF/,''));uIdx=header.findIndex(x=>/^URL$/i.test(x.trim()));yIdx=header.findIndex(x=>/^Label$/i.test(x.trim()));if(uIdx<0||yIdx<0)throw new Error('Expected URL and label columns; got: '+header.join(','));continue;}
   const fields=cells(row);const y=Number(fields[yIdx]);const url=fields[uIdx];
   if(![0,1].includes(y)||!url){skipped++;continue;}
   seen[y]++;const group=pools[y];if(group.length<keep)group.push(url);
   else {const idx=Math.floor(rand()*seen[y]);if(idx<keep)group[idx]=url;}
   parsed++;
 }
 let tp=0,fp=0,tn=0,fn=0,bad=0;
 for(let y=0;y<=1;y++)for(const url of pools[y]){
   const r=scan(url);if(!r.ok){bad++;continue;}
   const flagged=r.score>=R.REVIEW_RISK;
   if(y===0){if(flagged)tp++;else fn++;}else{if(flagged)fp++;else tn++;}
 }
 const percent=(a,b)=>b?`${(100*a/b).toFixed(1)}%`:'N/A';
 console.log('PhiUSIIL independent-labeled URL-only evaluation; historical labels, not current live phishing status');
 console.log(`Dataset rows ${parsed}, label 0 phishing ${seen[0]}, label 1 legitimate ${seen[1]}; sample up to ${keep}/class, rejected ${bad}, skipped ${skipped}`);
 console.log(`TP=${tp} FN=${fn} FP=${fp} TN=${tn}`);
 console.log(`Precision=${percent(tp,tp+fp)} Recall=${percent(tp,tp+fn)} False positive rate=${percent(fp,fp+tn)}`);
 console.log(`This tests URL-only rules and score threshold >=${R.REVIEW_RISK}, not dynamic page inspection, badges, or real-time protection. No URLs were opened.`);
})().catch(e=>{console.error(e);process.exitCode=1;});
