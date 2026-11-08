/* Repository lesson markup only. Student notebooks remain literal text. */
'use strict';
const AcademyMarkup=(()=>{
 const escape=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
 function inline(value,depth=0){
  const s=String(value??'');if(depth>5)return escape(s);
  const tokens=/(`+)([^`]+?)\1|\*\*([^\n]+?)\*\*|__([^\n]+?)__|(?<![\w가-힣-])\*([^*\n]+?)\*(?![\w가-힣-])|\[([^\]\n]+)\]\(([^\s)]+)\)/g;
  let out='',cursor=0;
  for(const m of s.matchAll(tokens)){
   out+=escape(s.slice(cursor,m.index));cursor=m.index+m[0].length;
   if(m[1])out+='<code>'+escape(m[2])+'</code>';
   else if(m[3]||m[4])out+='<strong>'+inline(m[3]||m[4],depth+1)+'</strong>';
   else if(m[5])out+='<em>'+inline(m[5],depth+1)+'</em>';
   else{const url=m[7];out+=/^(https?:\/\/|\/(?!\/)|#)/i.test(url)&&!/[\x00-\x20\\]/.test(url)?'<a href="'+escape(url)+'" target="_blank" rel="noopener noreferrer">'+inline(m[6],depth+1)+'</a>':escape(m[6]);}
  }
  return out+escape(s.slice(cursor));
 }
 function render(value){
  const lines=String(value??'').replace(/\r\n?/g,'\n').split('\n');let out='',i=0;
  const divider=s=>/^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)+\|?\s*$/.test(s);
  const cells=s=>s.trim().replace(/^\||\|$/g,'').split(/(?<!\\)\|/).map(x=>inline(x.trim().replace(/\\\|/g,'|')));
  while(i<lines.length){
   const line=lines[i];if(!line.trim()){i++;continue;}
   if(/^\s*```/.test(line)){const code=[];i++;while(i<lines.length&&!/^\s*```/.test(lines[i]))code.push(lines[i++]);i++;out+='<pre class="ac-code"><code>'+escape(code.join('\n'))+'</code></pre>';continue;}
   const h=line.match(/^\s*(#{1,6})\s+(.+)$/);if(h){const level=Math.min(6,h[1].length+2);out+='<h'+level+'>'+inline(h[2])+'</h'+level+'>';i++;continue;}
   if(i+1<lines.length&&line.includes('|')&&divider(lines[i+1])){out+='<div class="ac-table-scroll"><table><thead><tr>'+cells(line).map(x=>'<th>'+x+'</th>').join('')+'</tr></thead><tbody>';i+=2;while(i<lines.length&&lines[i].includes('|')&&lines[i].trim()){out+='<tr>'+cells(lines[i++]).map(x=>'<td>'+x+'</td>').join('')+'</tr>';}out+='</tbody></table></div>';continue;}
   const list=line.match(/^\s*(?:([-+*])|(\d+)[.)])\s+(.+)$/);if(list){const ordered=!!list[2],tag=ordered?'ol':'ul';out+='<'+tag+'>';while(i<lines.length){const item=lines[i].match(/^\s*(?:([-+*])|(\d+)[.)])\s+(.+)$/);if(!item||!!item[2]!==ordered)break;out+='<li>'+inline(item[3])+'</li>';i++;}out+='</'+tag+'>';continue;}
   if(/^\s*>\s?/.test(line)){const quote=[];while(i<lines.length&&/^\s*>/.test(lines[i]))quote.push(lines[i++].replace(/^\s*>\s?/,''));out+='<blockquote>'+quote.map(x=>inline(x)).join('<br>')+'</blockquote>';continue;}
   if(/^\s*(?:---+|\*\*\*+)\s*$/.test(line)){out+='<hr>';i++;continue;}
   out+='<p>'+inline(line)+'</p>';i++;
  }
  return out;
 }
 return {inline,render};
})();
