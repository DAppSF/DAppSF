function toggleCollapse(btn){
  const card = btn.closest('.card');
  const content = card.querySelector('.card-content');
  if(!content) return;
  content.classList.toggle('collapsed');
  const collapsed = content.classList.contains('collapsed');
  btn.setAttribute('aria-expanded', String(!collapsed));
  btn.textContent = collapsed ? '▼' : '▲';
}

function ensureHeaderAndContent(card){
  let header = card.querySelector('.card-header');
  let h2 = card.querySelector(':scope > h2');
  if(!header && h2){
    header = document.createElement('div');
    header.className = 'card-header';
    h2.replaceWith(header);
    header.appendChild(h2);
    const btn = document.createElement('button');
    btn.className = 'collapse-btn';
    btn.type = 'button';
    btn.textContent = '▼';
    btn.onclick = function(){ toggleCollapse(btn); };
    btn.setAttribute('aria-expanded','false');
    header.appendChild(btn);
  }
  let content = card.querySelector('.card-content');
  if(!content){
    content = document.createElement('div');
    content.className = 'card-content';
    const moving = [];
    let n = header ? header.nextSibling : card.firstChild;
    while(n){
      const next = n.nextSibling;
      if(!(n.nodeType === 1 && n.classList && n.classList.contains('card-content'))){
        moving.push(n);
      }
      n = next;
    }
    moving.forEach(x => content.appendChild(x));
    card.appendChild(content);
  }
  return { header, content };
}

function shouldCollapse(content){
  const lineHeight = parseFloat(getComputedStyle(content).lineHeight) || 20;
  const threshold = lineHeight * 7;
  const pre = content.querySelector('pre');
  const target = pre || content;
  return target.scrollHeight > threshold;
}

document.addEventListener('DOMContentLoaded', function(){
  document.querySelectorAll('.card').forEach(card=>{
    const { header, content } = ensureHeaderAndContent(card);
    const btn = header && header.querySelector('.collapse-btn');
    if(!btn || !content) return;
    if(shouldCollapse(content)){
      content.classList.add('collapsed');
      btn.textContent = '▼';
      btn.setAttribute('aria-expanded','false');
    }else{
      btn.textContent = '▲';
      btn.setAttribute('aria-expanded','true');
    }
  });
  // remove any stray buttons inside content
  document.querySelectorAll('.card .card-content .collapse-btn').forEach(b=>b.remove());
});
