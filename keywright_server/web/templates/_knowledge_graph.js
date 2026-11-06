/* Explicit knowledge graph; no remote scripts or inferred relationships. */
(function () {
  'use strict';
  const $ = id => document.getElementById(id);
  const canvas = $('knowledge-canvas'), ctx = canvas.getContext('2d');
  const colors = {documentation: '#3b82f6', decision: '#a855f7', memory: '#14b8a6', operational: '#f59e0b'};
  let data = {nodes: [], edges: [], unresolved: []}, nodes = [], byId = new Map();
  let selected = {{ document | tojson }}, center = selected, hover = '', query = '';
  let width = 1, height = 1, camera = {x: 0, y: 0, scale: 1}, steps = 0, frame = 0;
  let controller, loadVersion = 0, previewVersion = 0, pointer = null;

  function element(tag, text, className) {
    const node = document.createElement(tag);
    if (text !== undefined) node.textContent = text;
    if (className) node.className = className;
    return node;
  }
  function button(text, action) {
    const node = element('button', text, 'btn sm');
    node.type = 'button'; node.addEventListener('click', action); return node;
  }
  function matches(node) {
    return !query || (node.title + ' ' + node.path + ' ' + node.collection).toLowerCase().includes(query);
  }
  function linked(id) {
    const result = new Set([id]);
    data.edges.forEach(edge => {
      if (edge.source === id) result.add(edge.target);
      if (edge.target === id) result.add(edge.source);
    });
    return result;
  }
  function screen(node) {
    return {x: width / 2 + camera.x + node.x * camera.scale,
            y: height / 2 + camera.y + node.y * camera.scale};
  }
  function radius(node) { return Math.min(15, 6 + Math.sqrt(node.incoming + node.outgoing) * 2); }
  function draw() {
    const dark = matchMedia('(prefers-color-scheme: dark)').matches;
    ctx.clearRect(0, 0, width, height);
    const focus = hover || selected, neighbors = focus ? linked(focus) : null;
    data.edges.forEach(edge => {
      const a = byId.get(edge.source), b = byId.get(edge.target);
      if (!a || !b) return;
      const strong = focus && (edge.source === focus || edge.target === focus);
      ctx.globalAlpha = !matches(a) && !matches(b) ? .06 : focus && !strong ? .08 : strong ? .8 : .24;
      ctx.strokeStyle = strong ? colors[a.kind] : dark ? '#a8b8ca' : '#64748b';
      ctx.lineWidth = strong ? 1.8 : 1;
      const from = screen(a), to = screen(b);
      ctx.beginPath(); ctx.moveTo(from.x, from.y); ctx.lineTo(to.x, to.y); ctx.stroke();
      if (strong && edge.source !== edge.target) {
        const angle = Math.atan2(to.y - from.y, to.x - from.x), r = radius(b) + 4;
        const x = to.x - Math.cos(angle) * r, y = to.y - Math.sin(angle) * r;
        ctx.beginPath(); ctx.moveTo(x - Math.cos(angle - .5) * 6, y - Math.sin(angle - .5) * 6);
        ctx.lineTo(x, y); ctx.lineTo(x - Math.cos(angle + .5) * 6, y - Math.sin(angle + .5) * 6); ctx.stroke();
      }
    });
    nodes.forEach(node => {
      const point = screen(node), active = node.id === focus;
      ctx.globalAlpha = !matches(node) ? .12 : neighbors && !neighbors.has(node.id) ? .25 : 1;
      ctx.beginPath(); ctx.arc(point.x, point.y, radius(node), 0, Math.PI * 2);
      ctx.fillStyle = colors[node.kind] || '#64748b'; ctx.fill();
      if (active) {
        ctx.beginPath(); ctx.arc(point.x, point.y, radius(node) + 4, 0, Math.PI * 2);
        ctx.strokeStyle = dark ? '#f1f5f9' : '#0f172a'; ctx.lineWidth = 2; ctx.stroke();
      }
      if (nodes.length < 65 || active || query && matches(node) || camera.scale > 1.8) {
        ctx.font = (active ? '600 ' : '') + '12px system-ui, sans-serif'; ctx.textAlign = 'center';
        const title = node.title.length > 38 ? node.title.slice(0, 36) + '…' : node.title;
        ctx.fillStyle = dark ? '#dce5ef' : '#334155'; ctx.fillText(title, point.x, point.y + radius(node) + 17);
      }
    });
    ctx.globalAlpha = 1;
  }
  function tick() {
    frame = 0;
    if (steps > 0 && nodes.length > 1 && !document.hidden) {
      const cooling = Math.max(.08, steps / 180);
      nodes.forEach(node => { node.fx = -node.x * .0015; node.fy = -node.y * .0015; });
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const a = nodes[i], b = nodes[j];
          const dx = a.x - b.x || .1, dy = a.y - b.y || .1, d2 = Math.max(100, dx * dx + dy * dy);
          const force = Math.min(3, 700 / d2) / Math.sqrt(d2);
          a.fx += dx * force; a.fy += dy * force; b.fx -= dx * force; b.fy -= dy * force;
        }
      }
      data.edges.forEach(edge => {
        const a = byId.get(edge.source), b = byId.get(edge.target);
        if (!a || !b || a === b) return;
        const dx = b.x - a.x, dy = b.y - a.y, distance = Math.hypot(dx, dy) || 1;
        const force = (distance - 95) * .009 / distance;
        a.fx += dx * force; a.fy += dy * force; b.fx -= dx * force; b.fy -= dy * force;
      });
      nodes.forEach(node => {
        if (pointer && pointer.node === node) return;
        node.x += Math.max(-5, Math.min(5, node.fx)) * cooling;
        node.y += Math.max(-5, Math.min(5, node.fy)) * cooling;
      });
      steps--;
    }
    draw();
    if (steps > 0 && !document.hidden) frame = requestAnimationFrame(tick);
  }
  function redraw() { if (!frame) frame = requestAnimationFrame(tick); }
  function fit() {
    if (!nodes.length) return;
    const xs = nodes.map(n => n.x), ys = nodes.map(n => n.y);
    const minX = Math.min(...xs), maxX = Math.max(...xs), minY = Math.min(...ys), maxY = Math.max(...ys);
    camera.scale = Math.min(2, Math.max(.15, Math.min((width - 120) / Math.max(150, maxX - minX),
                                                   (height - 130) / Math.max(150, maxY - minY))));
    camera.x = -(minX + maxX) / 2 * camera.scale; camera.y = -(minY + maxY) / 2 * camera.scale;
    redraw();
  }
  function resize() {
    const bounds = canvas.getBoundingClientRect(), dpr = Math.min(devicePixelRatio || 1, 2);
    width = bounds.width; height = bounds.height;
    canvas.width = width * dpr; canvas.height = height * dpr; ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    draw();
  }
  function listDocuments() {
    $('kg-documents').replaceChildren();
    nodes.filter(matches).forEach(node => {
      const item = element('li'), choose = button(node.title + ' · ' + node.path, () => select(node.id));
      item.append(choose); $('kg-documents').append(item);
    });
  }
  function relationships(panel, node, heading, edges, incoming) {
    panel.append(element('h3', heading + ' (' + edges.length + ')'));
    const list = element('ul');
    edges.forEach(edge => {
      const target = byId.get(incoming ? edge.source : edge.target), item = element('li');
      if (target) item.append(button(target.title, () => select(target.id)));
      else item.append(element('span', edge.target_ref));
      item.append(element('div', (edge.source_field === 'source' ? 'source reference · ' : 'references · ') +
                          (incoming && target ? target.path + ', ' : '') +
                          (edge.source_field === 'source' ? 'source metadata' : 'line ' + edge.line_number), 'small mut'));
      list.append(item);
    });
    if (!edges.length) list.append(element('li', 'None in this view.', 'mut small'));
    panel.append(list);
  }
  async function select(id) {
    selected = id; const node = byId.get(id), version = ++previewVersion;
    if (!node) return;
    const panel = $('kg-selection'); panel.replaceChildren(element('h2', node.title));
    panel.append(element('p', node.collection + ' / ' + node.path, 'small mut'));
    panel.append(element('p', node.kind + ' · ' + node.incoming + ' backlinks · ' + node.outgoing + ' references', 'small'));
    const open = element('a', 'Open document', 'btn p sm'); open.href = node.url; panel.append(open);
    panel.append(button('Local graph', () => { center = id; $('kg-view').value = 'local'; load(); }));
    relationships(panel, node, 'References', data.edges.filter(e => e.source === id), false);
    relationships(panel, node, 'Backlinks', data.edges.filter(e => e.target === id), true);
    relationships(panel, node, 'Unresolved references', data.unresolved.filter(e => e.source === id), false);
    const details = element('details'), summary = element('summary', 'Preview & provenance'), preview = element('pre', 'Loading…');
    details.append(summary, element('p', 'Revision: ' + node.revision, 'small mut'), preview); panel.append(details);
    draw();
    try {
      const response = await fetch('/ui/knowledge/graph/preview/' + encodeURIComponent(id), {credentials: 'same-origin'});
      if (version !== previewVersion) return;
      if (!response.ok) { preview.textContent = 'This document is no longer available. Refresh the graph.'; return; }
      const result = await response.json();
      if (version !== previewVersion) return;
      preview.textContent = result.markdown + (result.preview_truncated ? '\n\n… Open document for the full text.' : '');
      details.insertBefore(element('p', 'Source: ' + (result.source || 'Admin-authored Markdown') +
                                  ' · ' + result.attribution, 'small mut'), preview);
    } catch (_) { if (version === previewVersion) preview.textContent = 'Could not load preview.'; }
  }
  async function load() {
    if ($('kg-view').value === 'local' && !center && !selected) {
      $('kg-view').value = 'global'; $('kg-status').textContent = 'Select a document to open its local graph.'; return;
    }
    if (controller) controller.abort(); controller = new AbortController();
    const version = ++loadVersion;
    const params = new URLSearchParams({collection: $('kg-collection').value, depth: $('kg-depth').value});
    if ($('kg-view').value === 'local') params.set('document', center || selected);
    $('kg-depth').disabled = $('kg-view').value !== 'local';
    $('kg-rebuild-collection').value = $('kg-collection').value;
    $('kg-status').textContent = 'Loading published knowledge…';
    try {
      const response = await fetch('/ui/knowledge/graph/data?' + params, {credentials: 'same-origin', signal: controller.signal});
      if (response.redirected || response.status === 401) throw new Error('Sign in again to view knowledge.');
      if (!response.ok) throw new Error('Could not load this graph. The selected document may no longer be published.');
      const result = await response.json(); if (version !== loadVersion) return;
      data = result;
      const old = byId;
      nodes = result.nodes.map((node, i) => {
        const angle = i * 2.399963, radius = 35 * Math.sqrt(i);
        return {...node, x: old.get(node.id)?.x ?? Math.cos(angle) * radius,
                        y: old.get(node.id)?.y ?? Math.sin(angle) * radius};
      });
      byId = new Map(nodes.map(node => [node.id, node])); steps = nodes.length > 1 ? 180 : 0;
      $('kg-empty').hidden = nodes.length > 0;
      $('kg-status').textContent = nodes.length + ' documents · ' + data.edges.length + ' references · ' +
        data.unresolved.length + ' unresolved' + (data.center ? ' · ' + data.depth + '-hop local graph' : '');
      const warnings = [];
      if (data.unindexed_documents) warnings.push(data.unindexed_documents + ' older documents need their links indexed. Use “Index links in existing documents” below.');
      if (nodes.length && !data.edges.length && !data.unresolved.length && !data.unindexed_documents) warnings.push('No explicit references found. Connect notes with [[wikilinks]], Markdown links, or a plain collection path such as projects/example/overview.md. Shared topics alone do not create links.');
      if (data.truncated) warnings.push('This view is limited. Choose a collection or a local graph to explore further.');
      $('kg-warning').hidden = !warnings.length; $('kg-warning').textContent = warnings.join(' ');
      listDocuments(); fit(); redraw();
      if (byId.has(selected)) select(selected);
      else { selected = ''; previewVersion++; $('kg-selection').replaceChildren(element('h2', 'Explore your knowledge'), element('p', 'Select a document to see its links, backlinks and preview.', 'mut')); }
      history.replaceState(null, '', '/ui/knowledge/graph?' + params);
    } catch (error) {
      if (error.name === 'AbortError' || version !== loadVersion) return;
      $('kg-status').textContent = error.message;
      nodes = []; byId.clear(); data = {nodes: [], edges: [], unresolved: []}; steps = 0; previewVersion++;
      listDocuments(); $('kg-selection').replaceChildren(element('p', 'Graph unavailable. Return to knowledge or refresh.', 'mut')); draw();
    }
  }
  function zoom(factor, x = width / 2, y = height / 2) {
    const previous = camera.scale; camera.scale = Math.max(.1, Math.min(5, previous * factor));
    camera.x = x - width / 2 - (x - width / 2 - camera.x) * camera.scale / previous;
    camera.y = y - height / 2 - (y - height / 2 - camera.y) * camera.scale / previous; redraw();
  }
  function position(event) { const rect = canvas.getBoundingClientRect(); return {x: event.clientX - rect.left, y: event.clientY - rect.top}; }
  function hit(point) { return nodes.find(node => { const p = screen(node); return Math.hypot(p.x - point.x, p.y - point.y) < radius(node) + 8; }); }
  canvas.addEventListener('pointerdown', event => {
    const p = position(event); pointer = {...p, startX: p.x, startY: p.y, node: hit(p), id: event.pointerId};
    canvas.setPointerCapture(event.pointerId); canvas.style.cursor = 'grabbing';
  });
  canvas.addEventListener('pointermove', event => {
    const p = position(event);
    if (!pointer) { hover = hit(p)?.id || ''; canvas.style.cursor = hover ? 'pointer' : 'grab'; draw(); return; }
    if (pointer.id !== event.pointerId) return;
    const dx = p.x - pointer.x, dy = p.y - pointer.y;
    if (pointer.node) { pointer.node.x += dx / camera.scale; pointer.node.y += dy / camera.scale; }
    else { camera.x += dx; camera.y += dy; }
    pointer.x = p.x; pointer.y = p.y; redraw();
  });
  canvas.addEventListener('pointerup', event => {
    if (!pointer || pointer.id !== event.pointerId) return;
    if (pointer.node && Math.hypot(pointer.x - pointer.startX, pointer.y - pointer.startY) < 5) select(pointer.node.id);
    pointer = null; canvas.style.cursor = 'grab';
  });
  canvas.addEventListener('pointercancel', () => { pointer = null; });
  canvas.addEventListener('pointerleave', () => { hover = ''; draw(); });
  canvas.addEventListener('wheel', event => { event.preventDefault(); const p = position(event); zoom(Math.exp(-event.deltaY * .001), p.x, p.y); }, {passive: false});
  canvas.addEventListener('keydown', event => {
    if (event.key === '+' || event.key === '=') zoom(1.2);
    else if (event.key === '-') zoom(1 / 1.2);
    else if (event.key === 'ArrowLeft') camera.x += 30;
    else if (event.key === 'ArrowRight') camera.x -= 30;
    else if (event.key === 'ArrowUp') camera.y += 30;
    else if (event.key === 'ArrowDown') camera.y -= 30;
    else return;
    event.preventDefault(); redraw();
  });
  $('kg-in').onclick = () => zoom(1.25); $('kg-out').onclick = () => zoom(.8); $('kg-fit').onclick = fit;
  $('kg-collection').onchange = () => { selected = center = ''; $('kg-view').value = 'global'; load(); };
  $('kg-view').onchange = () => { center = selected; load(); }; $('kg-depth').onchange = load;
  $('kg-search').oninput = () => { query = $('kg-search').value.trim().toLowerCase(); listDocuments(); draw(); };
  new ResizeObserver(resize).observe(canvas);
  document.addEventListener('visibilitychange', () => { if (!document.hidden) load(); });
  resize(); load();
}());
