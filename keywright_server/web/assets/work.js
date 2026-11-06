(() => {
  const banner = document.getElementById('work-updates');
  const showUpdate = () => { if (banner) banner.hidden = false; };
  const filters = document.querySelector('.work-filter-panel');
  if (filters && matchMedia('(max-width:700px)').matches) filters.open = false;
  document.querySelector('a[href="#new-task"]')?.addEventListener('click', () => {
    document.getElementById('new-task').open = true;
  });
  // Keep edits and drags intact: live events offer refresh rather than replacing markup.
  let socket;
  function connect() {
    socket = new WebSocket(`${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${location.host}/ui/events`);
    socket.onmessage = event => {
      try { const data = JSON.parse(event.data); if (data.type === 'work.changed' || data.type === 'resync') showUpdate(); } catch (_) {}
    };
    socket.onclose = () => setTimeout(connect, 10000);
  }
  connect();
  if (location.pathname === '/ui/work') {
    try {
      if (location.search) localStorage.setItem('kw.work.filters', location.search);
      else {
        const saved = localStorage.getItem('kw.work.filters');
        if (saved && saved.startsWith('?')) location.replace('/ui/work' + saved);
      }
    } catch (_) {}
  }
  const board = document.querySelector('.work-board');
  if (!board || board.classList.contains('work-list')) return;
  let dragged = null;
  board.querySelectorAll('[draggable=true]').forEach(card => {
    card.addEventListener('dragstart', event => {
      dragged = card; event.dataTransfer.setData('text/plain', card.dataset.task); event.dataTransfer.effectAllowed = 'move';
    });
    card.addEventListener('dragend', () => { dragged = null; board.querySelectorAll('.drag-over').forEach(el => el.classList.remove('drag-over')); });
  });
  board.querySelectorAll('.work-column').forEach(column => {
    column.addEventListener('dragover', event => { if (dragged) { event.preventDefault(); column.classList.add('drag-over'); } });
    column.addEventListener('dragleave', () => column.classList.remove('drag-over'));
    column.addEventListener('drop', async event => {
      event.preventDefault(); column.classList.remove('drag-over');
      if (!dragged) return;
      const card = dragged;
      const before = event.target.closest('.work-task');
      const data = new FormData();
      data.set('expected_version', card.dataset.version);
      data.set('status', column.dataset.status);
      if (board.dataset.boardId && before && before !== card) data.set('before_id', before.dataset.task);
      else if (board.dataset.boardId && before !== card) data.set('before_id', '');
      else if (column.dataset.status === card.dataset.status) return;
      try {
        const response = await fetch('/ui/work/tasks/' + card.dataset.task, {method: 'POST', body: data, headers: {Accept: 'application/json'}});
        if (!response.ok) {
          const failure = await response.json();
          banner.textContent = failure.message || 'Unable to move task. Refresh and retry.'; showUpdate(); return;
        }
        const updated = await response.json();
        card.dataset.version = updated.version;
        card.dataset.status = updated.status;
        card.querySelector('[name=expected_version]').value = updated.version;
        card.querySelector('[name=status]').value = updated.status;
        if (before && before !== card && board.dataset.boardId) column.insertBefore(card, before);
        else column.appendChild(card);
        column.querySelector('.work-empty')?.remove();
        board.querySelectorAll('.work-column').forEach(section => {
          const count = section.querySelector('h2 .mut');
          if (count) count.textContent = section.querySelectorAll('.work-task').length;
        });
        // Other card versions may have changed during reordering; offer a safe refresh.
        showUpdate();
      } catch (_) { banner.textContent = 'Move outcome unknown. Refresh before retrying.'; showUpdate(); }
    });
  });
})();
