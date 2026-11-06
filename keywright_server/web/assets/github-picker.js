(() => {
  const form = document.getElementById('github-repo-actions');
  if (!form) return;
  const all = document.getElementById('github-select-all');
  const rows = Array.from(form.querySelectorAll('input[name="selected"]:not(:disabled)'));
  const buttons = form.querySelectorAll('[data-bulk]');
  const update = () => {
    const count = rows.filter(row => row.checked).length;
    all.checked = rows.length > 0 && count === rows.length;
    all.indeterminate = count > 0 && count < rows.length;
    all.disabled = rows.length === 0;
    document.getElementById('github-selection-count').textContent = `${count} selected on this page`;
    buttons.forEach(button => { button.disabled = count === 0; });
  };
  all.addEventListener('change', () => { rows.forEach(row => { row.checked = all.checked; }); update(); });
  rows.forEach(row => row.addEventListener('change', update));
  update();
})();
