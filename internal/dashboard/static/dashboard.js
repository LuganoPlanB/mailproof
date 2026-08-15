const live = () => document.querySelector('#live');
let request;
document.addEventListener('htmx:beforeRequest', event => { if (request) request.abort(); request = event.detail.xhr; });
document.addEventListener('htmx:afterRequest', () => { request = undefined; });
document.addEventListener('visibilitychange', () => {
  const node = live(); if (!node || !window.htmx) return;
  if (document.hidden) { node.dataset.trigger = node.getAttribute('hx-trigger'); node.setAttribute('hx-trigger', 'none'); window.htmx.trigger(node, 'htmx:abort'); return; }
  node.setAttribute('hx-trigger', node.dataset.trigger || 'every 10s'); window.htmx.process(node); window.htmx.trigger(node, 'load');
});
