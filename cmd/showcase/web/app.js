'use strict';

const $ = selector => document.querySelector(selector);
const escapeHTML = value => String(value ?? '').replace(/[&<>"']/g, char => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
}[char]));
const timeFormat = new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' });
const dateFormat = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' });
const numberFormat = new Intl.NumberFormat();
let state = null;
let busy = false;

function callLabel(call) {
  if (!call) return 'Unknown call';
  const target = Object.entries(call.scope || {}).map(([key, value]) => key === 'channel_id' ? '#' + value : value).join(', ');
  return call.tool + '(' + target + ')';
}

function reasonLabel(decision) {
  const reasons = {
    authorized: 'All required checks passed',
    'call approval is required': 'Waiting for requester approval',
    'denied by mission_call_scope': 'Outside delegated scope',
    'denied by requester_base_access': 'Requester no longer authorized',
    'denied by agent_base_access': 'Agent no longer authorized',
    'denied by requester_resource_access': 'Requester cannot access this resource',
    'denied by agent_resource_access': 'Agent cannot access this resource',
    'denied by agent_bound_to_mission': 'Agent is not the Mission executor',
    'Mission dispatch budget exhausted': 'Dispatch budget exhausted',
    'authorization check failed': 'Authority could not be verified; denied safely'
  };
  return reasons[decision.reason] || decision.reason;
}

function decisionStyle(decision) {
  if (decision.allowed) return { color: 'green', symbol: '✓', badge: 'ALLOW' };
  if (decision.reason === 'call approval is required') return { color: 'amber', symbol: '!', badge: 'DENY · Approval required' };
  return { color: 'red', symbol: '×', badge: 'DENY' };
}

function productGrant() {
  return state?.grants.find(grant => grant.tool === 'post_message' && grant.scope.channel_id === 'product');
}

function missionExpired() {
  return state && new Date(state.expires_at).getTime() <= Date.now();
}

function renderExpiry() {
  if (!state) return;
  const milliseconds = new Date(state.expires_at).getTime() - Date.now();
  const minutes = Math.max(0, Math.ceil(milliseconds / 60000));
  $('#expires').textContent = milliseconds <= 0 ? 'Expired' : minutes < 1 ? '< 1 min' : numberFormat.format(minutes) + ' min';
  $('#expires').className = milliseconds <= 0 ? 'red' : '';
  const badge = $('#mission-state');
  badge.textContent = milliseconds <= 0 ? 'Expired' : state.state === 'active' ? 'Active' : state.state;
  badge.className = 'badge ' + (milliseconds > 0 && state.state === 'active' ? 'green' : 'red');
  updateControls();
}

function updateControls() {
  document.querySelectorAll('[data-action]').forEach(button => {
    button.disabled = busy || !state;
  });
  $('#retry-load').disabled = busy;
  if (!state) return;
  const grant = productGrant();
  const exhausted = state.max_dispatches > 0 && state.dispatch_count >= state.max_dispatches;
  const inactive = missionExpired() || state.state !== 'active';
  $('#read-label').textContent = inactive || exhausted || !state.source_access ? '× Access denied' : '✓ Allowed';
  $('#read-label').className = 'scenario-label ' + (inactive || exhausted || !state.source_access ? 'red' : '');
  $('#post-label').textContent = inactive || exhausted ? '× Access denied' : grant?.approved ? '✓ Approval granted' : grant?.preview ? '! Waiting for approval' : '! Approval required';
  $('#post-label').className = 'scenario-label ' + (inactive || exhausted ? 'red' : grant?.approved ? 'green' : 'amber');
  const revoke = $('#revoke-button');
  revoke.dataset.action = state.source_access ? 'revoke_source' : 'restore_source';
  $('#revoke-label').textContent = state.source_access ? '× Revoke source access' : '↶ Restore source access';
  $('#revoke-label').className = 'scenario-label ' + (state.source_access ? 'red' : '');
  $('#revoke-title').textContent = (state.source_access ? 'Revoke' : 'Restore') + ' Alice’s work-tracker access';
  $('#revoke-note').textContent = state.source_access ? 'Prove immediate revocation' : 'Undo the access revocation';
  const approve = $('[data-action="approve_retry"]');
  approve.disabled = busy || inactive || exhausted || !grant?.preview || grant.approved;
  if (inactive || exhausted) approve.title = 'Reset the demo to use a fresh Mission and dispatch budget.';
  else approve.removeAttribute('title');
}

function renderGrants() {
  const openDetails = new Set(Array.from(document.querySelectorAll('.grant details[open]')).map(item => item.dataset.call));
  $('#grants').innerHTML = state.grants.map(grant => {
    const resources = grant.requirements?.length
      ? grant.requirements.map(item => '<code translate="no">' + escapeHTML(item.relation + ' ' + item.object) + '</code>').join('<br>')
      : '<span class="muted">No additional resource check configured</span>';
    const scope = Object.entries(grant.scope).map(([key, value]) => '<code class="scope-value" translate="no">' + escapeHTML(key) + ' = ' + escapeHTML(value) + '</code>').join(' ');
    const policy = grant.requires_approval ? (grant.approved ? 'Approval granted by Alice' : 'Requester approval required') : 'No approval required';
    return '<article class="grant"><div class="grant-heading"><h3>' + escapeHTML(grant.tool === 'get_issue' ? 'Get issue' : 'Post message') + '</h3><span class="badge ' + (grant.risk === 'high' ? 'amber' : 'green') + '">' + escapeHTML(grant.risk.toUpperCase()) + (grant.requires_approval ? ' · APPROVAL' : '') + '</span></div><dl>' +
      '<div><dt>Tool</dt><dd><code translate="no">' + escapeHTML(grant.tool) + '</code> <span class="muted">/ ' + escapeHTML(grant.server) + '</span></dd></div>' +
      '<div><dt>Protected scope</dt><dd>' + scope + '</dd></div>' +
      '<div><dt>Resource check</dt><dd>' + resources + '</dd></div>' +
      '<div><dt>Approval</dt><dd>' + escapeHTML(policy) + '</dd></div></dl>' +
      '<details class="quiet-details" data-call="' + escapeHTML(grant.call_id) + '"' + (openDetails.has(grant.call_id) ? ' open' : '') + '><summary>Details</summary><span class="hash">Canonical call ID<code class="hash" translate="no">' + escapeHTML(grant.call_id) + '</code></span></details></article>';
  }).join('');
  $('#allowed-summary').innerHTML = state.grants.map(grant => '<span><b class="green" aria-hidden="true">✓</b><code translate="no">' + escapeHTML(callLabel(grant)) + '</code>' + (grant.requires_approval ? '<small>' + (grant.approved ? 'Approved' : 'Approval required') + '</small>' : '') + '</span>').join('');
}

const checkLabels = {
  token_valid: 'Token valid',
  mission_available: 'Mission loaded from control plane',
  agent_binding: 'Correct agent',
  mission_version: 'Token matches current Mission version',
  mission_active: 'Mission is active',
  mission_expiry: 'Mission has not expired',
  canonical_call: 'Canonical call is valid',
  requester_base_access: 'Requester has tool access',
  agent_base_access: 'Agent has tool access',
  agent_bound_to_mission: 'Agent is the Mission executor',
  mission_call_scope: 'Call is inside delegated scope',
  requester_resource_access: 'Requester has resource access',
  agent_resource_access: 'Agent has resource access',
  call_approved: 'Requester approval',
  mission_dispatch_control: 'Final dispatch controls',
  mission_dispatch_budget: 'Dispatch budget available'
};

function checkRow(check, label, detail = '') {
  const result = !check ? 'SKIPPED' : check.unknown ? 'UNKNOWN' : check.allowed ? 'YES' : 'NO';
  const color = result === 'YES' ? 'green' : result === 'NO' ? 'red' : result === 'UNKNOWN' ? 'amber' : 'muted';
  const icon = result === 'YES' ? '✓' : result === 'NO' ? '×' : result === 'UNKNOWN' ? '?' : '—';
  return '<li class="check-row ' + result.toLowerCase() + '"><span class="check-icon ' + color + '" aria-hidden="true">' + icon + '</span><span class="check-label">' + escapeHTML(label) + (detail ? '<small>' + escapeHTML(detail) + '</small>' : '') + '</span><span class="check-result ' + color + '">' + result + '</span></li>';
}

function renderDecision() {
  const decision = state.last_decision;
  const product = productGrant();
  $('#approval').hidden = !product?.preview || product.approved || missionExpired() || state.state !== 'active';
  $('#approval-preview').textContent = product?.preview || '';
  if (!decision) {
    $('#decision-badge').className = 'badge';
    $('#decision-badge').textContent = 'Ready to inspect';
    $('#decision-call').textContent = 'No call attempted';
    $('#decision-reason').textContent = 'Choose “Read APOLLO-17” to inspect the authorization checks.';
    $('#decision-time').textContent = '';
    $('#decision-time').removeAttribute('datetime');
    $('#checks').innerHTML = '<li class="trace-empty">The gateway’s checks will appear here.</li>';
    $('#extra-checks').replaceChildren();
    $('#decision-json').textContent = 'No decision yet.';
    $('#decision-footnote').textContent = 'A call is allowed only when every required gate passes.';
    $('#decision-details').open = false;
    return;
  }
  const style = decisionStyle(decision);
  $('#decision-badge').className = 'badge ' + style.color;
  $('#decision-badge').textContent = style.badge;
  $('#decision-call').textContent = callLabel(decision.call);
  $('#decision-reason').textContent = reasonLabel(decision);
  $('#decision-time').textContent = timeFormat.format(new Date(decision.timestamp));
  $('#decision-time').dateTime = decision.timestamp;
  const checks = decision.checks || [];
  const byName = name => checks.find(item => item.name === name);
  const displayed = new Set();
  let rows = '';
  const add = (name, label = checkLabels[name], detail = '') => {
    displayed.add(name);
    rows += checkRow(byName(name), label, detail);
  };
  add('token_valid');
  add('agent_binding', 'Correct agent', decision.agent);
  add('mission_call_scope', 'Mission contains ' + callLabel(decision.call));
  add('requester_base_access', 'Requester has tool access', state.requester);
  add('agent_base_access', 'Agent has tool access', state.agent);
  for (const requirement of decision.call?.requirements || []) {
    for (const name of ['requester_resource_access', 'agent_resource_access']) {
      displayed.add(name);
      const check = checks.find(item => item.name === name && item.relation === requirement.relation && item.object === requirement.object);
      rows += checkRow(check, checkLabels[name], requirement.relation + ' ' + requirement.object);
    }
  }
  const policy = state.grants.find(grant => grant.server === decision.call?.server && grant.tool === decision.call?.tool);
  if (policy?.requires_approval || byName('call_approved')) add('call_approved');
  if (byName('mission_dispatch_control')) add('mission_dispatch_control');
  else add('mission_dispatch_budget');
  $('#checks').innerHTML = rows;
  const extra = checks.filter(check => !displayed.has(check.name));
  $('#extra-checks').innerHTML = '<ol class="checks">' + extra.map(check => checkRow(check, checkLabels[check.name] || check.name)).join('') + '</ol>';
  $('#decision-json').textContent = JSON.stringify(decision, null, 2);
  $('#decision-footnote').textContent = decision.allowed
    ? 'Authorization allowed. One dispatch reserved; this demo does not invoke an upstream tool.'
    : 'No dispatch reserved. SKIPPED checks did not run after an earlier gate denied the call.';
}

function renderAuthority() {
  const authority = state.authority;
  $('#tool-graph').innerHTML = [
    { label: 'Alice', allowed: authority.requester_tool },
    { label: 'Triage', allowed: authority.agent_tool }
  ].map(principal => '<div class="tool-edge' + (principal.allowed ? '' : ' revoked') + '"><span>' + principal.label + '</span><span class="edge">' + (principal.allowed ? '✓ operator' : '× revoked') + '</span><code class="tool-node" translate="no">work-tracker</code></div>').join('');
  for (const [selector, allowed] of [['#alice-resource', authority.requester_resource], ['#agent-resource', authority.agent_resource]]) {
    $(selector).textContent = allowed ? '✓' : '×';
    $(selector).className = allowed ? 'green' : 'red';
    $(selector).setAttribute('aria-label', allowed ? 'Resource access allowed' : 'Resource access denied');
  }
  $('#resource-relation').textContent = authority.requester_resource && authority.agent_resource ? 'Members of' : 'Check current access';
  $('#authority-note').className = 'authority-note' + (state.source_access ? '' : ' revoked');
  $('#authority-note').textContent = state.source_access
    ? 'Both principals need tool access and resource access to read APOLLO-17.'
    : 'Alice’s work-tracker access is revoked. Project membership is unchanged. Reads require restored tool access.';
}

function eventView(event) {
  if (event.decision) {
    const style = decisionStyle(event.decision);
    return { ...style, title: callLabel(event.decision.call), detail: reasonLabel(event.decision), badge: event.decision.allowed ? 'Allowed' : event.decision.reason === 'call approval is required' ? 'Waiting for approval' : 'Denied' };
  }
  const grant = state.grants.find(item => item.call_id === event.call_id);
  const call = grant ? callLabel(grant) : '';
  const kinds = {
    mission_proposed: { title: 'Mission created', detail: 'Alice requested a scoped delegation', badge: 'Created' },
    mission_activated: { title: 'Delegation activated', detail: 'Alice approved the Mission; signed token issued to triage', badge: 'Active', color: 'green' },
    approval_requested: { title: 'Approval requested', detail: call + ' · Preview ready for Alice', badge: 'Pending', color: 'amber', symbol: '!' },
    approval_granted: { title: 'Approval granted by Alice', detail: call, badge: 'Approved', color: 'green', symbol: '✓' },
    source_access_revoked: { title: 'Alice’s work-tracker access revoked', detail: 'The next read must recheck current authority', badge: 'Revoked', color: 'red', symbol: '×' },
    source_access_restored: { title: 'Alice’s work-tracker access restored', detail: 'Operator relationship restored; Mission controls still apply', badge: 'Restored', color: 'green', symbol: '↶' }
  };
  return { color: 'muted', symbol: '·', ...kinds[event.kind], title: kinds[event.kind]?.title || event.summary };
}

function renderTimeline() {
  $('#event-count').textContent = numberFormat.format(state.timeline.length) + ' events · oldest first';
  $('#timeline').innerHTML = state.timeline.map(event => {
    const view = eventView(event);
    return '<li class="event"><time datetime="' + escapeHTML(event.timestamp) + '">' + escapeHTML(timeFormat.format(new Date(event.timestamp))) + '</time><span class="event-symbol ' + view.color + '" aria-hidden="true">' + view.symbol + '</span><div><div class="event-title">' + escapeHTML(view.title) + '</div><div class="event-detail">' + escapeHTML(view.detail || event.summary) + '</div></div><span class="badge ' + view.color + '">' + escapeHTML(view.badge || 'Recorded') + '</span></li>';
  }).join('');
}

function render(data) {
  state = data;
  $('#delegation').setAttribute('aria-busy', 'false');
  $('#requester').textContent = data.requester;
  $('#agent').textContent = data.agent;
  $('#mission-id').textContent = data.mission_id;
  $('#prompt').textContent = data.prompt;
  $('#expires-at').textContent = dateFormat.format(new Date(data.expires_at));
  $('#dispatches').textContent = numberFormat.format(data.dispatch_count) + ' / ' + numberFormat.format(data.max_dispatches);
  const meter = $('#budget-meter');
  meter.setAttribute('aria-valuemax', data.max_dispatches);
  meter.setAttribute('aria-valuenow', data.dispatch_count);
  meter.setAttribute('aria-valuetext', data.dispatch_count + ' of ' + data.max_dispatches + ' dispatches used');
  meter.classList.toggle('exhausted', data.dispatch_count >= data.max_dispatches);
  meter.replaceChildren(...Array.from({ length: data.max_dispatches }, (_, index) => {
    const segment = document.createElement('i');
    segment.className = index < data.dispatch_count ? 'used' : '';
    return segment;
  }));
  renderGrants();
  renderDecision();
  renderAuthority();
  renderTimeline();
  renderExpiry();
}

async function request(path, options) {
  const response = await fetch(path, { ...options, cache: 'no-store', signal: AbortSignal.timeout(10000) });
  const body = await response.json();
  if (!response.ok) throw new Error(body.error || 'Request failed (' + response.status + ')');
  return body;
}

function showError(error) {
  $('#error-message').textContent = (error.name === 'TimeoutError' ? 'The gateway did not respond in time.' : error.message) + ' Refresh state before trying another action.';
  $('#error').hidden = false;
}

async function load() {
  if (busy) return;
  busy = true;
  updateControls();
  $('#request-status').textContent = 'Loading state…';
  try {
    render(await request('/api/state'));
    $('#error').hidden = true;
  } catch (error) { showError(error); }
  finally {
    busy = false;
    updateControls();
    $('#request-status').textContent = '';
  }
}

async function act(action, trigger) {
  if (busy) return;
  busy = true;
  updateControls();
  $('#request-status').textContent = action === 'reset' ? 'Resetting demo…' : 'Evaluating…';
  $('#error').hidden = true;
  try {
    render(await request('/api/action', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ action })
    }));
    let announcement;
    if (action === 'reset') announcement = 'Demo reset. A new Mission is ready.';
    else if (action === 'revoke_source') announcement = 'Alice’s work-tracker access revoked. Try Read APOLLO-17 again.';
    else if (action === 'restore_source') announcement = 'Alice’s work-tracker access restored.';
    else announcement = callLabel(state.last_decision?.call) + ': ' + (state.last_decision?.allowed ? 'allowed. ' : 'denied. ') + reasonLabel(state.last_decision);
    $('#announcement').textContent = announcement;
    if (['read', 'post', 'outside_scope', 'approve_retry'].includes(action)) {
      $('#decision-title').focus({ preventScroll: true });
      $('#decision-title').scrollIntoView({ block: 'start' });
    }
  } catch (error) { showError(error); }
  finally {
    busy = false;
    updateControls();
    $('#request-status').textContent = '';
    if (trigger && ['reset', 'revoke_source', 'restore_source'].includes(action)) trigger.focus({ preventScroll: true });
  }
}

document.addEventListener('click', event => {
  const button = event.target.closest('button[data-action]');
  if (button && !button.disabled) act(button.dataset.action, button);
});
$('#retry-load').addEventListener('click', load);
setInterval(renderExpiry, 1000);
load();
