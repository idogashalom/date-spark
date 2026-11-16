/* Date Spark administration UI. Every record comes from protected Supabase
 * queries; this file only formats data that the signed-in administrator may read. */
(() => {
    const state = { profile: null, data: null };
    const $ = selector => document.querySelector(selector);
    const esc = value => {
        const element = document.createElement('span');
        element.textContent = value == null ? '' : String(value);
        return element.innerHTML;
    };
    const dateTime = value => value ? new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value)) : '—';
    const dateOnly = value => value ? new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric' }).format(new Date(`${value}T00:00:00`)) : '—';
    const money = value => new Intl.NumberFormat('en-NG', { style: 'currency', currency: 'NGN', maximumFractionDigits: 0 }).format(Number(value || 0));
    const number = value => new Intl.NumberFormat().format(Number(value || 0));

    function showToast(message, type = '') {
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.textContent = message;
        $('#toastRegion').append(toast);
        window.setTimeout(() => toast.remove(), 3600);
    }

    function setError(message = '') {
        const element = $('#dashboardError');
        element.hidden = !message;
        element.textContent = message;
    }

    function userLabel(userId) {
        const user = state.data?.users.find(item => item.id === userId);
        if (!user) return 'Unavailable user';
        return user.full_name || user.username || user.email;
    }

    function inboxOwner(message) {
        const inbox = state.data?.inboxes.find(item => item.id === message.inbox_id);
        return inbox ? userLabel(inbox.owner_id) : 'Unavailable inbox';
    }

    function emptyRow(columns, message) {
        return `<tr><td class="empty-row" colspan="${columns}">${esc(message)}</td></tr>`;
    }

    function formatEvent(eventType) {
        return String(eventType || 'activity').replaceAll('_', ' ').replace(/\b\w/g, letter => letter.toUpperCase());
    }

    function statusBadge(value, label) {
        return `<span class="status ${esc(value)}">${esc(label)}</span>`;
    }

    function renderMetrics() {
        const metrics = state.data.metrics || {};
        const cards = [
            ['fa-users', number(metrics.total_users), 'Registered users'],
            ['fa-user-plus', number(metrics.new_registrations_30_days), 'New registrations · 30 days'],
            ['fa-right-to-bracket', number(metrics.total_login_activity), 'Successful logins'],
            ['fa-envelope-open-text', number(metrics.anonymous_messages_received), 'Anonymous messages'],
            ['fa-key', number(metrics.verified_reveal_purchases), 'Verified paid reveals'],
            ['fa-coins', money(metrics.verified_reveal_revenue_ngn), 'Verified reveal revenue']
        ];
        $('#metricGrid').innerHTML = cards.map(([icon, value, label]) => `<article class="metric-card"><span class="metric-icon"><i class="fa-solid ${icon}"></i></span><div class="metric-value">${value}</div><div class="metric-label">${esc(label)}</div></article>`).join('');
        $('#activeUsersSummary').textContent = `${number(metrics.active_users_30_minutes)} active user${Number(metrics.active_users_30_minutes) === 1 ? '' : 's'}`;
        $('#revealSummary').textContent = `${number(metrics.verified_reveal_purchases)} verified paid reveal${Number(metrics.verified_reveal_purchases) === 1 ? '' : 's'}`;
    }

    function renderBars(target, analytics) {
        if (!analytics.length) {
            target.innerHTML = '<p class="bar-chart-empty">No recorded analytics yet.</p>';
            return;
        }
        const max = Math.max(1, ...analytics.flatMap(day => [Number(day.registrations), Number(day.logins)]));
        target.innerHTML = analytics.map(day => {
            const registrations = Math.max(2, Math.round(Number(day.registrations) / max * 150));
            const logins = Math.max(2, Math.round(Number(day.logins) / max * 150));
            return `<div class="bar-day" title="${esc(`${dateOnly(day.day)}: ${day.registrations} registrations, ${day.logins} logins`)}"><i class="bar" style="height:${registrations}px"></i><i class="bar login" style="height:${logins}px"></i><span>${esc(dateOnly(day.day))}</span></div>`;
        }).join('');
    }

    function renderActivityList() {
        const activity = state.data.activity.slice(0, 6);
        $('#recentActivity').innerHTML = activity.length ? activity.map(item => `<div class="activity-row"><span class="activity-icon"><i class="fa-solid fa-clock"></i></span><div><strong>${esc(formatEvent(item.event_type))}</strong><span>${esc(item.username || item.email || userLabel(item.user_id))}</span></div><time>${esc(dateTime(item.created_at))}</time></div>`).join('') : '<p class="subtle">No activity has been recorded yet.</p>';
    }

    function renderUsers() {
        const search = $('#userSearch').value.trim().toLowerCase();
        const status = $('#userStatusFilter').value;
        const users = state.data.users.filter(user => {
            const haystack = `${user.full_name || ''} ${user.username || ''} ${user.email || ''}`.toLowerCase();
            return (!search || haystack.includes(search)) && (status === 'all' || (status === 'suspended' ? user.is_suspended : !user.is_suspended));
        });
        $('#usersTable').innerHTML = users.length ? users.map(user => `<tr><td><div class="table-user"><strong>${esc(user.full_name || user.username)}</strong><span>${esc(user.email)}${user.full_name ? ` · @${esc(user.username)}` : ''}</span></div></td><td>${esc(dateTime(user.created_at))}</td><td>${esc(dateTime(user.last_active_at))}</td><td>${number(user.loginCount)}</td><td>${statusBadge(user.is_suspended ? 'suspended' : 'active', user.is_suspended ? 'Suspended' : 'Active')}</td><td><button class="small-action ${user.is_suspended ? '' : 'danger'}" data-suspend-user="${esc(user.id)}" data-suspend-to="${String(!user.is_suspended)}">${user.is_suspended ? 'Restore access' : 'Suspend'}</button></td></tr>`).join('') : emptyRow(6, 'No users match this filter.');
    }

    function renderActivity() {
        const search = $('#activitySearch').value.trim().toLowerCase();
        const filter = $('#activityTypeFilter').value;
        const rows = state.data.activity.filter(item => {
            const haystack = `${item.event_type} ${item.username || ''} ${item.email || ''}`.toLowerCase();
            return (!search || haystack.includes(search)) && (filter === 'all' || item.event_type === filter);
        });
        $('#activityTable').innerHTML = rows.length ? rows.map(item => `<tr><td>${esc(dateTime(item.created_at))}</td><td>${esc(formatEvent(item.event_type))}</td><td>${esc(item.username || item.email || userLabel(item.user_id))}</td><td class="subtle">${esc(Object.keys(item.metadata || {}).length ? JSON.stringify(item.metadata) : '—')}</td></tr>`).join('') : emptyRow(4, 'No matching activity was found.');
    }

    function renderMessages() {
        const search = $('#messageSearch').value.trim().toLowerCase();
        const filter = $('#messageReadFilter').value;
        const messages = state.data.messages.filter(message => {
            const haystack = `${message.message_text || ''} ${inboxOwner(message)}`.toLowerCase();
            return (!search || haystack.includes(search)) && (filter === 'all' || (filter === 'read' ? message.is_read : !message.is_read));
        });
        $('#messagesTable').innerHTML = messages.length ? messages.map(message => `<tr><td>${esc(dateTime(message.created_at))}</td><td>${esc(inboxOwner(message))}</td><td class="message-copy">${esc(message.message_text || '[Image message]')}</td><td>${message.image_path ? `<button class="attachment-link" data-attachment="${esc(message.image_path)}">Open attachment</button>` : '—'}</td><td>${statusBadge(message.is_read ? 'read' : 'unread', message.is_read ? 'Read' : 'Unread')}</td></tr>`).join('') : emptyRow(5, 'No anonymous messages match this filter.');

        const payments = state.data.payments.filter(payment => payment.status === 'verified');
        $('#purchasesTable').innerHTML = payments.length ? payments.map(payment => `<tr><td>${esc(dateTime(payment.verified_at))}</td><td>${esc(userLabel(payment.recipient_id))}</td><td>#${esc(payment.message_id)}</td><td class="subtle">${esc(payment.provider)} · ${esc(payment.provider_reference)}</td><td>${esc(money(payment.amount_ngn))}</td></tr>`).join('') : emptyRow(5, 'No verified reveal purchases have been recorded.');
    }

    function renderPermissions() {
        const select = $('#grantUser');
        const selected = select.value;
        const eligible = state.data.users.filter(user => user.role !== 'admin' && !user.is_suspended);
        select.innerHTML = `<option value="">Select a user</option>${eligible.map(user => `<option value="${esc(user.id)}">${esc(`${user.full_name || user.username} (${user.email})`)}</option>`).join('')}`;
        if (eligible.some(user => user.id === selected)) select.value = selected;

        const rows = state.data.permissions;
        $('#permissionsTable').innerHTML = rows.length ? rows.map(permission => `<tr><td>${esc(userLabel(permission.user_id))}</td><td>${statusBadge(permission.is_active ? 'active' : 'suspended', permission.is_active ? 'Active' : 'Revoked')}</td><td>${esc(userLabel(permission.granted_by))}</td><td>${esc(dateTime(permission.granted_at))}</td><td>${permission.is_active ? `<button class="small-action danger" data-revoke-access="${esc(permission.user_id)}">Revoke</button>` : '—'}</td></tr>`).join('') : emptyRow(5, 'No free reveal permissions have been granted.');
    }

    function renderReports() {
        const analytics = state.data.analytics;
        renderBars($('#overviewChart'), analytics);
        renderBars($('#reportChart'), analytics);
        $('#analyticsTable').innerHTML = analytics.length ? analytics.slice().reverse().map(day => `<tr><td>${esc(dateOnly(day.day))}</td><td>${number(day.registrations)}</td><td>${number(day.logins)}</td><td>${number(day.anonymous_messages)}</td><td>${number(day.reveal_purchases)}</td><td>${money(day.verified_revenue_ngn)}</td></tr>`).join('') : emptyRow(6, 'No analytics have been recorded.');
    }

    function renderAll() {
        renderMetrics();
        renderActivityList();
        renderUsers();
        renderActivity();
        renderMessages();
        renderPermissions();
        renderReports();
    }

    function showSection(section) {
        document.querySelectorAll('.nav-item').forEach(button => button.classList.toggle('is-active', button.dataset.section === section));
        document.querySelectorAll('.admin-section').forEach(panel => panel.classList.toggle('is-active', panel.dataset.panel === section));
        $('#pageTitle').textContent = document.querySelector(`.nav-item[data-section="${section}"]`).textContent.trim();
        $('#sidebar').classList.remove('is-open');
        $('#menuButton').setAttribute('aria-expanded', 'false');
        window.scrollTo({ top: 0, behavior: 'smooth' });
    }

    function csvCell(value) {
        return `"${String(value == null ? '' : value).replaceAll('"', '""')}"`;
    }

    function exportCsv(filename, headers, rows) {
        const csv = [headers, ...rows].map(row => row.map(csvCell).join(',')).join('\r\n');
        const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8' }));
        const link = document.createElement('a');
        link.href = url;
        link.download = filename;
        link.click();
        window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    }

    async function openAttachment(path) {
        const { data, error } = await AUTH.getClient().storage.from('anonymous-message-images').createSignedUrl(path, 300);
        if (error || !data?.signedUrl) return showToast('The attachment could not be opened.', 'error');
        window.open(data.signedUrl, '_blank', 'noopener');
    }

    async function changeSuspension(button) {
        const userId = button.dataset.suspendUser;
        const suspended = button.dataset.suspendTo === 'true';
        const action = suspended ? 'suspend' : 'restore';
        if (!window.confirm(`Do you want to ${action} this account?`)) return;
        button.disabled = true;
        const result = await AUTH.setUserSuspension(userId, suspended);
        if (!result.success) {
            button.disabled = false;
            showToast(result.message, 'error');
            return;
        }
        showToast(`Account access ${suspended ? 'suspended' : 'restored'}.`);
        await loadDashboard();
    }

    async function setFreeAccess(userId, isActive) {
        const result = await AUTH.setFreeRevealAccess(userId, isActive);
        if (!result.success) return showToast(result.message, 'error');
        showToast(isActive ? 'Free reveal access granted.' : 'Free reveal access revoked.');
        await loadDashboard();
    }

    async function loadDashboard() {
        try {
            setError();
            state.data = await AUTH.getAdminDashboardData();
            renderAll();
        } catch (error) {
            setError(error.message || 'The dashboard could not load its protected data.');
        }
    }

    function bindEvents() {
        document.querySelectorAll('.nav-item').forEach(button => button.addEventListener('click', () => showSection(button.dataset.section)));
        document.querySelectorAll('[data-go-to]').forEach(button => button.addEventListener('click', () => showSection(button.dataset.goTo)));
        document.querySelectorAll('[data-refresh]').forEach(button => button.addEventListener('click', loadDashboard));
        $('#menuButton').addEventListener('click', () => {
            const isOpen = $('#sidebar').classList.toggle('is-open');
            $('#menuButton').setAttribute('aria-expanded', String(isOpen));
        });
        $('#signOutButton').addEventListener('click', async () => { await AUTH.logout(); window.location.replace('/html/login.html'); });
        $('#userSearch').addEventListener('input', renderUsers);
        $('#userStatusFilter').addEventListener('change', renderUsers);
        $('#activitySearch').addEventListener('input', renderActivity);
        $('#activityTypeFilter').addEventListener('change', renderActivity);
        $('#messageSearch').addEventListener('input', renderMessages);
        $('#messageReadFilter').addEventListener('change', renderMessages);
        $('#usersTable').addEventListener('click', event => { const button = event.target.closest('[data-suspend-user]'); if (button) void changeSuspension(button); });
        $('#messagesTable').addEventListener('click', event => { const button = event.target.closest('[data-attachment]'); if (button) void openAttachment(button.dataset.attachment); });
        $('#permissionsTable').addEventListener('click', event => { const button = event.target.closest('[data-revoke-access]'); if (button && window.confirm('Revoke this user’s free reveal access?')) void setFreeAccess(button.dataset.revokeAccess, false); });
        $('#grantAccessForm').addEventListener('submit', event => { event.preventDefault(); const userId = $('#grantUser').value; if (!userId) return; void setFreeAccess(userId, true); });
        $('#exportUsers').addEventListener('click', () => exportCsv('date-spark-users.csv', ['Name', 'Username', 'Email', 'Role', 'Status', 'Registered', 'Last activity'], state.data.users.map(user => [user.full_name, user.username, user.email, user.role, user.is_suspended ? 'Suspended' : 'Active', user.created_at, user.last_active_at])));
        $('#exportActivity').addEventListener('click', () => exportCsv('date-spark-activity.csv', ['When', 'Event', 'Username', 'Email', 'Details'], state.data.activity.map(item => [item.created_at, item.event_type, item.username, item.email, JSON.stringify(item.metadata || {})])));
        $('#exportMessages').addEventListener('click', () => exportCsv('date-spark-anonymous-messages.csv', ['Received', 'Recipient', 'Message', 'Attachment path', 'Read'], state.data.messages.map(message => [message.created_at, inboxOwner(message), message.message_text, message.image_path, message.is_read])));
        $('#exportAnalytics').addEventListener('click', () => exportCsv('date-spark-analytics-30-days.csv', ['Date', 'Registrations', 'Logins', 'Anonymous messages', 'Paid reveals', 'Verified reveal revenue NGN'], state.data.analytics.map(day => [day.day, day.registrations, day.logins, day.anonymous_messages, day.reveal_purchases, day.verified_revenue_ngn])));
    }

    (async function init() {
        const profile = await AUTH.requireAdmin('/html/login.html');
        if (!profile) return;
        state.profile = profile;
        $('#adminName').textContent = profile.full_name || profile.username || 'Administrator';
        $('#adminInitials').textContent = (profile.full_name || profile.username || 'A').split(/\s+/).map(word => word[0]).join('').slice(0, 2).toUpperCase();
        $('#adminShell').hidden = false;
        bindEvents();
        await loadDashboard();
    })();
})();
