/*
 * Date Spark authentication client. Supabase Auth is the source of truth for
 * accounts and sessions; Date Spark never stores passwords, roles, user lists,
 * or activity logs in browser storage.
 */
const AUTH = (() => {
    let client = null;
    let initializationError = '';
    const SESSION_TIMEOUT_MS = 30 * 60 * 1000;
    const ACTIVITY_KEY = 'dateSpark:lastMeaningfulActivity';
    const ACTIVITY_THROTTLE_MS = 10 * 1000;
    const PRESENCE_THROTTLE_MS = 5 * 60 * 1000;
    let monitoredUserId = null;
    let monitoredLoginPage = null;
    let timeoutHandle = null;
    let lastActivityWrite = 0;
    let lastPresenceWrite = 0;
    let inactivityHandler = null;
    let storageHandler = null;
    let expiryInProgress = false;

    // Safe development diagnostic: it deliberately contains no URL, key, user,
    // or session data. It can be inspected in the browser console.
    function setSupabaseStatus(configured, initialized) {
        window.DateSparkSupabaseStatus = {
            configured: Boolean(configured),
            clientInitialized: Boolean(initialized)
        };
    }

    function getClient() {
        if (client) {
            setSupabaseStatus(true, true);
            return client;
        }
        const config = window.DATE_SPARK_SUPABASE_CONFIG || {};
        const configured = Boolean(config.url && config.anonKey);
        if (!window.supabase || !configured) {
            initializationError = !configured
                ? 'Supabase is not configured yet. Add the public Project URL and anon/publishable key in js/supabase-config.js.'
                : 'The Supabase library could not be loaded. Check your connection and try again.';
            setSupabaseStatus(configured, false);
            return null;
        }
        try {
            client = window.supabase.createClient(config.url, config.anonKey, {
                auth: { persistSession: true, autoRefreshToken: true, detectSessionInUrl: true }
            });
        } catch (_) {
            initializationError = 'Supabase could not be initialized. Check the public URL and anon/publishable key.';
            setSupabaseStatus(true, false);
            return null;
        }
        initializationError = '';
        setSupabaseStatus(true, true);
        return client;
    }

    function unavailable() {
        return { success: false, message: initializationError || 'Authentication service is unavailable. Please try again later.' };
    }

    function normalizeEmail(email) {
        return String(email || '').trim().toLowerCase();
    }

    function isValidEmail(email) {
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizeEmail(email));
    }

    function friendlyError(error, fallback) {
        const message = String(error?.message || '').toLowerCase();
        if (message.includes('invalid login credentials')) return 'Incorrect email or password.';
        if (message.includes('already registered') || message.includes('already been registered')) return 'An account with that email already exists.';
        if (message.includes('email not confirmed')) return 'Please verify your email before signing in.';
        if (message.includes('network') || message.includes('fetch')) return 'Unable to reach the authentication service. Check your connection and try again.';
        return fallback;
    }

    function getStoredActivity() {
        try {
            const value = JSON.parse(localStorage.getItem(ACTIVITY_KEY) || 'null');
            return value && typeof value.userId === 'string' && Number.isFinite(value.at) ? value : null;
        } catch (_) {
            return null;
        }
    }

    function clearSessionActivity() {
        localStorage.removeItem(ACTIVITY_KEY);
        if (timeoutHandle) clearTimeout(timeoutHandle);
        timeoutHandle = null;
        monitoredUserId = null;
        monitoredLoginPage = null;
    }

    function loginUrl(loginPage, reason) {
        const separator = loginPage.includes('?') ? '&' : '?';
        return `${loginPage}${separator}reason=${encodeURIComponent(reason)}`;
    }

    async function expireInactiveSession(loginPage) {
        if (expiryInProgress) return;
        expiryInProgress = true;
        const supabase = getClient();
        try {
            // A timeout is recorded before sign-out while the user JWT is valid.
            await recordActivity('session_timeout');
            await supabase?.auth.signOut();
        } finally {
            clearSessionActivity();
            window.location.replace(loginUrl(loginPage, 'inactive'));
        }
    }

    async function hasExpiredSession(user, loginPage) {
        const activity = getStoredActivity();
        if (!activity || activity.userId !== user.id) return false;
        if (Date.now() - activity.at < SESSION_TIMEOUT_MS) return false;
        await expireInactiveSession(loginPage);
        return true;
    }

    function scheduleExpiry(userId, loginPage) {
        if (timeoutHandle) clearTimeout(timeoutHandle);
        const activity = getStoredActivity();
        const lastActiveAt = activity?.userId === userId ? activity.at : Date.now();
        const remaining = Math.max(0, SESSION_TIMEOUT_MS - (Date.now() - lastActiveAt));
        timeoutHandle = setTimeout(() => expireInactiveSession(loginPage), remaining + 25);
    }

    async function recordPresence() {
        const supabase = getClient();
        if (!supabase || Date.now() - lastPresenceWrite < PRESENCE_THROTTLE_MS) return;
        lastPresenceWrite = Date.now();
        // The SQL function uses auth.uid(), so a browser can only update itself.
        await supabase.rpc('record_user_activity');
    }

    function touchSession(userId, loginPage, force = false) {
        const now = Date.now();
        if (!force && now - lastActivityWrite < ACTIVITY_THROTTLE_MS) {
            scheduleExpiry(userId, loginPage);
            return;
        }
        lastActivityWrite = now;
        localStorage.setItem(ACTIVITY_KEY, JSON.stringify({ userId, at: now }));
        scheduleExpiry(userId, loginPage);
        void recordPresence();
    }

    function startInactivityMonitor(user, loginPage) {
        if (!user || !loginPage) return;
        if (monitoredUserId === user.id && monitoredLoginPage === loginPage) {
            scheduleExpiry(user.id, loginPage);
            return;
        }

        if (inactivityHandler) {
            ['pointerdown', 'pointermove', 'keydown', 'scroll', 'touchstart'].forEach(event => {
                document.removeEventListener(event, inactivityHandler);
            });
        }
        if (storageHandler) window.removeEventListener('storage', storageHandler);

        monitoredUserId = user.id;
        monitoredLoginPage = loginPage;
        inactivityHandler = () => touchSession(user.id, loginPage);
        ['pointerdown', 'pointermove', 'keydown', 'scroll', 'touchstart'].forEach(event => {
            document.addEventListener(event, inactivityHandler, { passive: true });
        });
        storageHandler = event => {
            if (event.key !== ACTIVITY_KEY || !event.newValue) return;
            const activity = getStoredActivity();
            if (activity?.userId !== user.id) return;
            if (Date.now() - activity.at >= SESSION_TIMEOUT_MS) {
                void expireInactiveSession(loginPage);
            } else {
                scheduleExpiry(user.id, loginPage);
            }
        };
        window.addEventListener('storage', storageHandler);
        scheduleExpiry(user.id, loginPage);
        void recordPresence();
    }

    async function getSessionUser() {
        const supabase = getClient();
        if (!supabase) return null;
        const { data, error } = await supabase.auth.getUser();
        return error ? null : data.user;
    }

    async function getCurrentProfile() {
        const supabase = getClient();
        const user = await getSessionUser();
        if (!supabase || !user) return null;
        const { data, error } = await supabase
            .from('profiles')
            .select('id, username, full_name, email, role, is_suspended, last_active_at, created_at, updated_at')
            .eq('id', user.id)
            .maybeSingle();
        return error ? null : data;
    }

    async function getCurrentUser() {
        return getCurrentProfile();
    }

    async function recordActivity(eventType, metadata = {}) {
        const supabase = getClient();
        const user = await getSessionUser();
        if (!supabase || !user) return false;
        const { error } = await supabase.from('activity_logs').insert({
            user_id: user.id, event_type: eventType, metadata
        });
        return !error;
    }

    async function register(fullName, username, email, password) {
        fullName = String(fullName || '').trim().replace(/\s+/g, ' ');
        username = String(username || '').trim();
        email = normalizeEmail(email);
        if (fullName.length < 2 || fullName.length > 100) return { success: false, message: 'Please enter your name (2 to 100 characters).' };
        if (!username) return { success: false, message: 'Please enter a username.' };
        if (username.length > 50) return { success: false, message: 'Username must be 50 characters or fewer.' };
        if (!isValidEmail(email)) return { success: false, message: 'Please enter a valid email address.' };
        if (!password || password.length < 6) return { success: false, message: 'Password must be at least 6 characters.' };

        const supabase = getClient();
        if (!supabase) return unavailable();
        const { data, error } = await supabase.auth.signUp({
            email, password, options: { data: { username, full_name: fullName } }
        });
        if (error) return { success: false, message: friendlyError(error, 'Unable to create your account. Please try again.') };
        if (!data.session) {
            return { success: true, requiresVerification: true, message: 'Account created. Please check your email to verify your account before signing in.' };
        }
        touchSession(data.user.id, '/html/login.html', true);
        return { success: true, message: `Hello, ${fullName}! Your account is ready.` };
    }

    async function login(email, password) {
        email = normalizeEmail(email);
        if (!isValidEmail(email)) return { success: false, message: 'Please enter a valid email address.' };
        if (!password) return { success: false, message: 'Please enter your password.' };

        const supabase = getClient();
        if (!supabase) return unavailable();
        const { data, error } = await supabase.auth.signInWithPassword({ email, password });
        if (error) return { success: false, message: friendlyError(error, 'Unable to sign in. Please try again.') };
        const profile = await getCurrentProfile();
        if (!profile || profile.is_suspended) {
            await supabase.auth.signOut();
            return { success: false, message: 'This account is currently unavailable. Please contact Date Spark support.' };
        }
        touchSession(data.user.id, '/html/login.html', true);
        await recordActivity('login');
        return { success: true, message: profile.full_name ? `Hello, ${profile.full_name}! Redirecting...` : 'Hello! Redirecting...' };
    }

    async function logout() {
        const supabase = getClient();
        if (!supabase) return unavailable();
        await recordActivity('logout');
        const { error } = await supabase.auth.signOut();
        clearSessionActivity();
        return error ? { success: false, message: 'Unable to sign out. Please try again.' } : { success: true };
    }

    async function requireAuth(loginPage = 'login.html') {
        const user = await getSessionUser();
        if (!user) {
            window.location.replace(loginPage);
            return null;
        }
        if (await hasExpiredSession(user, loginPage)) return null;
        const profile = await getCurrentProfile();
        if (!profile || profile.is_suspended) {
            await getClient()?.auth.signOut();
            clearSessionActivity();
            window.location.replace(loginUrl(loginPage, 'suspended'));
            return null;
        }
        startInactivityMonitor(user, loginPage);
        return profile;
    }

    async function redirectIfAuthed(appPage = 'index.html') {
        const user = await getSessionUser();
        if (!user) return null;
        if (await hasExpiredSession(user, window.location.pathname)) return null;
        const profile = await getCurrentProfile();
        if (!profile || profile.is_suspended) {
            await getClient()?.auth.signOut();
            clearSessionActivity();
            return null;
        }
        window.location.replace(appPage);
        return profile;
    }

    async function isAdmin() {
        const profile = await getCurrentProfile();
        return Boolean(profile && profile.role === 'admin');
    }

    async function requireAdmin(loginPage = '/html/login.html') {
        const profile = await requireAuth(loginPage);
        if (!profile) return null;
        if (profile.role !== 'admin') {
            window.location.replace('/index.html');
            return null;
        }
        return profile;
    }

    async function getAdminDashboardData() {
        const supabase = getClient();
        if (!supabase) throw new Error(unavailable().message);
        const [metricsResult, analyticsResult, profilesResult, activityResult, inboxResult, messageResult, paymentResult, revealResult, permissionResult, auditResult] = await Promise.all([
            supabase.rpc('get_admin_dashboard_metrics'),
            supabase.rpc('get_admin_daily_analytics', { p_days: 30 }),
            supabase.from('profiles').select('id, username, full_name, email, role, is_suspended, last_active_at, created_at').order('created_at', { ascending: false }).limit(1000),
            supabase.from('activity_logs').select('id, user_id, event_type, email, username, created_at, metadata').order('created_at', { ascending: false }).limit(500),
            supabase.from('anonymous_inboxes').select('id, owner_id, created_at').limit(1000),
            supabase.from('anonymous_messages').select('id, inbox_id, message_text, image_path, created_at, is_read').order('created_at', { ascending: false }).limit(500),
            supabase.from('anonymous_reveal_payments').select('id, recipient_id, message_id, amount_ngn, provider, provider_reference, status, verified_at, created_at').order('created_at', { ascending: false }).limit(500),
            supabase.from('anonymous_message_reveals').select('id, recipient_id, message_id, access_source, payment_id, revealed_at').order('revealed_at', { ascending: false }).limit(500),
            supabase.from('free_anonymous_reveal_permissions').select('user_id, is_active, granted_by, granted_at, revoked_by, revoked_at').order('granted_at', { ascending: false }).limit(500),
            supabase.from('administrative_audit_logs').select('id, actor_id, action, target_user_id, message_id, metadata, created_at').order('created_at', { ascending: false }).limit(500)
        ]);
        if ([metricsResult, analyticsResult, profilesResult, activityResult, inboxResult, messageResult, paymentResult, revealResult, permissionResult, auditResult].some(result => result.error)) {
            throw new Error('Unable to load administrative data. Confirm the Date Spark administration migration has been applied.');
        }
        const activity = activityResult.data || [];
        return {
            metrics: metricsResult.data?.[0] || null,
            analytics: analyticsResult.data || [],
            activity,
            users: (profilesResult.data || []).map(profile => {
                const logins = activity.filter(event => event.user_id === profile.id && event.event_type === 'login');
                return { ...profile, loginCount: logins.length, lastLoginAt: logins[0]?.created_at || null };
            }),
            inboxes: inboxResult.data || [],
            messages: messageResult.data || [],
            payments: paymentResult.data || [],
            reveals: revealResult.data || [],
            permissions: permissionResult.data || [],
            audits: auditResult.data || []
        };
    }

    async function callAdminFunction(action, payload) {
        const supabase = getClient();
        if (!supabase) return unavailable();
        const { data, error } = await supabase.functions.invoke('admin-user-management', { body: { action, ...payload } });
        if (error || !data?.success) return { success: false, message: data?.message || 'The administrative action could not be completed.' };
        return data;
    }

    async function revealAnonymousSender(messageId) {
        const supabase = getClient();
        if (!supabase) return unavailable();
        const { data, error } = await supabase.rpc('reveal_anonymous_message_sender', { p_message_id: messageId });
        if (error) return { success: false, paymentRequired: String(error.message || '').toLowerCase().includes('payment is required'), message: 'Payment is required before this sender can be revealed.' };
        const result = data?.[0];
        return result?.identity_available
            ? { success: true, name: result.sender_name }
            : { success: false, unavailable: true, message: 'The sender did not provide a verified Date Spark identity.' };
    }

    function generateTempPassword() {
        const chars = 'ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
        const values = new Uint8Array(12);
        crypto.getRandomValues(values);
        return Array.from(values, value => chars[value % chars.length]).join('');
    }

    return {
        // Reuse this authenticated browser client for features such as the private
        // anonymous inbox, instead of creating duplicate Supabase clients.
        getClient,
        register, login, logout, getCurrentUser, getCurrentProfile, requireAuth,
        redirectIfAuthed, isValidEmail, isAdmin, requireAdmin, recordActivity,
        getAdminDashboardData, deleteUser: userId => callAdminFunction('delete_user', { userId }),
        adminResetPassword: (userId, newPassword) => callAdminFunction('reset_password', { userId, newPassword }),
        setUserSuspension: (userId, suspended) => callAdminFunction('set_user_suspension', { userId, suspended }),
        setFreeRevealAccess: (userId, isActive) => callAdminFunction('set_free_reveal_access', { userId, isActive }),
        revealAnonymousSender,
        generateTempPassword
    };
})();
