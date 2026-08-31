/*
 * Date Spark authentication client. Supabase Auth is the source of truth for
 * accounts and sessions; Date Spark never stores passwords, roles, user lists,
 * or activity logs in browser storage.
 */
const AUTH = (() => {
    let client = null;
    let initializationError = '';

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
            .select('id, username, email, role, created_at, updated_at')
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

    async function register(username, email, password) {
        username = String(username || '').trim();
        email = normalizeEmail(email);
        if (!username) return { success: false, message: 'Please enter a username.' };
        if (username.length > 50) return { success: false, message: 'Username must be 50 characters or fewer.' };
        if (!isValidEmail(email)) return { success: false, message: 'Please enter a valid email address.' };
        if (!password || password.length < 6) return { success: false, message: 'Password must be at least 6 characters.' };

        const supabase = getClient();
        if (!supabase) return unavailable();
        const { data, error } = await supabase.auth.signUp({
            email, password, options: { data: { username } }
        });
        if (error) return { success: false, message: friendlyError(error, 'Unable to create your account. Please try again.') };
        if (!data.session) {
            return { success: true, requiresVerification: true, message: 'Account created. Please check your email to verify your account before signing in.' };
        }
        return { success: true, message: 'Account created! Redirecting...' };
    }

    async function login(email, password) {
        email = normalizeEmail(email);
        if (!isValidEmail(email)) return { success: false, message: 'Please enter a valid email address.' };
        if (!password) return { success: false, message: 'Please enter your password.' };

        const supabase = getClient();
        if (!supabase) return unavailable();
        const { error } = await supabase.auth.signInWithPassword({ email, password });
        if (error) return { success: false, message: friendlyError(error, 'Unable to sign in. Please try again.') };
        await recordActivity('login');
        return { success: true, message: 'Welcome back! Redirecting...' };
    }

    async function logout() {
        const supabase = getClient();
        if (!supabase) return unavailable();
        await recordActivity('logout');
        const { error } = await supabase.auth.signOut();
        return error ? { success: false, message: 'Unable to sign out. Please try again.' } : { success: true };
    }

    async function requireAuth(loginPage = 'login.html') {
        const user = await getCurrentUser();
        if (!user) window.location.replace(loginPage);
        return user;
    }

    async function redirectIfAuthed(appPage = 'index.html') {
        const user = await getCurrentUser();
        if (user) window.location.replace(appPage);
        return user;
    }

    async function isAdmin() {
        const profile = await getCurrentProfile();
        return Boolean(profile && profile.role === 'admin');
    }

    async function requireAdmin(loginPage = '/html/login.html') {
        const profile = await getCurrentProfile();
        if (!profile) {
            window.location.replace(loginPage);
            return null;
        }
        return profile.role === 'admin' ? profile : null;
    }

    async function getAdminDashboardData() {
        const supabase = getClient();
        if (!supabase) throw new Error(unavailable().message);
        const [profilesResult, activityResult] = await Promise.all([
            supabase.from('profiles').select('id, username, email, role, created_at').order('created_at', { ascending: false }),
            supabase.from('activity_logs').select('id, user_id, event_type, email, username, created_at, metadata').order('created_at', { ascending: false }).limit(500)
        ]);
        if (profilesResult.error || activityResult.error) throw new Error('Unable to load administrative data.');
        const activity = activityResult.data;
        return {
            activity,
            users: profilesResult.data.map(profile => {
                const logins = activity.filter(event => event.user_id === profile.id && event.event_type === 'login');
                return { ...profile, loginCount: logins.length, lastLoginAt: logins[0]?.created_at || null };
            })
        };
    }

    async function callAdminFunction(action, payload) {
        const supabase = getClient();
        if (!supabase) return unavailable();
        const { data, error } = await supabase.functions.invoke('admin-user-management', { body: { action, ...payload } });
        if (error || !data?.success) return { success: false, message: data?.message || 'The administrative action could not be completed.' };
        return data;
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
        generateTempPassword
    };
})();
