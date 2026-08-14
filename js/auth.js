/*
  Date Spark auth (client-side only, no backend)
  ------------------------------------------------
  Users are stored in localStorage as a list of { username, email, salt, passwordHash }.
  Passwords are salted and hashed with SHA-256 before storage, so a raw password is
  never saved - but this is still NOT secure the way real authentication is:
  anyone with devtools access to this browser can read the users list, and there is
  no server to verify anything. This is a "functional demo" level of auth, good for
  a school project, not for real user data.

  An activity log records every register/login event (email, username, timestamp) as
  proof of account creation and sign-ins. admin.html reads this log and the user list
  through a passcode gate (ADMIN_PASSCODE below) - change that passcode before sharing
  this project, since anyone who opens this file in devtools can read it.
*/

const AUTH = (() => {
    const USERS_KEY = 'dateSparkUsers';
    const SESSION_KEY = 'dateSparkSession';
    const LOG_KEY = 'dateSparkActivityLog';
    const ADMIN_SESSION_KEY = 'dateSparkAdminSession';
    // Change this before sharing the project - anyone who reads this file can see it.
    const ADMIN_PASSCODE = 'SparkAdmin2026';

    function getUsers() {
        try {
            return JSON.parse(localStorage.getItem(USERS_KEY)) || [];
        } catch (e) {
            return [];
        }
    }

    function saveUsers(users) {
        localStorage.setItem(USERS_KEY, JSON.stringify(users));
    }

    function getLog() {
        try {
            return JSON.parse(localStorage.getItem(LOG_KEY)) || [];
        } catch (e) {
            return [];
        }
    }

    function recordActivity(type, email, username) {
        const log = getLog();
        log.push({ type, email, username, timestamp: Date.now() });
        // keep the most recent 500 entries so localStorage doesn't grow forever
        while (log.length > 500) log.shift();
        localStorage.setItem(LOG_KEY, JSON.stringify(log));
    }

    function normalizeEmail(email) {
        return email.trim().toLowerCase();
    }

    function isValidEmail(email) {
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
    }

    function randomSalt() {
        const arr = new Uint8Array(16);
        crypto.getRandomValues(arr);
        return Array.from(arr, b => b.toString(16).padStart(2, '0')).join('');
    }

    async function hashPassword(password, salt) {
        const encoder = new TextEncoder();
        const data = encoder.encode(salt + password);
        const digest = await crypto.subtle.digest('SHA-256', data);
        return Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, '0')).join('');
    }

    async function register(username, email, password) {
        username = (username || '').trim();
        email = normalizeEmail(email || '');

        if (!username) return { success: false, message: 'Please enter a username.' };
        if (!isValidEmail(email)) return { success: false, message: 'Please enter a valid email address.' };
        if (!password || password.length < 6) return { success: false, message: 'Password must be at least 6 characters.' };

        const users = getUsers();
        if (users.some(u => u.email === email)) {
            return { success: false, message: 'An account with that email already exists.' };
        }

        const salt = randomSalt();
        const passwordHash = await hashPassword(password, salt);
        users.push({ username, email, salt, passwordHash, createdAt: Date.now() });
        saveUsers(users);
        recordActivity('register', email, username);

        createSession(email);
        return { success: true, message: 'Account created! Redirecting...' };
    }

    async function login(email, password) {
        email = normalizeEmail(email || '');
        if (!isValidEmail(email)) return { success: false, message: 'Please enter a valid email address.' };
        if (!password) return { success: false, message: 'Please enter your password.' };

        const users = getUsers();
        const user = users.find(u => u.email === email);
        if (!user) return { success: false, message: 'No account found with that email.' };

        const hash = await hashPassword(password, user.salt);
        if (hash !== user.passwordHash) {
            return { success: false, message: 'Incorrect email or password.' };
        }

        createSession(email);
        recordActivity('login', email, user.username);
        return { success: true, message: 'Welcome back! Redirecting...' };
    }

    function createSession(email) {
        sessionStorage.setItem(SESSION_KEY, email);
    }

    function logout() {
        sessionStorage.removeItem(SESSION_KEY);
    }

    function getCurrentUser() {
        const email = sessionStorage.getItem(SESSION_KEY);
        if (!email) return null;
        const users = getUsers();
        const user = users.find(u => u.email === email);
        if (!user) return null;
        return { username: user.username, email: user.email };
    }

    // Call on protected pages. Redirects to login if not authenticated.
    function requireAuth(loginPage = 'login.html') {
        if (!getCurrentUser()) {
            window.location.href = loginPage;
        }
    }

    // Call on login/register pages. Redirects away if already authenticated.
    function redirectIfAuthed(appPage = 'index.html') {
        if (getCurrentUser()) {
            window.location.href = appPage;
        }
    }

    // ===== ADMIN =====
    // Separate from user accounts - gated by a passcode instead of an email/password pair.
    function adminLogin(passcode) {
        if (passcode === ADMIN_PASSCODE) {
            sessionStorage.setItem(ADMIN_SESSION_KEY, 'true');
            return true;
        }
        return false;
    }

    function adminLogout() {
        sessionStorage.removeItem(ADMIN_SESSION_KEY);
    }

    function isAdminAuthed() {
        return sessionStorage.getItem(ADMIN_SESSION_KEY) === 'true';
    }

    // Users without password hash/salt - safe to display in an admin view.
    function getUsersForAdmin() {
        const log = getLog();
        return getUsers().map(u => {
            const userLog = log.filter(entry => entry.email === u.email);
            const lastLogin = userLog.filter(e => e.type === 'login').slice(-1)[0];
            return {
                username: u.username,
                email: u.email,
                createdAt: u.createdAt,
                loginCount: userLog.filter(e => e.type === 'login').length,
                lastLoginAt: lastLogin ? lastLogin.timestamp : null
            };
        });
    }

    function getActivityLog() {
        return [...getLog()].reverse(); // most recent first
    }

    function deleteUser(email) {
        email = normalizeEmail(email);
        const users = getUsers().filter(u => u.email !== email);
        saveUsers(users);
    }

    function generateTempPassword() {
        const chars = 'ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
        const arr = new Uint8Array(10);
        crypto.getRandomValues(arr);
        return Array.from(arr, b => chars[b % chars.length]).join('');
    }

    // Admin sets a brand-new password for a user - it never reads or reveals the old one.
    async function adminResetPassword(email, newPassword) {
        email = normalizeEmail(email);
        if (!newPassword || newPassword.length < 6) {
            return { success: false, message: 'New password must be at least 6 characters.' };
        }

        const users = getUsers();
        const user = users.find(u => u.email === email);
        if (!user) return { success: false, message: 'No account found with that email.' };

        user.salt = randomSalt();
        user.passwordHash = await hashPassword(newPassword, user.salt);
        saveUsers(users);
        recordActivity('admin_reset', email, user.username);

        return { success: true, message: 'Password reset.' };
    }

    return {
        register, login, logout, getCurrentUser, requireAuth, redirectIfAuthed, isValidEmail,
        adminLogin, adminLogout, isAdminAuthed, getUsersForAdmin, getActivityLog, deleteUser,
        adminResetPassword, generateTempPassword
    };
})();