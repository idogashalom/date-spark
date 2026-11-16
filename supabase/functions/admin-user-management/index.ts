// Supabase Edge Function: admin-user-management
// Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY as Edge Function secrets only.
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

const corsHeaders = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type' };

Deno.serve(async request => {
    if (request.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders });

    try {
        const authorization = request.headers.get('Authorization');
        if (!authorization) throw new Error('Unauthorized');

        const admin = createClient(
            Deno.env.get('SUPABASE_URL') ?? '',
            Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? '',
            { auth: { autoRefreshToken: false, persistSession: false } }
        );
        const token = authorization.replace('Bearer ', '');
        const { data: { user }, error: userError } = await admin.auth.getUser(token);
        if (userError || !user) throw new Error('Unauthorized');

        const { data: profile } = await admin.from('profiles').select('role').eq('id', user.id).single();
        if (profile?.role !== 'admin') throw new Error('Forbidden');

        const { action, userId, newPassword, suspended, isActive } = await request.json();
        if (!userId) throw new Error('A user is required.');

        const { data: targetProfile, error: targetError } = await admin
            .from('profiles')
            .select('id, role, is_suspended')
            .eq('id', userId)
            .maybeSingle();
        if (targetError || !targetProfile) throw new Error('The selected user no longer exists.');
        if (targetProfile.role === 'admin') throw new Error('Administrator accounts cannot be changed from this dashboard.');
        if (userId === user.id) throw new Error('You cannot change your own account from this dashboard.');

        async function addAudit(actionName: string, metadata: Record<string, unknown> = {}) {
            const { error } = await admin.from('administrative_audit_logs').insert({
                actor_id: user.id,
                action: actionName,
                target_user_id: userId,
                metadata
            });
            if (error) throw error;
        }

        if (action === 'delete_user') {
            const { error } = await admin.auth.admin.deleteUser(userId);
            if (error) throw error;
            await addAudit('user_deleted');
            return Response.json({ success: true }, { headers: corsHeaders });
        }

        if (action === 'reset_password') {
            if (typeof newPassword !== 'string' || newPassword.length < 6) throw new Error('Password must be at least 6 characters.');
            const { error } = await admin.auth.admin.updateUserById(userId, { password: newPassword });
            if (error) throw error;
            await admin.from('activity_logs').insert({ user_id: userId, event_type: 'admin_password_reset', metadata: { admin_id: user.id } });
            await addAudit('password_reset');
            return Response.json({ success: true }, { headers: corsHeaders });
        }

        if (action === 'set_user_suspension') {
            if (typeof suspended !== 'boolean') throw new Error('A suspension status is required.');

            // The ban is performed by the server-only Admin API. Browser users
            // cannot change another account or access the service-role key.
            const { error: authError } = await admin.auth.admin.updateUserById(userId, {
                ban_duration: suspended ? '876000h' : 'none'
            });
            if (authError) throw authError;

            const { error: profileError } = await admin.from('profiles').update({
                is_suspended: suspended,
                suspended_at: suspended ? new Date().toISOString() : null
            }).eq('id', userId);
            if (profileError) throw profileError;

            await admin.from('activity_logs').insert({
                user_id: userId,
                event_type: suspended ? 'account_suspended' : 'account_reinstated',
                metadata: { admin_id: user.id }
            });
            await addAudit(suspended ? 'account_suspended' : 'account_reinstated');
            return Response.json({ success: true }, { headers: corsHeaders });
        }

        if (action === 'set_free_reveal_access') {
            if (typeof isActive !== 'boolean') throw new Error('A free-reveal status is required.');

            const timestamp = new Date().toISOString();
            const permissionChange = isActive
                ? admin.from('free_anonymous_reveal_permissions').upsert({
                    user_id: userId,
                    is_active: true,
                    granted_by: user.id,
                    granted_at: timestamp,
                    revoked_by: null,
                    revoked_at: null
                }, { onConflict: 'user_id' })
                : admin.from('free_anonymous_reveal_permissions').update({
                    is_active: false,
                    revoked_by: user.id,
                    revoked_at: timestamp
                }).eq('user_id', userId);
            const { error } = await permissionChange;
            if (error) throw error;

            await admin.from('activity_logs').insert({
                user_id: userId,
                event_type: isActive ? 'admin_free_reveal_granted' : 'admin_free_reveal_revoked',
                metadata: { admin_id: user.id }
            });
            await addAudit(isActive ? 'free_reveal_granted' : 'free_reveal_revoked');
            return Response.json({ success: true }, { headers: corsHeaders });
        }

        throw new Error('Unknown action.');
    } catch (error) {
        return Response.json({ success: false, message: error instanceof Error ? error.message : 'Request failed.' }, { status: 400, headers: corsHeaders });
    }
});
