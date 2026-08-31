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

        const { action, userId, newPassword } = await request.json();
        if (!userId) throw new Error('A user is required.');

        if (action === 'delete_user') {
            const { error } = await admin.auth.admin.deleteUser(userId);
            if (error) throw error;
            return Response.json({ success: true }, { headers: corsHeaders });
        }

        if (action === 'reset_password') {
            if (typeof newPassword !== 'string' || newPassword.length < 6) throw new Error('Password must be at least 6 characters.');
            const { error } = await admin.auth.admin.updateUserById(userId, { password: newPassword });
            if (error) throw error;
            await admin.from('activity_logs').insert({ user_id: userId, event_type: 'admin_password_reset', metadata: { admin_id: user.id } });
            return Response.json({ success: true }, { headers: corsHeaders });
        }

        throw new Error('Unknown action.');
    } catch (error) {
        return Response.json({ success: false, message: error instanceof Error ? error.message : 'Request failed.' }, { status: 400, headers: corsHeaders });
    }
});
