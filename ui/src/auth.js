import { createClient } from '@supabase/supabase-js';

const SUPABASE_URL = import.meta.env.VITE_SUPABASE_URL || '';
const SUPABASE_ANON_KEY = import.meta.env.VITE_SUPABASE_ANON_KEY || '';

export const authConfigured = Boolean(SUPABASE_URL && SUPABASE_ANON_KEY);

export const supabase = authConfigured
  ? createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
      auth: {
        persistSession: true,
        autoRefreshToken: true,
      },
    })
  : null;

export async function ensureAnonymousSession() {
  if (!supabase) {
    return { configured: false, session: null, user: null, error: null };
  }

  const current = await supabase.auth.getSession();
  if (current.error) {
    return { configured: true, session: null, user: null, error: current.error };
  }

  if (current.data.session) {
    return {
      configured: true,
      session: current.data.session,
      user: current.data.session.user,
      error: null,
    };
  }

  const created = await supabase.auth.signInAnonymously();
  return {
    configured: true,
    session: created.data?.session || null,
    user: created.data?.user || created.data?.session?.user || null,
    error: created.error || null,
  };
}

export function onAuthStateChange(callback) {
  if (!supabase) {
    return { unsubscribe: () => {} };
  }

  const { data } = supabase.auth.onAuthStateChange((_event, session) => {
    callback(session);
  });

  return data.subscription;
}
