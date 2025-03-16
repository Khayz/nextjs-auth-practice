import {Lucia} from 'lucia';
import {BetterSqlite3Adapter} from '@lucia-auth/adapter-sqlite';
import db from './db';
import {cookies} from "next/headers";

type BetterSqlite3AdapterConfig = {
  user: string;
  session: string;
}

type SessionCookieAttributes = {
  secure: boolean;
}

type LuciaConfig = {
  sessionCookie: {
    expires: boolean;
    attributes: SessionCookieAttributes;
  }
}

type UserId = number | bigint ;

type AuthResult = { user: string; session: { id: number | bigint } } | {
  user: null;
  session: null
};

const adapterConfig: BetterSqlite3AdapterConfig = {
  user: 'users',
  session: 'sessions'
}

const adapter = new BetterSqlite3Adapter(db, adapterConfig);

const sessionCookieAttributes: SessionCookieAttributes = {
  secure: process.env.NODE_ENV === 'production',
};

const luciaConfig: LuciaConfig = {
  sessionCookie: {
    expires: false,
    attributes: sessionCookieAttributes
  }
}

const lucia = new Lucia(adapter,luciaConfig);

export async function createAuthSession(userId: UserId): Promise<void> {
  const session = await lucia.createSession(`${userId}`, {});
  const sessionCookie = lucia.createSessionCookie(session.id);
  (await cookies()).set(sessionCookie.name, sessionCookie.value, sessionCookie.attributes);
}

const errorSession = {
  user: null,
  session: null
};

export async function verifyAuth(): Promise<AuthResult> {
  const sessionCookie = (await cookies()).get(lucia.sessionCookieName);

  if (!sessionCookie) {
    return errorSession;
  }

  const sessionId = sessionCookie.value;

  if (!sessionId) {
    return errorSession;
  }

  const result = await lucia.validateSession(sessionId);

  try {
    if (result.session && result.session.fresh) {
      const sessionCookie = lucia.createSessionCookie(result.session.id);
      (await cookies()).set(sessionCookie.name, sessionCookie.value, sessionCookie.attributes);
    }

    if (!result.session) {
      const sessionCookie = lucia.createBlankSessionCookie();
      (await cookies()).set(sessionCookie.name, sessionCookie.value, sessionCookie.attributes);
    }
  } catch {}

  // @ts-ignore
  return result;
}

export async function endSession(){
  const { session } = await verifyAuth()
  if (!session) {
    return {
      error: 'Unauthorized'
    }
  }

  await lucia.invalidateSession(`${session.id}`)
  const sessionCookie = lucia.createBlankSessionCookie();
  (await cookies()).set(sessionCookie.name, sessionCookie.value, sessionCookie.attributes);
}
