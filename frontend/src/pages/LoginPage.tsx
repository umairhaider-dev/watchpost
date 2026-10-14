import { type SubmitEvent, useId, useState } from 'react';
import { Navigate, useLocation } from 'react-router';

import { useCurrentUser, useSignIn } from '../api/auth';
import { ApiError } from '../api/client';
import { Brand } from '../components/Brand';
import { MAX_PASSWORD_LENGTH, returnPath } from '../lib/accounts';
import { countOf } from '../lib/format';

function waitText(seconds: number): string {
  return seconds < 60 ? countOf(seconds, 'second') : countOf(Math.ceil(seconds / 60), 'minute');
}

function signInError(error: Error): string {
  if (error instanceof ApiError) {
    if (error.status === 401) return 'Wrong user name or password.';
    if (error.status === 429) {
      return error.retryAfterSeconds
        ? `Too many failed sign-ins. Try again in ${waitText(error.retryAfterSeconds)}.`
        : 'Too many failed sign-ins. Try again later.';
    }
    if (error.status === 422) return 'Enter your user name and password.';
  }
  return 'Could not sign in. Check that the Watchpost API is running and try again.';
}

export function LoginPage() {
  const session = useCurrentUser();
  const signIn = useSignIn();
  const location = useLocation();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const headingId = useId();
  const usernameId = useId();
  const passwordId = useId();

  if (session.data) return <Navigate to={returnPath(location.state)} replace />;

  function handleSubmit(event: SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!username.trim() || !password) return;
    signIn.mutate({ username: username.trim(), password });
  }

  return (
    <main className="login">
      <section className="login__panel" aria-labelledby={headingId}>
        <Brand />
        <h1 id={headingId} className="login__title">
          Sign in
        </h1>
        <form className="form" onSubmit={handleSubmit}>
          <div className="field">
            <label htmlFor={usernameId}>User name</label>
            <input
              id={usernameId}
              type="text"
              autoComplete="username"
              autoCapitalize="none"
              spellCheck={false}
              maxLength={64}
              required
              value={username}
              onChange={(event) => {
                setUsername(event.target.value);
              }}
            />
          </div>
          <div className="field">
            <label htmlFor={passwordId}>Password</label>
            <input
              id={passwordId}
              type="password"
              autoComplete="current-password"
              maxLength={MAX_PASSWORD_LENGTH}
              required
              value={password}
              onChange={(event) => {
                setPassword(event.target.value);
              }}
            />
          </div>
          {signIn.isError ? (
            <p className="text-error small" role="alert">
              {signInError(signIn.error)}
            </p>
          ) : null}
          <button
            type="submit"
            className="button"
            disabled={!username.trim() || !password || signIn.isPending}
          >
            {signIn.isPending ? 'Signing in…' : 'Sign in'}
          </button>
        </form>
        <p className="muted small">Accounts are created by an administrator.</p>
      </section>
    </main>
  );
}
