import { type SubmitEvent, useId, useState } from 'react';

import { useChangePassword, useCurrentUser, useSignOut } from '../api/auth';
import type { CurrentUser } from '../api/types';
import { Card } from '../components/Card';
import { PageHeader } from '../components/PageHeader';
import { isValidPassword, MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH } from '../lib/accounts';
import { ROLES, roleLabel } from '../lib/labels';

function Profile({ user }: { user: CurrentUser }) {
  return (
    <Card title="Profile">
      <dl className="facts">
        <div>
          <dt>User name</dt>
          <dd className="mono">{user.username}</dd>
        </div>
        <div>
          <dt>Name</dt>
          <dd>{user.full_name ?? '—'}</dd>
        </div>
        <div>
          <dt>E-mail</dt>
          <dd>{user.email ?? '—'}</dd>
        </div>
        <div>
          <dt>Role</dt>
          <dd>{roleLabel(user.role)}</dd>
        </div>
      </dl>
      <p className="muted small">
        {ROLES.find((option) => option.value === user.role)?.description} Your name, e-mail and role
        are managed by an administrator.
      </p>
    </Card>
  );
}

function PasswordForm() {
  const change = useChangePassword();
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [repeat, setRepeat] = useState('');
  const currentId = useId();
  const nextId = useId();
  const repeatId = useId();
  const tooShort = next.length > 0 && next.length < MIN_PASSWORD_LENGTH;
  const mismatch = repeat.length > 0 && repeat !== next;
  const ready = current.length > 0 && isValidPassword(next) && repeat === next;

  function handleSubmit(event: SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!ready) return;
    change.mutate(
      { current_password: current, new_password: next },
      {
        onSuccess: () => {
          setCurrent('');
          setNext('');
          setRepeat('');
        },
      },
    );
  }

  return (
    <Card title="Change password">
      <form className="form" onSubmit={handleSubmit}>
        <div className="field">
          <label htmlFor={currentId}>Current password</label>
          <input
            id={currentId}
            type="password"
            autoComplete="current-password"
            maxLength={MAX_PASSWORD_LENGTH}
            value={current}
            onChange={(event) => {
              setCurrent(event.target.value);
              change.reset();
            }}
          />
        </div>
        <div className="field">
          <label htmlFor={nextId}>New password</label>
          <input
            id={nextId}
            type="password"
            autoComplete="new-password"
            maxLength={MAX_PASSWORD_LENGTH}
            aria-describedby={`${nextId}-hint`}
            value={next}
            onChange={(event) => {
              setNext(event.target.value);
              change.reset();
            }}
          />
          <span id={`${nextId}-hint`} className={tooShort ? 'text-warn small' : 'muted small'}>
            At least {MIN_PASSWORD_LENGTH} characters. A few unrelated words make a good one.
          </span>
        </div>
        <div className="field">
          <label htmlFor={repeatId}>New password again</label>
          <input
            id={repeatId}
            type="password"
            autoComplete="new-password"
            maxLength={MAX_PASSWORD_LENGTH}
            value={repeat}
            onChange={(event) => {
              setRepeat(event.target.value);
              change.reset();
            }}
          />
          {mismatch ? <span className="text-warn small">The passwords do not match.</span> : null}
        </div>
        <div>
          <button type="submit" className="button" disabled={!ready || change.isPending}>
            {change.isPending ? 'Saving…' : 'Change password'}
          </button>
        </div>
        {change.isError ? (
          <p className="text-error small" role="alert">
            {change.error.message}
          </p>
        ) : null}
        {change.isSuccess ? (
          <p className="text-ok small" role="status">
            Password changed. Your other sessions have been signed out.
          </p>
        ) : null}
      </form>
    </Card>
  );
}

function Sessions() {
  const signOut = useSignOut();

  return (
    <Card title="Sessions">
      <p className="prose">
        Sessions last up to the limit your administrator set and end when you sign out. If you
        signed in on a shared or lost device, end every session at once.
      </p>
      <div className="inline-field">
        <button
          type="button"
          className="button button--secondary"
          disabled={signOut.isPending}
          onClick={() => {
            signOut.mutate(false);
          }}
        >
          Sign out
        </button>
        <button
          type="button"
          className="button button--secondary"
          disabled={signOut.isPending}
          onClick={() => {
            signOut.mutate(true);
          }}
        >
          Sign out everywhere
        </button>
      </div>
      {signOut.isError ? (
        <p className="text-error small" role="alert">
          {signOut.error.message}
        </p>
      ) : null}
    </Card>
  );
}

export function AccountPage() {
  const user = useCurrentUser().data;

  return (
    <>
      <PageHeader title="Your account" description="Your profile, password and sessions." />
      {user ? (
        <div className="grid">
          <Profile user={user} />
          <PasswordForm />
          <Sessions />
        </div>
      ) : null}
    </>
  );
}
