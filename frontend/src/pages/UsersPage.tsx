import { Fragment, type SubmitEvent, useId, useState } from 'react';

import { useCreateUser, useResetPassword, useUpdateUser, useUserAccounts } from '../api/admin';
import { useCurrentUser } from '../api/auth';
import type { UserAccount, UserRole } from '../api/types';
import { Card } from '../components/Card';
import { PageHeader } from '../components/PageHeader';
import {
  isValidPassword,
  isValidUsername,
  MAX_PASSWORD_LENGTH,
  MIN_PASSWORD_LENGTH,
  USERNAME_RULE,
} from '../lib/accounts';
import { formatNumber, formatUtc } from '../lib/format';
import { ROLES } from '../lib/labels';

const COLUMNS = 5;

function PasswordResetRow({ user, onClose }: { user: UserAccount; onClose: () => void }) {
  const reset = useResetPassword(user.id);
  const [password, setPassword] = useState('');
  const inputId = useId();

  function handleSubmit(event: SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    if (isValidPassword(password)) reset.mutate(password);
  }

  return (
    <tr className="row-details">
      <td colSpan={COLUMNS}>
        {reset.isSuccess ? (
          <p className="text-ok small" role="status">
            New password set for {user.username}; their sessions have been signed out.{' '}
            <button type="button" className="link small" onClick={onClose}>
              Close
            </button>
          </p>
        ) : (
          <form className="inline-form" onSubmit={handleSubmit}>
            <label htmlFor={inputId} className="muted small">
              New password for {user.username}
            </label>
            <input
              id={inputId}
              type="password"
              autoComplete="new-password"
              maxLength={MAX_PASSWORD_LENGTH}
              placeholder={`At least ${String(MIN_PASSWORD_LENGTH)} characters`}
              value={password}
              onChange={(event) => {
                setPassword(event.target.value);
              }}
            />
            <button
              type="submit"
              className="button button--small"
              disabled={!isValidPassword(password) || reset.isPending}
            >
              Set password
            </button>
            <button type="button" className="link small" onClick={onClose}>
              Cancel
            </button>
            {reset.isError ? (
              <span className="text-error small" role="alert">
                {reset.error.message}
              </span>
            ) : null}
          </form>
        )}
      </td>
    </tr>
  );
}

function UserRow({ user, isSelf }: { user: UserAccount; isSelf: boolean }) {
  const update = useUpdateUser(user.id);
  const [resetting, setResetting] = useState(false);
  const selfNote = isSelf ? 'You cannot change your own role or deactivate yourself' : undefined;

  return (
    <Fragment>
      <tr className={user.is_active ? undefined : 'is-muted'}>
        <td>
          <span className="mono">{user.username}</span>
          {isSelf ? <span className="muted small"> (you)</span> : null}
          <span className="muted small origin">
            {[user.full_name, user.email].filter(Boolean).join(' · ') || '—'}
          </span>
        </td>
        <td>
          <select
            aria-label={`Role of ${user.username}`}
            title={selfNote}
            value={user.role}
            disabled={isSelf || update.isPending}
            onChange={(event) => {
              update.mutate({ role: event.target.value as UserRole });
            }}
          >
            {ROLES.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </td>
        <td>
          <span className="pill" data-account={user.is_active ? 'active' : 'disabled'}>
            {user.is_active ? 'Active' : 'Deactivated'}
          </span>
        </td>
        <td className="mono nowrap small">
          {user.last_login_at ? formatUtc(user.last_login_at) : 'Never'}
        </td>
        <td className="nowrap">
          <button
            type="button"
            className="button button--secondary button--small"
            title={selfNote}
            disabled={isSelf || update.isPending}
            onClick={() => {
              update.mutate({ is_active: !user.is_active });
            }}
          >
            {user.is_active ? 'Deactivate' : 'Reactivate'}
          </button>{' '}
          <button
            type="button"
            className="button button--secondary button--small"
            aria-expanded={resetting}
            onClick={() => {
              setResetting((open) => !open);
            }}
          >
            Reset password
          </button>
        </td>
      </tr>
      {update.isError ? (
        <tr>
          <td colSpan={COLUMNS}>
            <p className="text-error small" role="alert">
              {update.error.message}
            </p>
          </td>
        </tr>
      ) : null}
      {resetting ? (
        <PasswordResetRow
          user={user}
          onClose={() => {
            setResetting(false);
          }}
        />
      ) : null}
    </Fragment>
  );
}

function NewUserForm() {
  const create = useCreateUser();
  const [username, setUsername] = useState('');
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [role, setRole] = useState<UserRole>('analyst');
  const [password, setPassword] = useState('');
  const ids = { username: useId(), name: useId(), email: useId(), role: useId(), pass: useId() };
  const ready = isValidUsername(username) && isValidPassword(password);

  function handleSubmit(event: SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!ready) return;
    create.mutate(
      {
        username,
        password,
        role,
        full_name: fullName.trim() || null,
        email: email.trim() || null,
      },
      {
        onSuccess: () => {
          setUsername('');
          setFullName('');
          setEmail('');
          setPassword('');
        },
      },
    );
  }

  return (
    <Card title="Add a user">
      <form className="form" onSubmit={handleSubmit}>
        <div className="field">
          <label htmlFor={ids.username}>User name</label>
          <input
            id={ids.username}
            type="text"
            autoComplete="off"
            spellCheck={false}
            maxLength={64}
            aria-describedby={`${ids.username}-hint`}
            value={username}
            onChange={(event) => {
              setUsername(event.target.value.toLowerCase());
              create.reset();
            }}
          />
          <span
            id={`${ids.username}-hint`}
            className={username && !isValidUsername(username) ? 'text-warn small' : 'muted small'}
          >
            {USERNAME_RULE}
          </span>
        </div>
        <div className="form__row">
          <div className="field">
            <label htmlFor={ids.name}>Full name</label>
            <input
              id={ids.name}
              type="text"
              maxLength={128}
              value={fullName}
              onChange={(event) => {
                setFullName(event.target.value);
              }}
            />
          </div>
          <div className="field">
            <label htmlFor={ids.email}>E-mail</label>
            <input
              id={ids.email}
              type="email"
              maxLength={255}
              value={email}
              onChange={(event) => {
                setEmail(event.target.value);
              }}
            />
          </div>
        </div>
        <div className="form__row">
          <div className="field">
            <label htmlFor={ids.role}>Role</label>
            <select
              id={ids.role}
              value={role}
              onChange={(event) => {
                setRole(event.target.value as UserRole);
              }}
            >
              {ROLES.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          </div>
          <div className="field">
            <label htmlFor={ids.pass}>Initial password</label>
            <input
              id={ids.pass}
              type="password"
              autoComplete="new-password"
              maxLength={MAX_PASSWORD_LENGTH}
              placeholder={`At least ${String(MIN_PASSWORD_LENGTH)} characters`}
              value={password}
              onChange={(event) => {
                setPassword(event.target.value);
              }}
            />
          </div>
        </div>
        <div>
          <button type="submit" className="button" disabled={!ready || create.isPending}>
            Add user
          </button>
        </div>
        {create.isError ? (
          <p className="text-error small" role="alert">
            {create.error.message}
          </p>
        ) : null}
        {create.isSuccess ? (
          <p className="text-ok small" role="status">
            Added {create.data.username}. Share the password with them over a separate channel.
          </p>
        ) : null}
      </form>
    </Card>
  );
}

function RoleGuide() {
  return (
    <Card title="Roles">
      <dl className="role-guide">
        {ROLES.map((option) => (
          <div key={option.value}>
            <dt>{option.label}</dt>
            <dd className="muted">{option.description}</dd>
          </div>
        ))}
      </dl>
    </Card>
  );
}

export function UsersPage() {
  const users = useUserAccounts();
  const me = useCurrentUser().data;
  const items = users.data ?? [];

  return (
    <>
      <PageHeader
        title="Users"
        description="Accounts and roles. Changes apply at once: deactivating a user or resetting their password ends their sessions. Every change is written to the audit log."
      />
      <div className="grid grid--wide">
        <Card
          title="Accounts"
          aside={users.data ? <span className="muted">{formatNumber(items.length)}</span> : null}
        >
          {users.isPending ? <p className="muted">Loading users…</p> : null}
          {users.isError ? <p className="text-error">Could not load users.</p> : null}
          {items.length > 0 ? (
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th scope="col">User</th>
                    <th scope="col">Role</th>
                    <th scope="col">Status</th>
                    <th scope="col">Last sign-in</th>
                    <th scope="col">
                      <span className="visually-hidden">Actions</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((user) => (
                    <UserRow key={user.id} user={user} isSelf={user.id === me?.id} />
                  ))}
                </tbody>
              </table>
            </div>
          ) : null}
        </Card>
        <div className="stack stack--flush">
          <NewUserForm />
          <RoleGuide />
        </div>
      </div>
    </>
  );
}
