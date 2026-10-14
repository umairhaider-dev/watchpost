import { useId } from 'react';

import { useAssignableUsers } from '../api/investigation';

interface AssigneeSelectProps {
  label: string;
  value: number | null;
  disabled?: boolean;
  onChange: (assigneeId: number | null) => void;
}

/** Pick an analyst or admin; "Unassigned" clears the owner. */
export function AssigneeSelect({ label, value, disabled = false, onChange }: AssigneeSelectProps) {
  const users = useAssignableUsers();
  const id = useId();

  return (
    <div className="inline-field">
      <label htmlFor={id} className="muted small">
        {label}
      </label>
      <select
        id={id}
        value={value === null ? '' : String(value)}
        disabled={disabled || users.isPending}
        onChange={(event) => {
          onChange(event.target.value ? Number(event.target.value) : null);
        }}
      >
        <option value="">Unassigned</option>
        {users.data?.map((user) => (
          <option key={user.id} value={user.id}>
            {user.full_name ? `${user.full_name} (${user.username})` : user.username}
          </option>
        ))}
      </select>
    </div>
  );
}
