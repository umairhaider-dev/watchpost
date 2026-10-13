import type { ReactNode } from 'react';

interface CardProps {
  title: string;
  aside?: ReactNode;
  children: ReactNode;
}

export function Card({ title, aside, children }: CardProps) {
  return (
    <section className="card" aria-label={title}>
      <header className="card__header">
        <h2 className="card__title">{title}</h2>
        {aside}
      </header>
      <div className="card__body">{children}</div>
    </section>
  );
}
