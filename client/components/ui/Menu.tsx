import clsx from 'clsx';
import type { ReactNode } from 'react';

interface MenuProps {
  children: ReactNode;
  className?: string;
}

export function Menu({ children, className }: MenuProps) {
  return (
    <div className={clsx('user-menu', 'glass-surface', className)}>
      {children}
    </div>
  );
}
