import clsx from 'clsx';
import type { HTMLAttributes } from 'react';

export function MaterialSymbol({
  name,
  className,
  filled = false,
  style,
  'aria-label': ariaLabel,
  ...rest
}: {
  name: string;
  filled?: boolean;
} & Omit<HTMLAttributes<HTMLSpanElement>, 'children'>) {
  const decorative = ariaLabel == null || String(ariaLabel).trim() === '';
  return (
    <span
      className={clsx('material-symbol-rounded', className)}
      style={{
        fontVariationSettings: `'FILL' ${filled ? 1 : 0}, 'wght' 400, 'GRAD' 0, 'opsz' 24`,
        ...style,
      }}
      {...rest}
      {...(decorative ? null : { 'aria-label': ariaLabel })}
      aria-hidden={decorative ? true : undefined}
    >
      {name}
    </span>
  );
}
