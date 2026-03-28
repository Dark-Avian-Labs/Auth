import clsx from 'clsx';
import { useCallback, useEffect, useId, useRef, useState } from 'react';

export type FormSelectOption<T extends string = string> = {
  value: T;
  label: string;
};

type FormSelectProps<T extends string> = {
  id: string;
  value: T;
  options: FormSelectOption<T>[];
  onChange: (value: T) => void;
};

export function FormSelect<T extends string>({ id, value, options, onChange }: FormSelectProps<T>) {
  const listboxId = useId();
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);

  const current = options.find((o) => o.value === value) ?? options[0];

  const close = useCallback(() => setOpen(false), []);

  useEffect(() => {
    if (!open) return;
    const onDocPointer = (e: MouseEvent | PointerEvent) => {
      const el = rootRef.current;
      if (!el || el.contains(e.target as Node)) return;
      close();
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') close();
    };
    document.addEventListener('pointerdown', onDocPointer);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('pointerdown', onDocPointer);
      document.removeEventListener('keydown', onKey);
    };
  }, [open, close]);

  return (
    <div ref={rootRef} className="relative">
      <button
        ref={triggerRef}
        type="button"
        id={id}
        className="form-input flex w-full cursor-pointer items-center justify-between gap-2 text-left outline-none"
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-controls={listboxId}
        onClick={() => setOpen((o) => !o)}
        onKeyDown={(e) => {
          if (e.key === 'ArrowDown' || e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            setOpen(true);
          }
        }}
      >
        <span className="min-w-0 truncate">{current?.label}</span>
        <svg
          className={clsx('text-muted h-4 w-4 shrink-0 transition-transform', open && 'rotate-180')}
          viewBox="0 0 20 20"
          fill="currentColor"
          aria-hidden
        >
          <path
            fillRule="evenodd"
            d="M5.23 7.21a.75.75 0 011.06.02L10 11.168l3.71-3.94a.75.75 0 111.08 1.04l-4.25 4.5a.75.75 0 01-1.08 0l-4.25-4.5a.75.75 0 01.02-1.06z"
            clipRule="evenodd"
          />
        </svg>
      </button>
      {open ? (
        <ul
          id={listboxId}
          role="listbox"
          aria-labelledby={id}
          className="border-glass-border bg-glass-hover/95 absolute top-full right-0 left-0 z-[var(--z-dropdown)] mt-1 max-h-60 overflow-auto rounded-lg border p-1 shadow-[var(--shadow-panel)] backdrop-blur-md"
        >
          {options.map((opt) => (
            <li key={opt.value} role="presentation">
              <button
                type="button"
                role="option"
                aria-selected={opt.value === value}
                className={clsx(
                  'user-menu-item text-left',
                  opt.value === value && 'bg-glass-active text-foreground',
                )}
                onClick={() => {
                  onChange(opt.value);
                  close();
                  triggerRef.current?.focus();
                }}
              >
                {opt.label}
              </button>
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}
