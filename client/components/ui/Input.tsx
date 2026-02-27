import { forwardRef, type InputHTMLAttributes } from 'react';

interface InputProps extends InputHTMLAttributes<HTMLInputElement> {
  readOnlyStyle?: boolean;
}

export const Input = forwardRef<HTMLInputElement, InputProps>(function Input(
  { readOnlyStyle, className, ...props },
  ref,
) {
  const classes = ['form-input'];
  const isReadOnly = Boolean(props.readOnly || readOnlyStyle);
  if (isReadOnly) {
    classes.push('form-input-readonly');
  }
  if (className) {
    classes.push(className);
  }
  return (
    <input
      {...props}
      ref={ref}
      readOnly={isReadOnly}
      className={classes.join(' ')}
    />
  );
});
