import { forwardRef, type InputHTMLAttributes } from 'react';

interface InputProps extends InputHTMLAttributes<HTMLInputElement> {
  readOnlyStyle?: boolean;
}

export const Input = forwardRef<HTMLInputElement, InputProps>(function Input(
  { readOnlyStyle, className, ...props },
  ref,
) {
  const classes = ['form-input'];
  const useReadOnlyClass = Boolean(readOnlyStyle);
  if (useReadOnlyClass) {
    classes.push('form-input-readonly');
  }
  if (className) {
    classes.push(className);
  }
  return (
    <input
      {...props}
      ref={ref}
      readOnly={props.readOnly}
      className={classes.join(' ')}
    />
  );
});
