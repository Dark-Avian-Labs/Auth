import type { InputHTMLAttributes, Ref } from 'react';

interface InputProps extends InputHTMLAttributes<HTMLInputElement> {
  readOnlyStyle?: boolean;
  ref?: Ref<HTMLInputElement>;
}

export function Input({ readOnlyStyle, className, ref, ...props }: InputProps) {
  const classes = ['form-input'];
  const useReadOnlyClass = Boolean(readOnlyStyle);
  if (useReadOnlyClass) {
    classes.push('form-input-readonly');
  }
  if (className) {
    classes.push(className);
  }
  return <input {...props} ref={ref} readOnly={props.readOnly} className={classes.join(' ')} />;
}
