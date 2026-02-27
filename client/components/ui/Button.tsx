import {
  cloneElement,
  isValidElement,
  type AnchorHTMLAttributes,
  type ButtonHTMLAttributes,
  type ReactElement,
} from 'react';

type ButtonVariant = 'accent' | 'secondary' | 'danger';

function variantClass(variant: ButtonVariant): string {
  switch (variant) {
    case 'accent':
      return 'btn-accent';
    case 'danger':
      return 'btn-danger';
    default:
      return 'btn-secondary';
  }
}

interface BaseProps {
  variant?: ButtonVariant;
  className?: string;
  asChild?: boolean;
}

interface ButtonProps
  extends
    Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'className'>,
    BaseProps {
  href?: never;
}

interface LinkButtonProps
  extends
    Omit<AnchorHTMLAttributes<HTMLAnchorElement>, 'className'>,
    BaseProps {
  href: string;
}

function composeClassName(variant: ButtonVariant, className?: string): string {
  const classes = ['btn', variantClass(variant)];
  if (className) {
    classes.push(className);
  }
  return classes.join(' ');
}

export function Button(props: ButtonProps | LinkButtonProps) {
  const { children, variant = 'secondary', className, asChild } = props;
  const classes = composeClassName(variant, className);

  if (asChild) {
    if (!isValidElement(children)) {
      return null;
    }

    const {
      children: _children,
      variant: _variant,
      className: _className,
      asChild: _asChild,
      ...childProps
    } = props as ButtonProps;

    const childClassName = (children as ReactElement<{ className?: string }>)
      .props.className;
    const mergedClassName = [classes, childClassName].filter(Boolean).join(' ');

    return cloneElement(children as ReactElement, {
      ...childProps,
      className: mergedClassName,
    });
  }

  if ('href' in props && props.href) {
    const {
      href,
      variant: _variant,
      className: _className,
      asChild: _asChild,
      ...anchorProps
    } = props;
    return (
      <a href={href} className={classes} {...anchorProps}>
        {children}
      </a>
    );
  }

  const {
    variant: _variant,
    className: _className,
    ...buttonProps
  } = props as ButtonProps;
  return (
    <button type="button" {...buttonProps} className={classes}>
      {children}
    </button>
  );
}
