import { useId } from 'react';

import type { UiStyle } from '../../context/ThemeContext';

type ThemeRadioGroupProps = {
  uiStyle: UiStyle;
  setUiStyle: (style: UiStyle) => void;
};

export function ThemeRadioGroup({ uiStyle, setUiStyle }: ThemeRadioGroupProps) {
  const themeGroupLabelId = useId();

  return (
    <div role="radiogroup" aria-labelledby={themeGroupLabelId}>
      <div
        id={themeGroupLabelId}
        className="text-muted border-glass-border mt-1 border-t px-3 pt-2 pb-1 text-xs font-semibold tracking-wide uppercase"
      >
        Theme
      </div>
      <button
        type="button"
        className="user-menu-item text-left"
        role="menuitemradio"
        aria-checked={uiStyle === 'prism'}
        onClick={() => setUiStyle('prism')}
      >
        Prism
      </button>
      <button
        type="button"
        className="user-menu-item text-left"
        role="menuitemradio"
        aria-checked={uiStyle === 'shadow'}
        onClick={() => setUiStyle('shadow')}
      >
        Shadow
      </button>
    </div>
  );
}
