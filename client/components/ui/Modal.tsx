import type { MouseEvent, ReactNode } from 'react';

interface ModalProps {
  open: boolean;
  onClose: () => void;
  children: ReactNode;
  className?: string;
}

export function Modal({ open, onClose, children, className }: ModalProps) {
  if (!open) {
    return null;
  }

  const modalClass = ['modal'];
  if (className) {
    modalClass.push(className);
  }

  const stopPropagation = (event: MouseEvent<HTMLDivElement>) => {
    event.stopPropagation();
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className={modalClass.join(' ')} onClick={stopPropagation}>
        {children}
      </div>
    </div>
  );
}
