/**
 * [CR-009] 自定义确认对话框组件
 * 替代浏览器原生的 window.confirm()，提供一致的 UI 体验
 */
import { createPortal } from "react-dom";
import { ExclamationTriangleIcon, XMarkIcon } from "@heroicons/react/24/outline";
import { useTranslation } from "react-i18next";
import { useEffect, useRef } from "react";

export interface ConfirmDialogProps {
  /** 是否显示对话框 */
  isOpen: boolean;
  /** 对话框标题 */
  title: string;
  /** 确认消息（支持 React 节点） */
  message: React.ReactNode;
  /** 确认按钮文本（可选） */
  confirmText?: string;
  /** 取消按钮文本（可选） */
  cancelText?: string;
  /** 确认按钮样式变体 */
  variant?: "danger" | "warning" | "primary";
  /** 点击确认回调 */
  onConfirm: () => void;
  /** 点击取消回调 */
  onCancel: () => void;
}

export function ConfirmDialog({
  isOpen,
  title,
  message,
  confirmText,
  cancelText,
  variant = "danger",
  onConfirm,
  onCancel,
}: ConfirmDialogProps) {
  const { t } = useTranslation();
  const confirmButtonRef = useRef<HTMLButtonElement>(null);

  const dialogRef = useRef<HTMLDivElement>(null);
  const cancelButtonRef = useRef<HTMLButtonElement>(null);

  // 聚焦确认按钮、处理 Escape 键和焦点陷阱
  useEffect(() => {
    if (!isOpen) return;

    // 聚焦确认按钮
    setTimeout(() => confirmButtonRef.current?.focus(), 50);

    const handleKeyDown = (e: KeyboardEvent) => {
      // Escape 键关闭对话框
      if (e.key === "Escape") {
        e.preventDefault();
        onCancel();
        return;
      }

      // 焦点陷阱：Tab 键只在对话框内循环
      if (e.key === "Tab") {
        const focusableElements = dialogRef.current?.querySelectorAll<HTMLElement>(
          'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
        );
        if (!focusableElements || focusableElements.length === 0) return;

        const firstElement = focusableElements[0];
        const lastElement = focusableElements[focusableElements.length - 1];

        if (e.shiftKey) {
          // Shift+Tab: 如果焦点在第一个元素，循环到最后一个
          if (document.activeElement === firstElement) {
            e.preventDefault();
            lastElement.focus();
          }
        } else {
          // Tab: 如果焦点在最后一个元素，循环到第一个
          if (document.activeElement === lastElement) {
            e.preventDefault();
            firstElement.focus();
          }
        }
      }
    };

    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [isOpen, onCancel]);

  if (!isOpen) return null;

  // 根据变体选择颜色
  const variantStyles = {
    danger: {
      icon: "text-red-400",
      iconBg: "bg-red-500/20",
      button: "bg-red-600 hover:bg-red-700 focus:ring-red-500",
    },
    warning: {
      icon: "text-yellow-400",
      iconBg: "bg-yellow-500/20",
      button: "bg-yellow-600 hover:bg-yellow-700 focus:ring-yellow-500",
    },
    primary: {
      icon: "text-brand",
      iconBg: "bg-brand/20",
      button: "bg-brand hover:bg-brand-dark focus:ring-brand",
    },
  };

  const styles = variantStyles[variant];

  return createPortal(
    <div
      className="fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4"
      onClick={onCancel}
    >
      <div
        ref={dialogRef}
        role="alertdialog"
        aria-modal="true"
        aria-labelledby="confirm-dialog-title"
        aria-describedby="confirm-dialog-message"
        className="bg-slate-900 rounded-2xl border border-white/10 w-full max-w-sm animate-scale-in"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="p-4 border-b border-white/10 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className={`p-2 rounded-full ${styles.iconBg}`}>
              <ExclamationTriangleIcon className={`w-5 h-5 ${styles.icon}`} />
            </div>
            <h3 id="confirm-dialog-title" className="text-lg font-semibold text-white">
              {title}
            </h3>
          </div>
          <button
            onClick={onCancel}
            className="p-1 rounded-lg hover:bg-white/10 text-slate-400 transition-colors"
            aria-label={t("common.close")}
          >
            <XMarkIcon className="h-5 w-5" />
          </button>
        </div>

        {/* Content */}
        <div id="confirm-dialog-message" className="p-4">
          <div className="text-slate-300 text-sm">
            {message}
          </div>
        </div>

        {/* Actions */}
        <div className="p-4 border-t border-white/10 flex justify-end gap-3">
          <button
            onClick={onCancel}
            className="px-4 py-2 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300 text-sm transition-colors focus:outline-none focus:ring-2 focus:ring-white/20"
          >
            {cancelText || t("common.cancel")}
          </button>
          <button
            ref={confirmButtonRef}
            onClick={onConfirm}
            className={`px-4 py-2 rounded-lg text-white text-sm transition-colors focus:outline-none focus:ring-2 ${styles.button}`}
          >
            {confirmText || t("common.confirm")}
          </button>
        </div>
      </div>
    </div>,
    document.body
  );
}
