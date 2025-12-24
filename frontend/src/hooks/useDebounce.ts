import { useRef, useCallback } from "react";

/**
 * M22 修复: 防抖 Hook - 防止快速重复点击
 *
 * @param callback - 要防抖的回调函数
 * @param delay - 防抖延迟时间（毫秒），默认 300ms
 * @returns 防抖后的回调函数
 */
export function useDebouncedCallback<T extends (...args: unknown[]) => unknown>(
  callback: T,
  delay: number = 300
): T {
  const lastCallTime = useRef<number>(0);
  const pendingRef = useRef<boolean>(false);

  return useCallback(
    ((...args: Parameters<T>) => {
      const now = Date.now();

      // 如果距离上次调用时间太短，忽略本次调用
      if (now - lastCallTime.current < delay) {
        return;
      }

      // 如果已经有一个调用正在处理中，忽略
      if (pendingRef.current) {
        return;
      }

      lastCallTime.current = now;

      // 对于异步函数，跟踪 pending 状态
      const result = callback(...args);
      if (result instanceof Promise) {
        pendingRef.current = true;
        result.finally(() => {
          pendingRef.current = false;
        });
      }

      return result;
    }) as T,
    [callback, delay]
  );
}

/**
 * 简单的节流函数（非 Hook 版本）
 * 用于事件处理器
 */
export function throttle<T extends (...args: unknown[]) => void>(
  func: T,
  limit: number
): T {
  let inThrottle = false;

  return ((...args: Parameters<T>) => {
    if (!inThrottle) {
      func(...args);
      inThrottle = true;
      setTimeout(() => {
        inThrottle = false;
      }, limit);
    }
  }) as T;
}

export default useDebouncedCallback;
