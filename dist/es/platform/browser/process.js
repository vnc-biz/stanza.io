/* eslint-disable @typescript-eslint/ban-types */
export function nextTick(callback, ...args) {
    queueMicrotask(() => callback(...args));
}
