"use client";
import { create } from "zustand";
export const useAuthStore = create<{
  revealPassword: boolean;
  togglePassword: () => void;
}>((set) => ({
  revealPassword: false,
  togglePassword: () =>
    set((state) => ({ revealPassword: !state.revealPassword })),
}));
