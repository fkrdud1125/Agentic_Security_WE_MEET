"use strict";
// Runs before CSS without weakening the dashboard's script-src policy.
try {
  const theme = localStorage.getItem("vibescan-theme");
  if (["light", "dark"].includes(theme)) document.documentElement.dataset.theme = theme;
} catch { /* Private browsing still follows the system theme. */ }
