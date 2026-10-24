/**
 * FileGuard - Core Global Utilities
 */
document.addEventListener("DOMContentLoaded", () => {
  // Auto-dismiss alerts after 5 seconds if desired
  const alerts = document.querySelectorAll(".alert-dismissible");
  alerts.forEach(alert => {
    setTimeout(() => {
      alert.style.transition = "opacity 0.5s ease";
      alert.style.opacity = "0";
      setTimeout(() => alert.remove(), 500);
    }, 5000);
  });
});

