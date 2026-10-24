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

  // Make entire FAQ card clickable (including answer body and outer card bounds)
  const faqItems = document.querySelectorAll(".faq-item");
  faqItems.forEach(details => {
    details.addEventListener("click", (e) => {
      // Native <summary> click already toggles <details>; avoid double-toggling
      if (e.target.closest("summary")) {
        return;
      }
      // Do not toggle if user is highlighting/selecting text or clicking a link
      const selection = window.getSelection ? window.getSelection().toString() : "";
      if (selection.length > 0 || e.target.closest("a, button")) {
        return;
      }
      details.open = !details.open;
    });
  });
});

