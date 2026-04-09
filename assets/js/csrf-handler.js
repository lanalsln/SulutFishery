/**
 * CSRF Handler
 * Auto-append CSRF token ke AJAX requests
 */

// Get CSRF token from DOM
function getCSRFToken() {
  const token = document.querySelector('[name="csrf_token"]');
  return token ? token.value : "";
}

// Escape HTML entities (XSS protection)
function escapeHTML(text) {
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}

// Add CSRF token to FormData
function addCSRFToFormData(formData) {
  formData.append("csrf_token", getCSRFToken());
  return formData;
}

// Sanitize input (client-side)
function sanitizeInput(input) {
  return escapeHTML(input).trim();
}

// Show alert/notification
function showAlert(message, type = "error") {
  const alertDiv = document.createElement("div");
  alertDiv.className = `alert alert-${type}`;
  alertDiv.textContent = message;

  const container = document.querySelector(".form-container") || document.body;
  container.insertBefore(alertDiv, container.firstChild);

  // Auto-remove after 5 seconds
  setTimeout(() => alertDiv.remove(), 5000);
}
