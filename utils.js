// utils.js
export function isValidProxy(proxy) {
  if (!proxy) return false;
  const proxyRegex = /^(\d{1,3}\.){3}\d{1,3}:\d{1,5}(:.+:.+)?$/;
  if (!proxyRegex.test(proxy)) return false;
  
  const ip = proxy.split(':')[0];
  const ipParts = ip.split('.');
  return ipParts.every(part => {
    const num = parseInt(part, 10);
    return num >= 0 && num <= 255;
  });
}

export function showToast(message, type = 'success') {
  const toastId = 'toast-' + Date.now();
  const toastHTML = `
    <div id="${toastId}" class="toast show align-items-center text-bg-${type}" role="alert">
      <div class="d-flex">
        <div class="toast-body">
          <i class="fas ${type === 'success' ? 'fa-check-circle' : 'fa-exclamation-circle'} me-2"></i>
          ${message}
        </div>
        <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
      </div>
    </div>
  `;
  
  const container = document.querySelector('.toast-container') || document.body;
  container.insertAdjacentHTML('beforeend', toastHTML);

  setTimeout(() => {
    const toast = document.getElementById(toastId);
    if (toast) toast.remove();
  }, 5000);
}