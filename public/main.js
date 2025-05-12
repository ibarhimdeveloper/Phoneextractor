const socket = io({
  reconnection: true,
  reconnectionAttempts: Infinity,
  reconnectionDelay: 1000,
  reconnectionDelayMax: 5000,
  timeout: 20000,
  transports: ['websocket'] // Force WebSocket transport
});

// Add connection status logging
socket.on('connect', () => {
  console.log('Connected to server with socket ID:', socket.id);
  socketId = socket.id;
});

socket.on('disconnect', () => {
  console.log('Disconnected from server');
});

socket.on('connect_error', (err) => {
  console.error('Socket connection error:', err);
  showToast('Connection error - trying to reconnect...', 'warning');
});

socket.on('extraction-result', (data) => {
  const tbody = document.getElementById('resultTableBody');
  const row = document.createElement('tr');
  row.setAttribute('data-number', data.phone);
  row.innerHTML = `
    <td>${tbody.children.length + 1}</td>
    <td>${data.phone}</td>
    <td>${data.source}</td>
    <td>${data.type}</td>
    <td>${data.country}</td>
    <td>${data.carrier}</td>
    <td class="text-success">${data.status}</td>
  `;
  tbody.appendChild(row);

  document.getElementById('resultCount').textContent = `${tbody.children.length} numbers`;
});

// Socket events for extraction
socket.on('phoneNumber', (data) => {
  if (!isStopped && data?.number && !existingNumbers.has(data.number)) {
    existingNumbers.add(data.number);
    const { number, source } = data;
    showNumber(number, source);
    extractedNumbers.push({ number, source });
    updateResultCount();
  }
});

socket.on('progress', (percent) => {
  if (elements.extractionProgress) {
    elements.extractionProgress.style.width = `${percent}%`;
    if (elements.statusText) {
      elements.statusText.textContent = `Extracting... ${percent}%`;
    }
  }
});

let currentUser = null;
let socketId = null;
socket.on('connect', () => {
  console.log('Connected to server with socket ID:', socket.id);
  socketId = socket.id;
  // Refresh credentials if in admin panel
  if (document.getElementById('adminPanel')?.style.display === 'block') {
    fetchAndDisplayCredentials();
  }
});
let isStopped = false;
let extractedNumbers = [];
let existingNumbers = new Set();
let isAuthenticated = false;

// DOM Elements
const elements = {
  extractBtn: document.getElementById('extractBtn'),
  extractForm: document.getElementById('extractForm'),
  stopBtn: document.getElementById('stopBtn'),
  signInBtn: document.getElementById('signInBtn'),
  signInForm: document.getElementById('signInForm'),
  usernameInput: document.getElementById('usernameInput'),
  passwordInput: document.getElementById('passwordInput'),
  adminLoginForm: document.getElementById('adminLoginForm'),
  adminLoginBtn: document.getElementById('adminLoginBtn'),
  adminLogoutBtn: document.getElementById('adminLogoutBtn'),
  credentialsList: document.getElementById('credentialsList'),
  adminPanel: document.getElementById('adminPanel'),
  sourceSelect: document.getElementById('source'),
  searchTermInput: document.getElementById('searchTerm'),
  locationInput: document.getElementById('location'),
  pagesInput: document.getElementById('pages'),
  customUrlInput: document.getElementById('customUrl'),
  depthInput: document.getElementById('depthPages'),
  depthValue: document.getElementById('depthValue'),
  resultTableBody: document.getElementById('resultTableBody'),
  resultCount: document.getElementById('resultCount'),
  statusText: document.getElementById('statusText'),
  extractionProgress: document.getElementById('extractionProgress'),
  saveToNotepad: document.getElementById('saveToNotepad')
};

// Initialize the app
document.addEventListener('DOMContentLoaded', async () => {
  await checkAuth();
  setupEventListeners();
  
  // Initialize form visibility
  handleFormVisibility();
  
  // Initialize depth slider
  if (elements.depthInput) {
    elements.depthInput.addEventListener('input', updateDepthValue);
    updateDepthValue();
  }
  
  // Initialize extraction form
  initExtractionForm();
});

// Check authentication status
async function checkAuth() {
  try {
    const response = await fetch('/check-auth', {
      credentials: 'include'
    });

    if (response.ok) {
      const data = await response.json();
      if (data.success && data.user) {
        currentUser = data.user;
        updateUI(); // e.g. show/hide admin panel
        return true;
      }
    }
    updateUI(); // unauthenticated state
    return false;
  } catch (err) {
    console.error('Auth check failed:', err);
    updateUI();
    return false;
  }
}

// Update UI based on auth state
function updateUI() {
  const isLoggedIn = !!currentUser;
  elements.extractBtn.disabled = !isLoggedIn;
  elements.stopBtn.disabled = !isLoggedIn;

  elements.signInBtn.innerHTML = isLoggedIn
    ? `<i class="fas fa-sign-out-alt me-2"></i> Sign Out (${currentUser.username})`
    : '<i class="fas fa-sign-in-alt me-2"></i> Sign In';
}

// Setup event listeners
function setupEventListeners() {
  // Sign in/out
  elements.signInBtn?.addEventListener('click', async () => {
    if (currentUser) {
      await handleSignOut();
    } else {
      new bootstrap.Modal(document.getElementById('signInModal')).show();
    }
  });
}
  // Sign in form submission
  elements.signInForm?.addEventListener('submit', async (e) => {
    e.preventDefault();
    await handleUserLogin(e);
  });

  // Admin login
  elements.adminLoginBtn?.addEventListener('click', handleAdminLogin);

  // Admin logout
  elements.adminLogoutBtn?.addEventListener('click', handleAdminLogout);
  
  // Add these if missing
  elements.extractForm?.addEventListener('submit', handleFormSubmit);
  elements.stopBtn?.addEventListener('click', stopExtraction);

// Handle user login
async function handleUserLogin(e) {
  const username = elements.usernameInput.value;
  const password = elements.passwordInput.value;

  try {
    const response = await fetch('/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ username, password })
    });

    const data = await response.json();
    if (data.success) {
      currentUser = { username: data.username };
      showToast('Signed in successfully!', 'success');
      updateUI();
      bootstrap.Modal.getInstance(document.getElementById('signInModal')).hide();
    } else {
      showToast(data.error || 'Invalid credentials', 'danger');
    }
  } catch (err) {
    showToast('Login failed', 'danger');
    console.error('Login error:', err);
  }
}

// Handle sign out
async function handleSignOut() {
  try {
    await fetch('/logout', {
      method: 'POST',
      credentials: 'include'
    });

    currentUser = null;
    updateUI();
    showToast('Signed out successfully', 'success');
  } catch (err) {
    showToast('Logout failed', 'danger');
    console.error('Logout error:', err);
  }
}

// Admin login
async function handleAdminLogin() {
  const password = document.getElementById('adminPassword').value;

  try {
    const response = await fetch('/admin-login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ password })
    });

    const data = await response.json();
    if (data.success) {
      elements.adminLoginForm.style.display = 'none';
      elements.adminPanel.style.display = 'block';
      await fetchAndDisplayCredentials();
      showToast('Admin login successful', 'success');
    } else {
      throw new Error(data.error || 'Wrong password');
    }
  } catch (err) {
    showToast(err.message, 'danger');
    console.error('Admin login error:', err);
  }
}

// Update handleAdminLogout function
async function handleAdminLogout() {
  try {
    await fetch('/logout', {
      method: 'POST',
      credentials: 'include'
    });
    elements.adminPanel.style.display = 'none';
    elements.adminLoginForm.style.display = 'block';
    document.getElementById('adminPassword').value = '';
    
    // Clear credentials list
    const tbody = document.getElementById('credentialsList');
    tbody.innerHTML = `
      <tr>
        <td colspan="5" class="text-center py-4 text-muted">
          No credentials generated yet
        </td>
      </tr>
    `;
    showToast('Admin logged out', 'info');
  } catch (err) {
    showToast('Logout failed', 'danger');
    console.error('Admin logout error:', err);
  }
}

// Fetch and display credentials
async function fetchAndDisplayCredentials() {
  try {
    const response = await fetch('/get-credentials', {
      credentials: 'include'
    });
    const data = await response.json();

    if (!data.success) throw new Error(data.error || 'Failed to fetch credentials');

    const tbody = document.getElementById('credentialsList');
    tbody.innerHTML = '';

    if (data.credentials.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="6" class="text-center py-4 text-muted">
            No credentials generated yet
          </td>
        </tr>
      `;
      return;
    }

    data.credentials.forEach(cred => {
      const row = document.createElement('tr');
      const expiresAt = cred.expires_at ? new Date(cred.expires_at) : null;
      const isActive = !cred.revoked && (!expiresAt || expiresAt > new Date());

      row.innerHTML = `
        <td>${cred.username}</td>
        <td>********</td>
        <td>${new Date(cred.created_at).toLocaleDateString()}</td>
        <td>${expiresAt ? expiresAt.toLocaleDateString() : 'Never'}</td>
        <td>${isActive ? 'Active' : 'Inactive'}</td>
        <td>
          <button class="btn btn-sm ${isActive ? 'btn-danger' : 'btn-success'}" 
            data-action="toggle" data-username="${cred.username}">
            ${isActive ? 'Revoke' : 'Activate'}
          </button>
          <button class="btn btn-sm btn-primary ms-1" 
            data-action="extend" data-username="${cred.username}">
            <i class="fas fa-plus"></i> Extend
          </button>
        </td>
      `;
      tbody.appendChild(row);
    });

    document.querySelectorAll('[data-action="toggle"]').forEach(btn => {
      btn.addEventListener('click', () => toggleCredential(btn.dataset.username));
    });

    document.querySelectorAll('[data-action="extend"]').forEach(btn => {
      btn.addEventListener('click', () => extendCredential(btn.dataset.username));
    });

  } catch (err) {
    showToast(err.message, 'danger');
    console.error('Credentials fetch error:', err);
  }
}

// Toggle credential status
async function toggleCredential(username) {
  try {
    const btn = document.querySelector(`[data-action="toggle"][data-username="${username}"]`);
    const revoke = btn.textContent.trim() === 'Revoke';

    const response = await fetch('/toggle-credential', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ username, revoke })
    });

    const data = await response.json();
    if (data.success) {
      showToast(`Credential ${username} ${revoke ? 'revoked' : 'activated'}`, 'success');
      await fetchAndDisplayCredentials();
    } else {
      throw new Error(data.error || 'Failed to toggle credential');
    }
  } catch (err) {
    showToast(err.message, 'danger');
    console.error('Toggle credential error:', err);
  }
}

// Extend credential expiry
async function extendCredential(username) {
  try {
    const response = await fetch('/extend-credential', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ username, days: 7 })
    });

    const data = await response.json();
    if (data.success) {
      showToast(`Extended ${username} by 7 days`, 'success');
      await fetchAndDisplayCredentials();
    } else {
      throw new Error(data.error || 'Failed to extend credential');
    }
  } catch (err) {
    showToast(err.message, 'danger');
    console.error('Extend credential error:', err);
  }
}

// Generate new credentials
document.getElementById('generateCredentialsBtn').addEventListener('click', async () => {
  const username = document.getElementById('generateUsername').value;
  const tableBody = document.getElementById('credentialsList');

  try {
    const response = await fetch('/generate-credentials', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username })
    });

    const data = await response.json();
    if (data.success) {
      const newRow = document.createElement('tr');
      newRow.innerHTML = `
        <td>${data.username}</td>
        <td>${data.password}</td>
        <td>${data.expires || 'N/A'}</td>
        <td><span class="badge bg-success">Active</span></td>
        <td><button class="btn btn-sm btn-outline-danger">Revoke</button></td>
      `;
      tableBody.innerHTML = ''; // Remove "No credentials" row if it exists
      tableBody.appendChild(newRow);
    } else {
      alert('Error generating credentials');
    }
  } catch (err) {
    console.error('Request failed:', err);
    alert('Failed to connect to server or parse response.');
  }
});

// Show toast notification
function showToast(message, type = 'success') {
  const toastId = 'toast-' + Date.now();
  const toastHTML = `
    <div id="${toastId}" class="toast show align-items-center text-bg-${type}" role="alert" aria-live="assertive" aria-atomic="true">
      <div class="d-flex">
        <div class="toast-body">
          <i class="fas ${type === 'success' ? 'fa-check-circle' : 'fa-exclamation-circle'} me-2"></i>
          ${message}
        </div>
        <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
      </div>
    </div>
  `;

  const container = document.querySelector('.toast-container') || document.body;
  container.insertAdjacentHTML('beforeend', toastHTML);

  setTimeout(() => {
    const toast = document.getElementById(toastId);
    if (toast) {
      toast.classList.remove('show');
      setTimeout(() => toast.remove(), 300);
    }
  }, 5000);
}

// Initialize admin panel when modal is shown
if (document.getElementById('adminModal')) {
  document.getElementById('adminModal').addEventListener('show.bs.modal', () => {
    elements.adminLoginForm.style.display = 'block';
    elements.adminPanel.style.display = 'none';
    document.getElementById('adminPassword').value = '';
  });
}

const apiMap = { 
  yellowpages: '/scrape-yellowpages',
  yelp: '/scrape-yelp',
  personal: '/scrape-personal',
  custom: '/scrape-custom',
  global: '/scrape-global',
  whitepages: '/scrape-whitepages',
  linkedin: '/scrape-linkedin',
  facebook: '/scrape-facebook',
  truepeoplesearch: '/scrape-truepeoplesearch',
  anywho: '/scrape-anywho',
  spokeo: '/scrape-spokeo',
  fastpeoplesearch: '/scrape-fastpeoplesearch',
  411: '/scrape-411',
  usphonebook: '/scrape-usphonebook',
  radaris: '/scrape-radaris',
  zabasearch: '/scrape-zabasearch',
  peoplefinders: '/scrape-peoplefinders',
  peekyou: '/scrape-peekyou',
  thatsthem: '/scrape-thatsthem',
  addresses: '/scrape-addresses',
  pipl: '/scrape-pipl',
  manta: '/scrape-manta',
  bbb: '/scrape-bbb',
  hotfrog: '/scrape-hotfrog',
  foursquare: '/scrape-foursquare',
  brownbook: '/scrape-brownbook',
  cityfos: '/scrape-cityfos',
  cylex: '/scrape-cylex',
  merchantcircle: '/scrape-merchantcircle',
  localstack: '/scrape-localstack'
};

// Initialize form visibility and depth slider
handleFormVisibility();
if (elements.depthInput) {
  elements.depthInput.addEventListener('input', updateDepthValue);
  updateDepthValue();
}


socket.on('phoneNumber', (data) => {
  if (!isStopped && data?.number && !existingNumbers.has(data.number)) {
    existingNumbers.add(data.number);
    const { number, source } = data;
    showNumber(number, source);
    extractedNumbers.push({ number, source });
    updateResultCount();
  }
});

socket.on('progress', (percent) => {
  if (extractionProgress) {
    extractionProgress.style.width = `${percent}%`;
  }
});

// Functions
function handleFormVisibility() {
  const sourceSelect = document.getElementById('source');
  const searchTermLabel = document.getElementById('searchTermLabel');
  const pagesInput = document.getElementById('pages');

  const source = sourceSelect.value;
  const isPersonal = source === 'personal';
  const isCustom = source === 'custom';

  document.getElementById('locationGroup').style.display = isPersonal || isCustom ? 'none' : 'block';
  document.getElementById('searchTermGroup').style.display = 'block';
  document.getElementById('customUrlGroup').style.display = isCustom ? 'block' : 'none';
  document.getElementById('depthGroup').style.display = isCustom ? 'block' : 'none';
  document.getElementById('pagesGroup').style.display = isCustom ? 'none' : 'block';

  if (searchTermLabel) {
    searchTermLabel.textContent = isPersonal ? 'Person Name' : 'Search Term';
  }

  if (pagesInput) {
    pagesInput.max = isPersonal ? '1000' : '50'; // Adjust this as you like
  }
}

function updateDepthValue() {
  const depthInput = document.getElementById('depthPages');
  const depthValue = document.getElementById('depthValue');

  if (depthInput && depthValue) {
    const value = depthInput.value;
    depthValue.textContent = `${value} page${value > 1 ? 's' : ''}`;
  }
}

function initExtractionForm() {
  const sourceSelect = document.getElementById('source');
  const depthInput = document.getElementById('depthPages');
  const extractForm = document.getElementById('extractForm');

  if (sourceSelect) {
    sourceSelect.addEventListener('change', handleFormVisibility);
    handleFormVisibility(); // Call once to set initial state
  }

  if (depthInput) {
    depthInput.addEventListener('input', updateDepthValue);
    updateDepthValue(); // Call once to set initial value
  }

  if (extractForm) {
    extractForm.addEventListener('submit', function (e) {
      e.preventDefault();
      // Add your extraction logic here
      console.log('Extraction submitted');
    });
  }
}

// Make sure DOM don ready before calling
document.addEventListener('DOMContentLoaded', initExtractionForm);


function showNumber(number, source) {
  const resultTableBody = document.getElementById('resultTableBody');
  
  // Clear "no results" message if present
  if (resultTableBody.querySelector('td[colspan]')) {
    resultTableBody.innerHTML = '';
  }

  const row = document.createElement('tr');
  row.dataset.number = number;
  row.innerHTML = `
    <td>${resultTableBody.children.length + 1}</td>
    <td>${number}</td>
    <td>${source || 'Unknown'}</td>
    <td>-</td>
    <td>-</td>
    <td>-</td>
    <td class="text-muted">Unverified</td>
  `;
  resultTableBody.appendChild(row);

  // Auto-scroll to bottom
  const tableResponsive = document.querySelector('.table-responsive');
  if (tableResponsive) {
    tableResponsive.scrollTop = tableResponsive.scrollHeight;
  }
}

function updateResultCount() {
  if (elements.resultCount && elements.resultTableBody) {
    const count = elements.resultTableBody.children.length;
    elements.resultCount.textContent = `${count} number${count !== 1 ? 's' : ''} extracted`;
  }
}

function resetExtraction() {
  existingNumbers.clear();
  extractedNumbers = [];
  if (elements.resultTableBody) {
    elements.resultTableBody.innerHTML = `
      <tr>
        <td colspan="7" class="text-center py-5 text-muted">
          <i class="fas fa-inbox fa-3x mb-3"></i><br>
          No results yet. Start extraction to see data.
        </td>
      </tr>
    `;
  }
  updateResultCount();
  isStopped = false;
}

function startLoading() {
  if (statusText) statusText.textContent = 'Extracting...';
}

function stopLoading() {
  if (statusText) statusText.textContent = isAuthenticated ? 'Ready' : 'Please sign in to extract';
}

// Update handleFormSubmit function
async function handleFormSubmit(e) {
  e.preventDefault();
  if (!currentUser) {
    showToast('Please sign in before extracting.', 'danger');
    return;
  }

  resetExtraction();
  startLoading();
  isStopped = false;

  const source = elements.sourceSelect.value;
  const endpoint = apiMap[source];
  
  try {
    const requestData = {
      socketId: socket.id,
      searchTerm: elements.searchTermInput.value.trim(),
      location: elements.locationInput.value.trim(),
      pages: parseInt(elements.pagesInput.value) || 1
    };

    // Add error handling for the fetch request
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(requestData)
    });

    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.error || 'Request failed');
    }

    showToast(`${source} extraction started`, 'success');
  } catch (err) {
    console.error('Extraction error:', err);
    showToast(err.message, 'danger');
  } finally {
    elements.extractBtn.disabled = false;
    elements.stopBtn.disabled = true;
    stopLoading();
  }
}

function stopExtraction() {
  isStopped = true;
  socket.emit('cancelScrape');
  
  // UI updates
  elements.extractBtn.disabled = false;
  elements.stopBtn.disabled = true;
  elements.statusText.textContent = 'Extraction stopped';
  showToast('Extraction stopped', 'info');
  
  // If you have a progress bar
  if (elements.extractionProgress) {
    elements.extractionProgress.style.width = '0%';
  }
}

// Add stop button event listener
elements.stopBtn?.addEventListener('click', stopExtraction);

function saveNumbers() {
  if (extractedNumbers.length === 0) {
    alert('No numbers to save.');
    return;
  }
  const content = extractedNumbers.map(item => item.number).join('\n');
  const blob = new Blob([content], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'extracted_phone_numbers.txt';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}


function updateCredentialsList() {
  if (!credentialsList) return;
  
  credentialsList.innerHTML = '';
  
  Object.entries(credentialsData).forEach(([username, cred]) => {
    const row = document.createElement('tr');
    row.innerHTML = `
      <td>${username}</td>
      <td>${cred.password}</td>
      <td>${new Date(cred.expiresAt).toLocaleString()}</td>
      <td>${getTimeRemaining(cred.expiresAt)}</td>
      <td><button class="btn btn-sm btn-danger" data-username="${username}">Revoke</button></td>
    `;
    row.querySelector('button').addEventListener('click', () => revokeCredential(username));
    credentialsList.appendChild(row);
  });
}

function revokeCredential(username) {
  delete credentialsData[username];
  localStorage.setItem('credentials', JSON.stringify(credentialsData));
  updateCredentialsList();
}

function getTimeRemaining(expiresAt) {
  const now = new Date();
  const expiry = new Date(expiresAt);
  const diff = expiry - now;
  
  if (diff <= 0) return 'Expired';
  
  const days = Math.floor(diff / (1000 * 60 * 60 * 24));
  const hours = Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
  return `${days}d ${hours}h`;
}

function startCredentialsTimer() {
  adminRefreshInterval = setInterval(() => {
    updateCredentialsList();
  }, 60000);
}

function generatePassword() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let password = '';
  for (let i = 0; i < 8; i++) {
    password += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return password;
}


function validateUserCredentials(username, password) {
  const cred = credentialsData[username];
  if (!cred) return false;
  
  const now = new Date();
  const expiry = new Date(cred.expiresAt);
  
  return cred.password === password && now < expiry;
}

// Proxy Management
if (saveProxiesBtn) {
  saveProxiesBtn.addEventListener('click', function() {
    const proxies = proxyList.value.trim();
    
    if (!proxies) {
      showToast('Please enter at least one proxy', 'danger');
      return;
    }

    const proxyLines = proxies.split('\n').map(line => line.trim()).filter(line => line.length > 0);
    const invalidProxies = proxyLines.filter(line => !isValidProxy(line));

    if (invalidProxies.length > 0) {
      showToast(`Invalid proxy format detected`, 'danger');
      return;
    }

    socket.emit('save-proxies', proxyLines);
    showToast(`${proxyLines.length} proxies saved successfully`, 'success');
    
    const proxyModal = bootstrap.Modal.getInstance(document.getElementById('proxyModal'));
    proxyModal.hide();
  });
}

function isValidProxy(proxy) {
  if (!proxy) return false;
  
  // Basic format validation
  const proxyRegex = /^(\d{1,3}\.){3}\d{1,3}:\d{1,5}(:.+:.+)?$/;
  if (!proxyRegex.test(proxy)) return false;
  
  // Validate IP parts
  const ip = proxy.split(':')[0];
  const ipParts = ip.split('.');
  return ipParts.every(part => {
    const num = parseInt(part, 10);
    return num >= 0 && num <= 255;
  });
}
