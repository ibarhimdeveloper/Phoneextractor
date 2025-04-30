function getCookie(name) {
  const value = `; ${document.cookie}`;
  const parts = value.split(`; ${name}=`);
  if (parts.length === 2) return parts.pop().split(';').shift();
}

// Admin configuration
const CREDENTIAL_EXPIRY_DAYS = 14; // 2 weeks expiry

// Replace the duplicate declarations at the top with:
const elements = {
  searchTermInput: document.getElementById('searchTerm'),
  searchTermLabel: document.querySelector('label[for="searchTerm"]'),
  locationInput: document.getElementById('location'),
  customUrlInput: document.getElementById('customUrl'),
  pagesInput: document.getElementById('pages'),
  depthInput: document.getElementById('depthPages'),
  depthValue: document.getElementById('depthValue'),
  resultTableBody: document.getElementById('resultTableBody'),
  extractionProgress: document.getElementById('extractionProgress'),
  stopBtn: document.getElementById('stopBtn'),
  saveBtn: document.getElementById('saveToNotepad'),
  extractBtn: document.getElementById('extractBtn'),
  resultCount: document.getElementById('resultCount'),
  statusText: document.getElementById('statusText'),
  signInBtn: document.getElementById('signInBtn'),
  adminBtn: document.getElementById('adminBtn'),
  adminLoginBtn: document.getElementById('adminLoginBtn'),
  adminLogoutBtn: document.getElementById('adminLogoutBtn'),
  generateCredentialsBtn: document.getElementById('generateCredentialsBtn'),
  signInForm: document.getElementById('signInForm'),
  usernameInput: document.getElementById('usernameInput'),
  passwordInput: document.getElementById('passwordInput'),
  adminPasswordInput: document.getElementById('adminPassword'),
  generateUsernameInput: document.getElementById('generateUsername'),
  credentialsList: document.getElementById('credentialsList'),
  proxyList: document.getElementById('proxyList'),
  saveProxiesBtn: document.getElementById('saveProxiesBtn'),
  verifyNumbersBtn: document.getElementById('verifyNumbersBtn')
};

// Credentials data store
let credentialsData = JSON.parse(localStorage.getItem('credentials')) || {};



// Generate New Credentials
function generateCredentials() {
  const username = generateUsernameInput.value.trim() || 
    `user_${Math.random().toString(36).substring(2, 8)}`;
  const password = generatePassword();
  
  // Calculate expiry date (2 weeks from now)
  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + CREDENTIAL_EXPIRY_DAYS);
  
  // Create credential object
  const credential = {
    username,
    password,
    expiresAt: expiresAt.toISOString(),
    generatedAt: new Date().toISOString(),
    isActive: true
  };
  
  // Save to localStorage
  credentialsData[username] = credential;
  localStorage.setItem('credentials', JSON.stringify(credentialsData));
  
  // Update UI
  updateCredentialsList();
  generateUsernameInput.value = '';
  
  // Show success message
  alert(`New credentials generated!\nUsername: ${username}\nPassword: ${password}`);
}

// Update Credentials List in UI
function updateCredentialsList() {
  credentialsList.innerHTML = '';
  
  // Sort by expiry date (soonest first)
  const sortedCredentials = Object.entries(credentialsData)
    .sort((a, b) => new Date(a[1].expiresAt) - new Date(b[1].expiresAt));
  
  if (sortedCredentials.length === 0) {
    credentialsList.innerHTML = `
      <tr>
        <td colspan="6" class="text-center py-4 text-muted">
          No credentials generated yet
        </td>
      </tr>
    `;
    return;
  }
  
  sortedCredentials.forEach(([username, cred]) => {
    const row = document.createElement('tr');
    row.innerHTML = `
      <td>${username}</td>
      <td>${cred.password}</td>
      <td>${new Date(cred.generatedAt).toLocaleDateString()}</td>
      <td>${new Date(cred.expiresAt).toLocaleDateString()}</td>
      <td>${getTimeRemaining(cred.expiresAt)}</td>
      <td>
        <button class="btn btn-sm ${cred.isActive ? 'btn-success' : 'btn-danger'}" 
          data-action="toggle" data-username="${username}">
          ${cred.isActive ? 'Active' : 'Banned'}
        </button>
        <button class="btn btn-sm btn-primary ms-1" 
          data-action="extend" data-username="${username}">
          <i class="fas fa-plus"></i> 1 Week
        </button>
      </td>
    `;
    credentialsList.appendChild(row);
  });
  
  // Add event listeners to buttons
  document.querySelectorAll('[data-action="toggle"]').forEach(btn => {
    btn.addEventListener('click', () => toggleCredential(btn.dataset.username));
  });
  
  document.querySelectorAll('[data-action="extend"]').forEach(btn => {
    btn.addEventListener('click', () => extendCredential(btn.dataset.username));
  });
}

// Toggle credential active status
function toggleCredential(username) {
  if (credentialsData[username]) {
    credentialsData[username].isActive = !credentialsData[username].isActive;
    localStorage.setItem('credentials', JSON.stringify(credentialsData));
    updateCredentialsList();
  }
}

// Extend credential expiry
function extendCredential(username) {
  if (credentialsData[username]) {
    const newExpiry = new Date(credentialsData[username].expiresAt);
    newExpiry.setDate(newExpiry.getDate() + 7); // Add 1 week
    
    credentialsData[username].expiresAt = newExpiry.toISOString();
    localStorage.setItem('credentials', JSON.stringify(credentialsData));
    updateCredentialsList();
    
    showToast(`Extended expiry for ${username} by 1 week`, 'success');
  }
}

// Helper function to generate random password
function generatePassword() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let password = '';
  for (let i = 0; i < 10; i++) {
    password += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return password;
}

// Calculate time remaining
function getTimeRemaining(expiresAt) {
  const now = new Date();
  const expiry = new Date(expiresAt);
  const diff = expiry - now;
  
  if (diff <= 0) return 'Expired';
  
  const days = Math.floor(diff / (1000 * 60 * 60 * 24));
  const hours = Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
  return `${days}d ${hours}h`;
}

// Auto-refresh credentials list
function startCredentialsTimer() {
  // Clear existing interval if any
  if (window.credentialsRefreshInterval) {
    clearInterval(window.credentialsRefreshInterval);
  }
  
  // Update every minute
  window.credentialsRefreshInterval = setInterval(() => {
    updateCredentialsList();
  }, 60000);
}

// Admin logout
function handleAdminLogout() {
  adminLoginForm.style.display = 'block';
  adminPanel.style.display = 'none';
  adminPasswordInput.value = '';
  
  // Clear refresh interval
  if (window.credentialsRefreshInterval) {
    clearInterval(window.credentialsRefreshInterval);
  }
}

// Event Listeners
adminLoginBtn.addEventListener('click', handleAdminLogin);
adminLogoutBtn.addEventListener('click', handleAdminLogout);
generateCredentialsBtn.addEventListener('click', generateCredentials);

// User authentication
function validateUserCredentials(username, password) {
  const cred = credentialsData[username];
  if (!cred) return false;
  
  const now = new Date();
  const expiry = new Date(cred.expiresAt);
  
  return (
    cred.password === password && 
    now < expiry && 
    cred.isActive === true
  );
}

// Initialize admin panel
if (adminModal) {
  adminModal.addEventListener('show.bs.modal', () => {
    adminLoginForm.style.display = 'block';
    adminPanel.style.display = 'none';
    adminPasswordInput.value = '';
  });
}

// Toast notification
function showToast(message, type = 'success') {
  const toastContainer = document.querySelector('.toast-container') || document.body;
  const toastId = `toast-${Date.now()}`;
  
  const toast = document.createElement('div');
  toast.id = toastId;
  toast.className = `toast show align-items-center text-bg-${type}`;
  toast.setAttribute('role', 'alert');
  toast.setAttribute('aria-live', 'assertive');
  toast.setAttribute('aria-atomic', 'true');
  toast.innerHTML = `
    <div class="d-flex">
      <div class="toast-body">
        <i class="fas ${type === 'success' ? 'fa-check-circle' : 'fa-exclamation-circle'} me-2"></i>
        ${message}
      </div>
      <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
    </div>
  `;
  
  toastContainer.appendChild(toast);
  
  // Auto-remove after 5 seconds
  setTimeout(() => {
    toast.remove();
  }, 5000);
}

const socket = io();
let socketId = null;
let isStopped = false;
let extractedNumbers = [];
let isAuthenticated = localStorage.getItem('isAuthenticated') === 'true';
let storedUsername = localStorage.getItem('username') || '';

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

// Initialize UI
updateUI();
if (isAuthenticated) {
  signInBtn.textContent = `Sign Out (${storedUsername})`;
}

// Event Listeners
const {
  form,
  sourceSelect,
  stopBtn,
  saveBtn,
  signInBtn,
  adminBtn,
  adminLoginBtn,
  adminLogoutBtn,
  generateCredentialsBtn,
  signInForm,
  verifyNumbersBtn
} = elements;

// Initialize form visibility and depth slider
handleFormVisibility();
if (depthInput) {
  depthInput.addEventListener('input', updateDepthValue);
  updateDepthValue();
}

let existingNumbers = new Set();

// Socket Events
socket.on('connect', () => {
  socketId = socket.id;
});

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
    pagesInput.max = isPersonal ? '1000' : '1000';
  }
}

function updateDepthValue() {
  if (depthValue && depthInput) {
    depthValue.textContent = `${depthInput.value} page${depthInput.value > 1 ? 's' : ''}`;
  }
}

function showNumber(number, source) {
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

  const tableResponsive = document.querySelector('.table-responsive');
  if (tableResponsive) {
    tableResponsive.scrollTop = tableResponsive.scrollHeight;
  }
}

function updateResultCount() {
  if (resultCount) {
    const count = extractedNumbers.length;
    resultCount.textContent = `${count} number${count !== 1 ? 's' : ''} extracted`;
  }
}

function updateUI() {
  if (isAuthenticated) {
    if (extractBtn) extractBtn.disabled = false;
    if (stopBtn) stopBtn.disabled = false;
    document.querySelector('.disclaimer')?.style?.setProperty('display', 'none', 'important');
    if (statusText) statusText.textContent = 'Ready to extract';
  } else {
    if (extractBtn) extractBtn.disabled = true;
    if (stopBtn) stopBtn.disabled = true;
    document.querySelector('.disclaimer')?.style?.setProperty('display', 'block', 'important');
    if (statusText) statusText.textContent = 'Please sign in to extract';
  }
}

function resetExtraction() {
  existingNumbers.clear();
  extractedNumbers = [];
  if (resultTableBody) {
    resultTableBody.innerHTML = `
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

async function handleFormSubmit(e) {
  e.preventDefault();
  if (!isAuthenticated) {
    alert('Please sign in before extracting.');
    return;
  }

  resetExtraction();
  startLoading();

  const source = sourceSelect.value;
  const endpoint = apiMap[source];
  let body = {};

  try {
    if (source === 'custom') {
      const url = customUrlInput.value.trim();
      if (!url) throw new Error('Enter a valid URL.');
      body = { url, depth: parseInt(depthInput.value) || 1, socketId };
    } else if (source === 'personal') {
      const name = searchTermInput.value.trim();
      if (!name) throw new Error('Enter a name.');
      body = { name, socketId };
    } else {
      const searchTerm = searchTermInput.value.trim();
      const location = locationInput.value.trim();
      if (!searchTerm || !location) throw new Error('Enter search term and location.');
      body = { searchTerm, location, pages: parseInt(pagesInput.value) || 1, socketId };
    }

    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });

    if (!res.ok) {
      const error = await res.json().catch(() => ({ error: 'Server error' }));
      throw new Error(error.error || 'Request failed');
    }

    const data = await res.json();
    if (!data.success) throw new Error(data.error || 'Unknown error');
    
    stopLoading();
    if (statusText) statusText.textContent = 'Extraction completed';
  } catch (err) {
    stopLoading();
    if (statusText) statusText.textContent = 'Error occurred during extraction';
    alert(`Error: ${err.message}`);
  }
}

function stopExtraction() {
  isStopped = true;
  stopLoading();
  socket.emit('cancelScrape');
  if (statusText) statusText.textContent = 'Extraction stopped';
}

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

function handleSignIn() {
  if (isAuthenticated) {
    isAuthenticated = false;
    localStorage.removeItem('isAuthenticated');
    localStorage.removeItem('username');
    if (signInBtn) signInBtn.textContent = 'Sign In';
    updateUI();
    alert('Signed out!');
  } else {
    new bootstrap.Modal(document.getElementById('signInModal')).show();
  }
}

async function verifyNumbers() {
  if (extractedNumbers.length === 0) {
    alert('No numbers to verify.');
    return;
  }

  try {
    const numbers = extractedNumbers.map(item => item.number);
    const res = await fetch('/verify-numbers', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ numbers })
    });

    const data = await res.json();
    
    if (data.success) {
      data.results.forEach((result, i) => {
        const row = resultTableBody.children[i];
        if (row) {
          row.cells[3].textContent = result.type || 'Unknown';
          row.cells[4].textContent = result.country || 'Unknown';
          row.cells[5].textContent = result.carrier || 'Unknown';
          row.cells[6].className = result.valid ? 'text-success' : 'text-danger';
          row.cells[6].textContent = result.valid ? 'Valid' : 'Invalid';
          row.dataset.verified = result.valid;
        }
      });
      alert('Verification completed!');
    } else {
      throw new Error(data.error || 'Failed to verify numbers');
    }
  } catch (err) {
    console.error('Verification error:', err);
    alert('Error verifying numbers: ' + err.message);
  }
}

// Admin Login Functionality
async function handleAdminLogin() {
  const response = await fetch('/admin-login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password: elements.adminPasswordInput.value })
  });
  
  if (response.ok) {
    document.cookie = `adminToken=${await response.json().token}; path=/; Secure`;

    const data = await response.json();
    
    if (data.success) {
      document.getElementById('adminLoginForm').style.display = 'none';
      document.getElementById('adminPanel').style.display = 'block';
      updateCredentialsList();
      startCredentialsTimer();
      showToast('Admin login successful', 'success');
    } else {
      showToast('Invalid admin password', 'danger');
    }
  } catch (err) {
    console.error('Admin login error:', err);
    showToast('Login failed. Please try again.', 'danger');
  }
}

function handleAdminLogout() {
  document.getElementById('adminLoginForm').style.display = 'block';
  document.getElementById('adminPanel').style.display = 'none';
  clearInterval(adminRefreshInterval);
}

function generateCredentials() {
  const username = generateUsername.value.trim() || `user_${Math.random().toString(36).substr(2, 6)}`;
  const password = generatePassword();
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
  
  const credential = {
    username,
    password,
    expiresAt: expiresAt.toISOString(),
    generatedAt: new Date().toISOString()
  };
  
  credentialsData[username] = credential;
  localStorage.setItem('credentials', JSON.stringify(credentialsData));
  updateCredentialsList();
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

function handleUserLogin(e) {
  e.preventDefault();
  const username = usernameInput.value.trim();
  const password = passwordInput.value;
  
  if (validateUserCredentials(username, password)) {
    isAuthenticated = true;
    localStorage.setItem('isAuthenticated', 'true');
    localStorage.setItem('username', username);
    if (signInBtn) signInBtn.textContent = `Sign Out (${username})`;
    updateUI();
    bootstrap.Modal.getInstance(document.getElementById('signInModal')).hide();
    alert('Signed in successfully!');
  } else {
    alert('Invalid credentials or credentials expired');
  }
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
  const proxyRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?):\d{1,5}(?::[^:]+:[^:]+)?$/;
  return proxyRegex.test(proxy) && 
         !proxy.includes('127.0.0.1') && 
         !proxy.includes('localhost');
}
  
  // Validate IP segments
  const ip = proxy.split(':')[0];
  const ipParts = ip.split('.');
  return ipParts.every(part => {
    const num = parseInt(part, 10);
    return num >= 0 && num <= 255;
  });
}

function isValidIP(ip) {
  const segments = ip.split('.');
  if (segments.length !== 4) return false;
  return segments.every(seg => {
    const n = parseInt(seg, 10);
    return n >= 0 && n <= 255;
  });
}

// Toast notification system
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
  }, 3000);
}