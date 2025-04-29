function getCookie(name) {
  const value = `; ${document.cookie}`;
  const parts = value.split(`; ${name}=`);
  if (parts.length === 2) return parts.pop().split(';').shift();
}

// Credentials data store
let credentialsData = JSON.parse(localStorage.getItem('credentials')) || {};
let adminRefreshInterval = null;

// DOM Elements
const form = document.getElementById('extractForm');
const sourceSelect = document.getElementById('source');
const searchTermInput = document.getElementById('searchTerm');
const searchTermLabel = document.querySelector('label[for="searchTerm"]');
const locationInput = document.getElementById('location');
const customUrlInput = document.getElementById('customUrl');
const pagesInput = document.getElementById('pages');
const depthInput = document.getElementById('depthPages');
const depthValue = document.getElementById('depthValue');
const resultTableBody = document.getElementById('resultTableBody');
const extractionProgress = document.getElementById('extractionProgress');
const stopBtn = document.getElementById('stopBtn');
const saveBtn = document.getElementById('saveToNotepad');
const extractBtn = document.getElementById('extractBtn');
const resultCount = document.getElementById('resultCount');
const statusText = document.getElementById('statusText');
const signInBtn = document.getElementById('signInBtn');
const adminBtn = document.getElementById('adminBtn');
const adminLoginBtn = document.getElementById('adminLoginBtn');
const adminLogoutBtn = document.getElementById('adminLogoutBtn');
const generateCredentialsBtn = document.getElementById('generateCredentialsBtn');
const signInForm = document.getElementById('signInForm');
const usernameInput = document.getElementById('usernameInput');
const passwordInput = document.getElementById('passwordInput');
const adminPassword = document.getElementById('adminPassword');
const generateUsername = document.getElementById('generateUsername');
const credentialsList = document.getElementById('credentialsList');
const proxyList = document.getElementById('proxyList');
const saveProxiesBtn = document.getElementById('saveProxiesBtn');
const verifyNumbersBtn = document.getElementById('verifyNumbersBtn');

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
sourceSelect.addEventListener('change', handleFormVisibility);
form.addEventListener('submit', handleFormSubmit);
stopBtn.addEventListener('click', stopExtraction);
saveBtn.addEventListener('click', saveNumbers);
signInBtn.addEventListener('click', handleSignIn);
adminBtn.addEventListener('click', () => {
  new bootstrap.Modal(document.getElementById('adminModal')).show();
});
adminLoginBtn.addEventListener('click', handleAdminLogin);
adminLogoutBtn.addEventListener('click', handleAdminLogout);
generateCredentialsBtn.addEventListener('click', generateCredentials);
signInForm.addEventListener('submit', handleUserLogin);
verifyNumbersBtn.addEventListener('click', verifyNumbers);

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

// Admin Functions
function handleAdminLogin() {
  const password = adminPassword.value;
  if (password === 'Admin112122') {
    document.getElementById('adminLoginForm').style.display = 'none';
    document.getElementById('adminPanel').style.display = 'block';
    updateCredentialsList();
    startCredentialsTimer();
  } else {
    alert('Invalid admin password');
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
  const ipPortRegex = /^(\d{1,3}\.){3}\d{1,3}:\d{2,5}$/;
  const ipPortAuthRegex = /^(\d{1,3}\.){3}\d{1,3}:\d{2,5}:.+:.+$/;
  
  if (ipPortRegex.test(proxy)) {
    const parts = proxy.split(':');
    const ip = parts[0];
    const port = parseInt(parts[1], 10);
    return isValidIP(ip) && (port >= 1 && port <= 65535);
  } else if (ipPortAuthRegex.test(proxy)) {
    const parts = proxy.split(':');
    const ip = parts[0];
    const port = parseInt(parts[1], 10);
    return isValidIP(ip) && (port >= 1 && port <= 65535) && parts[2] && parts[3];
  }
  return false;
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