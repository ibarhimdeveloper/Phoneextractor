const socket = io({
  reconnection: true,
  reconnectionAttempts: Infinity,
  reconnectionDelay: 1000,
  reconnectionDelayMax: 5000,
  timeout: 20000,
  transports: ['websocket']
});

// App state
const appState = {
  isAuthenticated: false,
  currentUser: null,
  socketId: null,
  isExtracting: false,
  extractedNumbers: [],
  existingNumbers: new Set()
};

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
  saveToNotepad: document.getElementById('saveToNotepad'),
  submitButton: document.getElementById('submitButton'),
  loadingSpinner: document.getElementById('loadingOverlay'),
  progressContainer: document.querySelector('.progressContainer'),
  progressBar: document.getElementById('extractionProgress'),
  progressText: document.querySelector('.progressText'),
  extractionStatus: document.getElementById('statusText')
};

// Verify all elements exist
for (const [key, element] of Object.entries(elements)) {
  if (!element) {
    console.error(`Element ${key} not found`);
  }
}

// Source to API endpoint mapping
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

// Source display names
const sourceDisplayNames = {
  yellowpages: 'Yellow Pages',
  yelp: 'Yelp',
  personal: 'Personal Search',
  custom: 'Custom Website',
  global: 'All Sources',
  whitepages: 'White Pages',
  linkedin: 'LinkedIn',
  facebook: 'Facebook',
  truepeoplesearch: 'TruePeopleSearch',
  anywho: 'AnyWho',
  spokeo: 'Spokeo',
  fastpeoplesearch: 'FastPeopleSearch',
  '411': '411',
  usphonebook: 'USPhonebook',
  radaris: 'Radaris',
  zabasearch: 'ZabaSearch',
  peoplefinders: 'PeopleFinders',
  peekyou: 'PeekYou',
  thatsthem: 'ThatsThem',
  addresses: 'Addresses',
  pipl: 'Pipl',
  manta: 'Manta',
  bbb: 'BBB',
  hotfrog: 'Hotfrog',
  foursquare: 'Foursquare',
  brownbook: 'Brownbook',
  cityfos: 'Cityfos',
  cylex: 'Cylex',
  merchantcircle: 'MerchantCircle',
  localstack: 'Localstack'
};

// Initialize the app
document.addEventListener('DOMContentLoaded', async () => {
  await checkAuth();
  setupEventListeners();
  handleFormVisibility();
  
  if (elements.depthInput) {
    elements.depthInput.addEventListener('input', updateDepthValue);
    updateDepthValue();
  }
  
  initExtractionForm();
});

// Socket.io events
socket.on('connect', () => {
  console.log('Socket connected:', socket.connected); // Should be true
  appState.socketId = socket.id;
  
  if (document.getElementById('adminPanel')?.style.display === 'block') {
    fetchAndDisplayCredentials();
  }
});

socket.on('disconnect', () => {
  console.log('Disconnected from server');
});

socket.on('connect_error', (err) => {
  console.error('Socket connection error:', err);
  showToast('Connection error - trying to reconnect...', 'warning');
});

socket.on('reconnect_attempt', () => {
  console.log('Attempting reconnect...');
});

socket.on('phoneNumber', (data) => {
  if (!appState.isExtracting || !data?.number || appState.existingNumbers.has(data.number)) return;
  
  appState.existingNumbers.add(data.number);
  appState.extractedNumbers.push(data);
  showNumber(data.number, data.source);
  updateResultCount();
});

socket.on('progress', (percent) => {
  if (elements.extractionProgress) {
    elements.extractionProgress.style.width = `${percent}%`;
    if (elements.statusText) {
      elements.statusText.textContent = `Extracting... ${percent}%`;
    }
  }
});

socket.on('error', (message) => {
  showToast(message, 'danger');
  stopExtraction();
});

// Auth functions
async function checkAuth() {
  try {
    const response = await fetch('/check-auth', { credentials: 'include' });
    
    if (response.ok) {
      const data = await response.json();
      if (data.success) {
        appState.isAuthenticated = true;
        appState.currentUser = data.user;
        updateUI();
        return true;
      }
    }
    
    appState.isAuthenticated = false;
    appState.currentUser = null;
    updateUI();
    return false;
  } catch (err) {
    console.error('Auth check failed:', err);
    return false;
  }
}

function updateUI() {
  const { isAuthenticated, currentUser } = appState;
  
  if (elements.signInBtn) {
    elements.signInBtn.innerHTML = isAuthenticated
      ? `<i class="fas fa-sign-out-alt me-2"></i> Sign Out (${currentUser?.username || ''})`
      : '<i class="fas fa-sign-in-alt me-2"></i> Sign In';
  }
  
  if (elements.extractBtn) elements.extractBtn.disabled = !isAuthenticated;
  if (elements.stopBtn) elements.stopBtn.disabled = !isAuthenticated;
  
  if (elements.statusText) {
    elements.statusText.textContent = isAuthenticated 
      ? 'Ready to extract' 
      : 'Please sign in to extract';
  }
}

// Setup event listeners
function setupEventListeners() {
  if (elements.signInBtn) {
    elements.signInBtn.addEventListener('click', async () => {
      if (appState.isAuthenticated) {
        await handleSignOut();
      } else {
        new bootstrap.Modal(document.getElementById('signInModal')).show();
      }
    });
  }

  if (elements.signInForm) {
    elements.signInForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      await handleUserLogin(e);
    });
  }

  if (elements.adminLoginBtn) {
    elements.adminLoginBtn.addEventListener('click', handleAdminLogin);
  }

  if (elements.adminLogoutBtn) {
    elements.adminLogoutBtn.addEventListener('click', handleAdminLogout);
  }
  
  if (elements.extractForm) {
    elements.extractForm.addEventListener('submit', handleFormSubmit);
  }

  if (elements.stopBtn) {
    elements.stopBtn.addEventListener('click', stopExtraction);
  }

  if (elements.saveToNotepad) {
    elements.saveToNotepad.addEventListener('click', saveNumbers);
  }
}

// Form handling
function handleFormVisibility() {
  if (!elements.sourceSelect) return;

  const source = elements.sourceSelect.value;
  const isPersonal = source === 'personal';
  const isCustom = source === 'custom';

  if (elements.locationGroup) {
    elements.locationGroup.style.display = isPersonal || isCustom ? 'none' : 'block';
  }
  
  if (elements.searchTermGroup) {
    elements.searchTermGroup.style.display = 'block';
  }
  
  if (elements.customUrlGroup) {
    elements.customUrlGroup.style.display = isCustom ? 'block' : 'none';
  }
  
  if (elements.depthGroup) {
    elements.depthGroup.style.display = isCustom ? 'block' : 'none';
  }
  
  if (elements.pagesGroup) {
    elements.pagesGroup.style.display = isCustom ? 'none' : 'block';
  }

  if (elements.searchTermLabel) {
    elements.searchTermLabel.textContent = isPersonal ? 'Person Name' : 'Search Term';
  }

  if (elements.pagesInput) {
    elements.pagesInput.max = isPersonal ? '1000' : '50';
  }
}

function updateDepthValue() {
  if (!elements.depthInput || !elements.depthValue) return;

  const value = elements.depthInput.value;
  elements.depthValue.textContent = `${value} page${value > 1 ? 's' : ''}`;
}

function initExtractionForm() {
  if (elements.sourceSelect) {
    elements.sourceSelect.addEventListener('change', handleFormVisibility);
    handleFormVisibility();
  }

  if (elements.depthInput) {
    elements.depthInput.addEventListener('input', updateDepthValue);
    updateDepthValue();
  }
}

document.addEventListener('DOMContentLoaded', initExtractionForm);


// Extraction functions
async function handleFormSubmit(e) {
  e.preventDefault();
  
  if (!appState.isAuthenticated) {
    showToast('Please sign in before extracting.', 'danger');
    return;
  }

  // Set initial loading state
  startLoading();

  try {
    const pagesRaw = elements.pagesInput.value.trim();
    const pagesParsed = parseInt(pagesRaw, 10);
    const pages = Number.isInteger(pagesParsed) && pagesParsed > 0 ? pagesParsed : 1;

    const depthInput = elements.depthInput?.value.trim();
    const depthParsed = depthInput ? parseInt(depthInput, 10) : 1;
    const depth = Number.isInteger(depthParsed) && depthParsed > 0 ? depthParsed : 1;

    const formData = {
      source: elements.sourceSelect.value,
      searchTerm: elements.searchTermInput.value.trim(),
      location: elements.locationInput.value.trim(),
      pages: pages,
      url: elements.customUrlInput?.value.trim(),
      depth: depth,
      socketId: appState.socketId
    };

    updateProgress(10, "Validating inputs...");
    
    const endpoint = apiMap[formData.source];
    if (!endpoint) throw new Error('Invalid source selected');

    updateProgress(30, "Connecting to server...");
    
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(formData)
    });

    updateProgress(60, "Processing request...");

    if (!response.ok) {
      let errorMessage = 'Extraction failed';
      try {
        const errorData = await response.json();
        errorMessage = errorData.error || errorMessage;
      } catch {
        const responseText = await response.text();
        errorMessage = responseText || errorMessage;
      }
      throw new Error(errorMessage);
    }

    updateProgress(90, "Finalizing...");
    
    const sourceName = sourceDisplayNames?.[formData.source] || formData.source;
    showToast(`${sourceName} extraction started`, 'success');
    updateProgress(100, "Extraction in progress...");

    // Keep progress visible for ongoing extraction
    appState.isExtracting = true;
    
  } catch (err) {
    showToast(err.message, 'danger');
    console.error('Extraction error:', err);
    stopLoading();
    resetExtraction();
  } finally {
    // Don't fully stop loading if extraction is ongoing
    if (!appState.isExtracting) {
      stopLoading();
    }
  }
}

function stopExtraction() {
  appState.isExtracting = false;
  socket.emit('cancelScrape', { socketId: appState.socketId });
  updateUI();
  
  if (elements.statusText) {
    elements.statusText.textContent = 'Extraction stopped';
  }
}

function startLoading() {
  if (elements.submitButton) {
    elements.submitButton.disabled = true;
    elements.submitButton.classList.add('button-loading');
  }

  submitBtn.disabled = true;
  submitBtn.classList.add('button-loading');

  if (spinner) {
    spinner.style.display = 'inline-block'; // non-blocking
  }
}

function stopLoading() {
  const submitBtn = document.getElementById('submit-btn');
  const spinner = document.getElementById('loading-spinner');

  submitBtn.disabled = false;
  submitBtn.classList.remove('button-loading');

  if (spinner) {
    spinner.style.display = 'none';
  }
}

function updateProgress(percent, message) {
  elements.progressBar.style.width = `${percent}%`;
  elements.progressText.textContent = message;
  elements.extractionStatus.textContent = message;
  
  // Change color based on progress
  if (percent < 30) {
    elements.progressBar.style.backgroundColor = '#ff9800'; // orange
  } else if (percent < 70) {
    elements.progressBar.style.backgroundColor = '#2196F3'; // blue
  } else {
    elements.progressBar.style.backgroundColor = '#4CAF50'; // green
  }
}

function resetExtraction() {
  appState.isExtracting = false;
  stopLoading();
  elements.progressContainer.style.display = 'none';
  elements.extractionStatus.textContent = '';
}

function resetExtraction() {
  appState.existingNumbers.clear();
  appState.extractedNumbers = [];
  
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
}

function showNumber(number, source) {
  if (!elements.resultTableBody) return;

  // Clear "no results" message if present
  if (elements.resultTableBody.querySelector('td[colspan]')) {
    elements.resultTableBody.innerHTML = '';
  }

  const row = document.createElement('tr');
  row.dataset.number = number;
  row.innerHTML = `
    <td>${elements.resultTableBody.children.length + 1}</td>
    <td>${number}</td>
    <td>${source || 'Unknown'}</td>
    <td>-</td>
    <td>-</td>
    <td>-</td>
    <td class="text-muted">Unverified</td>
  `;
  elements.resultTableBody.appendChild(row);

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

function saveNumbers() {
  if (appState.extractedNumbers.length === 0) {
    showToast('No numbers to save.', 'warning');
    return;
  }
  
  const content = appState.extractedNumbers.map(item => item.number).join('\n');
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

// Auth functions
async function handleUserLogin(e) {
  e.preventDefault();
  
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
      appState.currentUser = { username: data.username };
      appState.isAuthenticated = true;
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

async function handleSignOut() {
  try {
    await fetch('/logout', {
      method: 'POST',
      credentials: 'include'
    });

    appState.currentUser = null;
    appState.isAuthenticated = false;
    updateUI();
    showToast('Signed out successfully', 'success');
  } catch (err) {
    showToast('Logout failed', 'danger');
    console.error('Logout error:', err);
  }
}

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

async function handleAdminLogout() {
  try {
    await fetch('/logout', {
      method: 'POST',
      credentials: 'include'
    });
    elements.adminPanel.style.display = 'none';
    elements.adminLoginForm.style.display = 'block';
    document.getElementById('adminPassword').value = '';
    
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
        <td>
          <span class="password-mask" data-password="${cred.password}">*****</span>
          <button class="btn btn-sm btn-outline-secondary ms-2 toggle-password">
            Show
          </button>
        </td>
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

    document.querySelectorAll('.toggle-password').forEach(btn => {
      btn.addEventListener('click', () => {
        const span = btn.previousElementSibling;
        const realPassword = span.getAttribute('data-password');
        const isHidden = span.textContent === '*****';

        span.textContent = isHidden ? realPassword : '*****';
        btn.textContent = isHidden ? 'Hide' : 'Show';
      });
    });

  } catch (err) {
    showToast(err.message, 'danger');
    console.error('Credentials fetch error:', err);
  }
}

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

// Helper functions
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

// Initialize admin modal
if (document.getElementById('adminModal')) {
  document.getElementById('adminModal').addEventListener('show.bs.modal', () => {
    elements.adminLoginForm.style.display = 'block';
    elements.adminPanel.style.display = 'none';
    document.getElementById('adminPassword').value = '';
  });
}

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

// Generate new credentials
document.getElementById('generateCredentialsBtn').addEventListener('click', async () => {
  const username = document.getElementById('generateUsername').value;
  const tableBody = document.getElementById('credentialsList');

  try {
    const response = await fetch('/generate-credentials', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ username })
    });

    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || 'Failed to generate credentials');
    }

    showToast('Credentials generated successfully!', 'success');
    await fetchAndDisplayCredentials(); // Refresh the list
  } catch (err) {
    showToast(err.message, 'danger');
    console.error('Request failed:', err);
  }
});

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

// main.js - Complete verification
async function verifySelectedNumbers() {
  const selected = Array.from(document.querySelectorAll('#verifyNumbersList input[type="checkbox"]:checked'))
    .map(el => el.closest('tr').querySelector('td:nth-child(2)').textContent);

  try {
    const response = await fetch('/verify-numbers', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ numbers: selected })
    });
    
    const data = await response.json();
    updateVerificationResults(data.results);
  } catch (err) {
    showToast('Verification failed', 'danger');
  }
}

function updateVerificationResults(results) {
  results.forEach(result => {
    const row = document.querySelector(`tr[data-number="${result.phone}"]`);
    if (row) {
      row.cells[6].textContent = result.valid ? 'Valid' : 'Invalid';
      row.cells[6].className = result.valid ? 'text-success' : 'text-danger';
    }
  });
}

socket.on('cancelScrape', ({ socketId }) => {
  if (activeBrowsers[socketId]) {
    activeBrowsers[socketId].browser.close();
    delete activeBrowsers[socketId];
  }
});