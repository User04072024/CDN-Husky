const dropArea = document.getElementById('drop-area');
const uploadForm = document.querySelector('.upload-box form');
const fileInput = document.getElementById('input');
const uploadButton = document.getElementById('upload');
const expirationSelect = document.getElementById('expiresIn');
const permanentHelp = document.getElementById('permanent-help');
const uploading = document.getElementById('uploading');

function getPermanentAccessPath() {
  if (uploadForm.dataset.authenticated !== 'true') return '/login?next=permanent';
  if (uploadForm.dataset.permanentEnabled !== 'true') return '/account?payment=required';
  return null;
}

function updatePermanentHelp() {
  permanentHelp.hidden = expirationSelect.value !== 'never';
}

function beginUpload(files) {
  if (!files || files.length === 0) return;

  const accessPath = expirationSelect.value === 'never' ? getPermanentAccessPath() : null;
  if (accessPath) {
    window.location.assign(accessPath);
    return;
  }

  fileInput.files = files;
  uploadForm.submit();
  uploading.style.display = 'block';
}

uploadButton.addEventListener('click', (event) => {
  event.preventDefault();
  const accessPath = expirationSelect.value === 'never' ? getPermanentAccessPath() : null;
  if (accessPath) {
    window.location.assign(accessPath);
    return;
  }
  fileInput.click();
});

fileInput.addEventListener('change', () => {
  beginUpload(fileInput.files);
});

expirationSelect.addEventListener('change', updatePermanentHelp);
updatePermanentHelp();

dropArea.addEventListener('dragover', (event) => {
  event.preventDefault();
  dropArea.classList.add('dragover');
});

dropArea.addEventListener('dragleave', () => {
  dropArea.classList.remove('dragover');
});

dropArea.addEventListener('drop', (event) => {
  event.preventDefault();
  dropArea.classList.remove('dragover');
  beginUpload(event.dataTransfer.files);
});
