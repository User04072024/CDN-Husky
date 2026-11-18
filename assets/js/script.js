const dropArea = document.getElementById('drop-area');
const uploadForm = document.querySelector('.upload-box form');
const fileInput = document.getElementById('input');
const uploadButton = document.getElementById('upload');
const expirationSelect = document.getElementById('expiresIn');
const permanentHelp = document.getElementById('permanent-help');
const uploading = document.getElementById('uploading');
const uploadStatus = document.getElementById('upload-status');
const uploadProgress = document.getElementById('upload-progress');

function getPermanentAccessPath() {
  if (uploadForm.dataset.authenticated !== 'true') return '/login?next=permanent';
  if (uploadForm.dataset.permanentEnabled !== 'true') return '/account?payment=required';
  return null;
}

function updatePermanentHelp() {
  permanentHelp.hidden = expirationSelect.value !== 'never';
}

function showUploadError(message) {
  uploading.style.display = 'block';
  uploadStatus.textContent = message;
  uploadProgress.hidden = true;
}

async function uploadFile(file) {
  const contentType = file.type || 'application/octet-stream';
  uploading.style.display = 'block';
  uploadProgress.hidden = false;
  uploadProgress.value = 0;
  uploadStatus.textContent = 'Preparing upload...';

  try {
    const presignResponse = await fetch('/api/presign', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        filename: file.name,
        contentType,
        size: file.size,
        expiresIn: expirationSelect.value,
      }),
    });
    const presignResult = await presignResponse.json();
    if (!presignResponse.ok || !presignResult.status) {
      throw new Error(presignResult.message || 'Could not prepare the upload.');
    }

    await new Promise((resolve, reject) => {
      const request = new XMLHttpRequest();
      request.open('PUT', presignResult.data.uploadUrl);
      Object.entries(presignResult.data.uploadHeaders).forEach(([name, value]) => {
        request.setRequestHeader(name, value);
      });
      request.upload.addEventListener('progress', (event) => {
        if (!event.lengthComputable) return;
        const percent = Math.round((event.loaded / event.total) * 100);
        uploadProgress.value = percent;
        uploadStatus.textContent = `Uploading to storage... ${percent}%`;
      });
      request.addEventListener('load', () => {
        if (request.status >= 200 && request.status < 300) {
          resolve();
        } else if (request.status === 412) {
          resolve();
        } else {
          reject(new Error(`Storage upload failed (${request.status}). Check the bucket CORS settings.`));
        }
      });
      request.addEventListener('error', () => reject(new Error('Network error while uploading to storage.')));
      request.addEventListener('abort', () => reject(new Error('Upload was cancelled.')));
      request.send(file);
    });

    uploadStatus.textContent = 'Saving file details...';
    const completeResponse = await fetch('/api/files', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ intentId: presignResult.data.intentId }),
    });
    const completeResult = await completeResponse.json();
    if (!completeResponse.ok || !completeResult.status) {
      throw new Error(completeResult.message || 'Could not save file details.');
    }
    window.location.assign(completeResult.data.pageUrl);
  } catch (error) {
    showUploadError(error.message || 'Upload failed. Please try again.');
  }
}

function beginUpload(files) {
  if (!files || files.length === 0) return;

  const accessPath = expirationSelect.value === 'never' ? getPermanentAccessPath() : null;
  if (accessPath) {
    window.location.assign(accessPath);
    return;
  }

  uploadFile(files[0]);
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
