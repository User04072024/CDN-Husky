// `url` and `contentType` are defined in data.ejs before this file is loaded.
function copyLink(link) {
  const tempInput = document.createElement('textarea');
  tempInput.value = link;
  document.body.appendChild(tempInput);
  tempInput.select();
  document.execCommand('copy');
  document.body.removeChild(tempInput);

  if (document.queryCommandSupported('copy')) {
    const notif = document.createElement('div');
    notif.className = 'notification';
    notif.textContent = 'Link telah berhasil disalin ke clipboard.';
    document.body.appendChild(notif);
    setTimeout(() => {
      notif.style.display = 'none';
    }, 2000);
  } else {
    alert('Salin link secara manual: ' + link);
  }
}

const filePreview = document.getElementById('filePreview');
const extension = new URL(url).pathname.split('/').pop().split('.').pop().toLowerCase();
const mimeType = contentType.split(';')[0].toLowerCase();
const PREVIEW_WIDTH = 180;
const imageExtensions = ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'avif', 'svg'];
const videoExtensions = ['mp4', 'webm', 'mov', 'm4v', 'ogv'];
const audioExtensions = ['mp3', 'wav', 'ogg', 'm4a', 'aac', 'flac'];

function showTypeCard(icon, label) {
  const card = document.createElement('div');
  card.className = 'file-type-card';
  card.setAttribute('role', 'img');
  card.setAttribute('aria-label', `${label} file`);

  const symbol = document.createElement('span');
  symbol.className = 'file-type-icon';
  symbol.setAttribute('aria-hidden', 'true');
  symbol.textContent = icon;

  const description = document.createElement('span');
  description.className = 'file-type-label';
  description.textContent = label;
  card.append(symbol, description);
  filePreview.appendChild(card);
}

if (mimeType.startsWith('image/') || imageExtensions.includes(extension)) {
  const image = document.createElement('img');
  image.src = url;
  image.alt = 'Uploaded image preview';
  image.width = PREVIEW_WIDTH;
  image.addEventListener('error', () => {
    image.remove();
    showTypeCard('🖼️', 'Image');
  }, { once: true });
  filePreview.appendChild(image);
} else if (mimeType.startsWith('video/') || videoExtensions.includes(extension)) {
  showTypeCard('▶', 'Video');
  const video = document.createElement('video');
  video.src = url;
  video.width = PREVIEW_WIDTH;
  video.controls = true;
  video.preload = 'metadata';
  filePreview.appendChild(video);
} else if (mimeType.startsWith('audio/') || audioExtensions.includes(extension)) {
  showTypeCard('♫', 'Audio');
  const audio = document.createElement('audio');
  audio.src = url;
  audio.controls = true;
  filePreview.appendChild(audio);
} else {
  const types = {
    pdf: ['📕', 'PDF document'],
    zip: ['🗜', 'Archive'],
    rar: ['🗜', 'Archive'],
    '7z': ['🗜', 'Archive'],
    gz: ['🗜', 'Archive'],
    doc: ['📄', 'Document'],
    docx: ['📄', 'Document'],
    txt: ['📝', 'Text file'],
    csv: ['📊', 'Spreadsheet'],
    xls: ['📊', 'Spreadsheet'],
    xlsx: ['📊', 'Spreadsheet'],
    ppt: ['📽', 'Presentation'],
    pptx: ['📽', 'Presentation'],
    js: ['</>', 'Code'],
    ts: ['</>', 'Code'],
    py: ['</>', 'Code'],
    json: ['{ }', 'Data file'],
    apk: ['📦', 'Android app'],
    exe: ['⚙', 'Application'],
  };
  const knownType = mimeType === 'application/pdf'
    ? 'pdf'
    : mimeType.startsWith('text/')
      ? 'txt'
      : mimeType.includes('spreadsheet')
        ? 'xlsx'
        : mimeType.includes('presentation')
          ? 'pptx'
          : '';
  const fallback = knownType ? types[knownType] : ['📦', 'File'];
  const [icon, label] = types[extension] || fallback;
  showTypeCard(icon, label);
}
