// `url` is defined in data.ejs before this file is loaded.
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

const uploadArea = document.getElementById('uploadArea');
const filePreview = document.getElementById('filePreview');
const fileExtension = url.split('.').pop().toLowerCase();
const PREVIEW_WIDTH = 150;

if (fileExtension === 'mp4') {
  const video = document.createElement('video');
  video.src = url;
  video.width = PREVIEW_WIDTH;
  video.controls = true;
  filePreview.appendChild(video);
} else if (['jpg', 'jpeg', 'png', 'gif', 'bmp'].includes(fileExtension)) {
  const image = document.createElement('img');
  image.src = url;
  image.width = PREVIEW_WIDTH;
  filePreview.appendChild(image);
} else {
  const customImage = document.createElement('img');
  customImage.src = 'https://telegra.ph/file/8acbc9aa6ef4a64595c24.jpg';
  customImage.width = PREVIEW_WIDTH;
  filePreview.appendChild(customImage);
}
