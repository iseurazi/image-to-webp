(function () {
  'use strict';

  const ACCEPTED_MIME_TYPES = new Set([
    'image/jpeg',
    'image/jpg',
    'image/png',
    'image/bmp',
    'image/x-ms-bmp',
    'image/gif',
    'image/webp',
    'image/avif',
    'image/x-icon',
    'image/vnd.microsoft.icon',
    'image/tiff'
  ]);

  const ACCEPTED_EXTENSIONS = new Set([
    'jpg',
    'jpeg',
    'jfif',
    'pjpeg',
    'pjp',
    'png',
    'bmp',
    'dib',
    'gif',
    'webp',
    'avif',
    'ico',
    'tif',
    'tiff'
  ]);

  const MAX_CONCURRENCY = Math.min(
    4,
    Math.max(2, (typeof navigator !== 'undefined' && navigator.hardwareConcurrency) || 4)
  );

  const QUALITY_DEBOUNCE_MS = 140;
  const MAX_DIRECT_ALPHA_PIXELS = 25000000;

  // Precomputed IEEE 802.3 CRC-32 lookup table
  const CRC32_TABLE = (function buildCrc32Table() {
    const table = new Uint32Array(256);
    for (let i = 0; i < 256; i++) {
      let c = i;
      for (let k = 0; k < 8; k++) {
        c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
      }
      table[i] = c >>> 0;
    }
    return table;
  })();

  function computeCrc32(bytes) {
    let crc = 0xffffffff;
    for (let i = 0; i < bytes.length; i++) {
      crc = CRC32_TABLE[(crc ^ bytes[i]) & 0xff] ^ (crc >>> 8);
    }
    return (crc ^ 0xffffffff) >>> 0;
  }

  function toDosDateTime(dateInput) {
    const d = dateInput instanceof Date ? dateInput : new Date(dateInput || Date.now());
    const year = Math.max(1980, Math.min(2107, d.getFullYear()));
    const month = d.getMonth() + 1;
    const day = d.getDate();
    const hours = d.getHours();
    const minutes = d.getMinutes();
    const seconds = Math.floor(d.getSeconds() / 2);

    const dosTime = ((hours & 0x1f) << 11) | ((minutes & 0x3f) << 5) | (seconds & 0x1f);
    const dosDate = (((year - 1980) & 0x7f) << 9) | ((month & 0x0f) << 5) | (day & 0x1f);
    return { dosTime, dosDate };
  }

  /**
   * Build a standard PKZIP 2.0 STORE-method archive (UTF-8 filenames supported).
   * Each entry: { name: string, blob?: Blob, data?: Uint8Array | ArrayBuffer, lastModified?: number | Date }
   */
  async function createZipBlob(entries) {
    const encoder = new TextEncoder();
    const parts = [];
    const centralDirectoryRecords = [];
    let offset = 0;

    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i];
      const nameBytes = encoder.encode(String(entry.name || ('file-' + (i + 1))));

      let payloadBytes;
      if (entry.data instanceof Uint8Array) {
        payloadBytes = entry.data;
      } else if (entry.data instanceof ArrayBuffer) {
        payloadBytes = new Uint8Array(entry.data);
      } else if (entry.blob && typeof entry.blob.arrayBuffer === 'function') {
        payloadBytes = new Uint8Array(await entry.blob.arrayBuffer());
      } else {
        payloadBytes = new Uint8Array(0);
      }

      const crc = computeCrc32(payloadBytes);
      const size = payloadBytes.byteLength >>> 0;
      const { dosTime, dosDate } = toDosDateTime(entry.lastModified);

      // Local File Header (30 bytes + filename length)
      const localHeader = new ArrayBuffer(30 + nameBytes.length);
      const lhView = new DataView(localHeader);
      lhView.setUint32(0, 0x04034b50, true); // signature
      lhView.setUint16(4, 20, true);         // version needed to extract (2.0)
      lhView.setUint16(6, 0x0800, true);     // UTF-8 filename flag
      lhView.setUint16(8, 0, true);          // compression method: 0 (STORE)
      lhView.setUint16(10, dosTime, true);   // mod time
      lhView.setUint16(12, dosDate, true);   // mod date
      lhView.setUint32(14, crc, true);       // crc-32
      lhView.setUint32(18, size, true);      // compressed size
      lhView.setUint32(22, size, true);      // uncompressed size
      lhView.setUint16(26, nameBytes.length, true); // file name length
      lhView.setUint16(28, 0, true);         // extra field length
      new Uint8Array(localHeader, 30).set(nameBytes);

      parts.push(localHeader);
      parts.push(payloadBytes);

      // Central Directory File Header (46 bytes + filename length)
      const centralHeader = new ArrayBuffer(46 + nameBytes.length);
      const cdView = new DataView(centralHeader);
      cdView.setUint32(0, 0x02014b50, true); // signature
      cdView.setUint16(4, 20, true);         // version made by
      cdView.setUint16(6, 20, true);         // version needed to extract
      cdView.setUint16(8, 0x0800, true);     // UTF-8 filename flag
      cdView.setUint16(10, 0, true);         // compression method: 0 (STORE)
      cdView.setUint16(12, dosTime, true);   // mod time
      cdView.setUint16(14, dosDate, true);   // mod date
      cdView.setUint32(16, crc, true);       // crc-32
      cdView.setUint32(20, size, true);      // compressed size
      cdView.setUint32(24, size, true);      // uncompressed size
      cdView.setUint16(28, nameBytes.length, true); // file name length
      cdView.setUint16(30, 0, true);         // extra field length
      cdView.setUint16(32, 0, true);         // file comment length
      cdView.setUint16(34, 0, true);         // disk number start
      cdView.setUint16(36, 0, true);         // internal file attributes
      cdView.setUint32(38, 0, true);         // external file attributes
      cdView.setUint32(42, offset >>> 0, true); // relative offset of local header
      new Uint8Array(centralHeader, 46).set(nameBytes);

      centralDirectoryRecords.push(centralHeader);
      offset += localHeader.byteLength + size;
    }

    let centralDirSize = 0;
    for (let i = 0; i < centralDirectoryRecords.length; i++) {
      parts.push(centralDirectoryRecords[i]);
      centralDirSize += centralDirectoryRecords[i].byteLength;
    }

    // End of Central Directory Record (22 bytes)
    const eocd = new ArrayBuffer(22);
    const eocdView = new DataView(eocd);
    eocdView.setUint32(0, 0x06054b50, true); // signature
    eocdView.setUint16(4, 0, true);          // number of this disk
    eocdView.setUint16(6, 0, true);          // disk where central dir starts
    eocdView.setUint16(8, entries.length, true);  // entries on this disk
    eocdView.setUint16(10, entries.length, true); // total entries
    eocdView.setUint32(12, centralDirSize >>> 0, true); // size of central dir
    eocdView.setUint32(16, offset >>> 0, true);         // offset of central dir
    eocdView.setUint16(20, 0, true);         // comment length
    parts.push(eocd);

    return new Blob(parts, { type: 'application/zip' });
  }

  function getFileExtension(filename) {
    const name = String(filename || '');
    const lastDot = name.lastIndexOf('.');
    if (lastDot <= 0 || lastDot === name.length - 1) {
      return '';
    }
    return name.slice(lastDot + 1).toLowerCase();
  }

  function isStaticBitmapFile(file) {
    if (!file) {
      return false;
    }
    const mime = String(file.type || '').toLowerCase().trim();
    const ext = getFileExtension(file.name);

    // Reject vector SVG formats explicitly
    if (mime === 'image/svg+xml' || mime.indexOf('svg') !== -1 || ext === 'svg' || ext === 'svgz') {
      return false;
    }

    if (mime && mime !== 'application/octet-stream') {
      if (ACCEPTED_MIME_TYPES.has(mime)) {
        return true;
      }
      if (mime.startsWith('image/') && ACCEPTED_EXTENSIONS.has(ext)) {
        return true;
      }
      return false;
    }

    return ACCEPTED_EXTENSIONS.has(ext);
  }

  function toWebpFileName(filename) {
    const name = String(filename || 'image').trim() || 'image';
    const lastDot = name.lastIndexOf('.');
    if (lastDot > 0) {
      return name.slice(0, lastDot) + '.webp';
    }
    return name + '.webp';
  }

  function deduplicateFileName(name, usedLowerSet) {
    const baseName = String(name || 'image.webp');
    let candidate = baseName;
    if (!usedLowerSet.has(candidate.toLowerCase())) {
      usedLowerSet.add(candidate.toLowerCase());
      return candidate;
    }

    const lastDot = baseName.lastIndexOf('.');
    const stem = lastDot > 0 ? baseName.slice(0, lastDot) : baseName;
    const ext = lastDot > 0 ? baseName.slice(lastDot) : '';
    let counter = 1;
    while (usedLowerSet.has(candidate.toLowerCase())) {
      candidate = stem + ' (' + counter + ')' + ext;
      counter += 1;
    }
    usedLowerSet.add(candidate.toLowerCase());
    return candidate;
  }

  function formatBytes(bytes) {
    if (!Number.isFinite(bytes) || bytes < 0) {
      return '0 B';
    }
    if (bytes < 1024) {
      return Math.round(bytes) + ' B';
    }
    const units = ['KB', 'MB', 'GB'];
    let value = bytes / 1024;
    let unitIndex = 0;
    while (value >= 1024 && unitIndex < units.length - 1) {
      value /= 1024;
      unitIndex += 1;
    }
    const decimals = value >= 100 ? 0 : value >= 10 ? 1 : 2;
    return value.toFixed(decimals) + ' ' + units[unitIndex];
  }

  function clampQuality(val, fallback) {
    const num = Math.round(Number(val));
    if (!Number.isFinite(num)) {
      return fallback;
    }
    return Math.min(100, Math.max(1, num));
  }

  const helpers = {
    createZipBlob,
    isStaticBitmapFile,
    toWebpFileName,
    formatBytes
  };

  if (typeof window !== 'undefined') {
    window.WebPConverterHelpers = helpers;
  } else if (typeof globalThis !== 'undefined') {
    globalThis.WebPConverterHelpers = helpers;
  }

  if (typeof document === 'undefined') {
    return;
  }

  // Application State
  const state = {
    items: [],
    itemsById: new Map(),
    cardRefs: new Map(),
    nextId: 1,
    clipboardSeq: 1,
    globalQuality: 85,
    queue: [],
    activeWorkers: 0,
    activeModalId: null,
    modalBgMode: 'checkerboard',
    dragDepth: 0,
    isZipping: false
  };

  // DOM References
  const dom = {};

  function cacheDom() {
    dom.browserWarning = document.getElementById('browserWarning');
    dom.dropzone = document.getElementById('dropzone');
    dom.fileInput = document.getElementById('fileInput');
    dom.summaryCount = document.getElementById('summaryCount');
    dom.summarySize = document.getElementById('summarySize');
    dom.summarySavings = document.getElementById('summarySavings');
    dom.globalQualityRange = document.getElementById('globalQualityRange');
    dom.globalQualityNumber = document.getElementById('globalQualityNumber');
    dom.applyGlobalQualityBtn = document.getElementById('applyGlobalQualityBtn');
    dom.downloadAllBtn = document.getElementById('downloadAllBtn');
    dom.clearAllBtn = document.getElementById('clearAllBtn');
    dom.batchProgress = document.getElementById('batchProgress');
    dom.batchProgressBar = document.getElementById('batchProgressBar');
    dom.emptyState = document.getElementById('emptyState');
    dom.imageList = document.getElementById('imageList');
    dom.dragOverlay = document.getElementById('dragOverlay');
    dom.previewModal = document.getElementById('previewModal');
    dom.modalTitle = document.getElementById('modalTitle');
    dom.modalMeta = document.getElementById('modalMeta');
    dom.closeModalBtn = document.getElementById('closeModalBtn');
    dom.modalOriginalStage = document.getElementById('modalOriginalStage');
    dom.modalConvertedStage = document.getElementById('modalConvertedStage');
    dom.modalOriginalImg = document.getElementById('modalOriginalImg');
    dom.modalConvertedImg = document.getElementById('modalConvertedImg');
    dom.modalOriginalInfo = document.getElementById('modalOriginalInfo');
    dom.modalConvertedInfo = document.getElementById('modalConvertedInfo');
    dom.modalQualityRange = document.getElementById('modalQualityRange');
    dom.modalQualityNumber = document.getElementById('modalQualityNumber');
    dom.modalDownloadBtn = document.getElementById('modalDownloadBtn');
    dom.bgModeBtns = Array.from(document.querySelectorAll('.bg-mode-btn'));
    dom.toastContainer = document.getElementById('toastContainer');
  }

  function checkWebpEncodingSupport() {
    try {
      const testCanvas = document.createElement('canvas');
      testCanvas.width = 1;
      testCanvas.height = 1;
      const dataUrl = testCanvas.toDataURL('image/webp');
      return typeof dataUrl === 'string' && dataUrl.startsWith('data:image/webp');
    } catch (_) {
      return false;
    }
  }

  function showToast(message, type) {
    const toast = document.createElement('div');
    toast.className = 'toast' + (type ? ' toast-' + type : '');
    toast.textContent = message;
    dom.toastContainer.appendChild(toast);
    setTimeout(function () {
      if (toast.parentNode) {
        toast.parentNode.removeChild(toast);
      }
    }, 3600);
  }

  function triggerDownload(url, filename) {
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    link.rel = 'noopener';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  }

  function decodeBitmapViaImageElement(file) {
    return new Promise(function (resolve, reject) {
      const tempUrl = URL.createObjectURL(file);
      const img = new Image();
      img.onload = function () {
        URL.revokeObjectURL(tempUrl);
        const width = img.naturalWidth || img.width;
        const height = img.naturalHeight || img.height;
        if (!width || !height) {
          reject(new Error('이미지 크기를 읽을 수 없습니다.'));
          return;
        }
        resolve({ source: img, width, height, isBitmap: false });
      };
      img.onerror = function () {
        URL.revokeObjectURL(tempUrl);
        reject(new Error('브라우저에서 이미지를 디코딩할 수 없습니다.'));
      };
      img.src = tempUrl;
    });
  }

  async function decodeBitmap(file) {
    if (typeof createImageBitmap === 'function') {
      try {
        let bitmap;
        try {
          bitmap = await createImageBitmap(file, { imageOrientation: 'from-image' });
        } catch (_) {
          bitmap = await createImageBitmap(file);
        }
        if (bitmap && bitmap.width > 0 && bitmap.height > 0) {
          return {
            source: bitmap,
            width: bitmap.width,
            height: bitmap.height,
            isBitmap: true
          };
        }
        if (bitmap && typeof bitmap.close === 'function') {
          bitmap.close();
        }
      } catch (_) {
        // Fallback to HTMLImageElement below
      }
    }
    return decodeBitmapViaImageElement(file);
  }

  function detectTransparency(ctx, width, height, mimeType) {
    const mime = String(mimeType || '').toLowerCase();
    if (mime === 'image/jpeg' || mime === 'image/jpg') {
      return false;
    }

    const totalPixels = width * height;
    if (totalPixels > MAX_DIRECT_ALPHA_PIXELS) {
      const scale = Math.min(1, 1024 / Math.max(width, height));
      const sw = Math.max(1, Math.round(width * scale));
      const sh = Math.max(1, Math.round(height * scale));
      const probeCanvas = document.createElement('canvas');
      probeCanvas.width = sw;
      probeCanvas.height = sh;
      try {
        const probeCtx = probeCanvas.getContext('2d', { alpha: true });
        probeCtx.clearRect(0, 0, sw, sh);
        probeCtx.drawImage(ctx.canvas, 0, 0, sw, sh);
        const data = probeCtx.getImageData(0, 0, sw, sh).data;
        for (let i = 3; i < data.length; i += 4) {
          if (data[i] < 255) {
            return true;
          }
        }
        return false;
      } finally {
        probeCanvas.width = 0;
        probeCanvas.height = 0;
      }
    }

    const data = ctx.getImageData(0, 0, width, height).data;
    for (let i = 3; i < data.length; i += 4) {
      if (data[i] < 255) {
        return true;
      }
    }
    return false;
  }

  function canvasToWebpBlob(canvas, qualityRatio) {
    return new Promise(function (resolve, reject) {
      try {
        canvas.toBlob(
          function (blob) {
            if (!blob || blob.type !== 'image/webp') {
              reject(new Error('WebP 인코딩에 실패했습니다.'));
              return;
            }
            resolve(blob);
          },
          'image/webp',
          qualityRatio
        );
      } catch (err) {
        reject(err);
      }
    });
  }

  async function convertItemToWebp(item) {
    const decoded = await decodeBitmap(item.file);
    const canvas = document.createElement('canvas');
    canvas.width = decoded.width;
    canvas.height = decoded.height;

    try {
      const ctx = canvas.getContext('2d', { alpha: true });
      if (!ctx) {
        throw new Error('2D Canvas 컨텍스트를 생성할 수 없습니다.');
      }
      // Preserve alpha transparency without painting any background fill
      ctx.clearRect(0, 0, decoded.width, decoded.height);
      ctx.drawImage(decoded.source, 0, 0, decoded.width, decoded.height);

      let hasTransparency = item.hasTransparency;
      if (hasTransparency === null) {
        hasTransparency = detectTransparency(ctx, decoded.width, decoded.height, item.file.type);
      }

      const blob = await canvasToWebpBlob(canvas, item.quality / 100);
      return {
        blob,
        width: decoded.width,
        height: decoded.height,
        hasTransparency
      };
    } finally {
      if (decoded.isBitmap && decoded.source && typeof decoded.source.close === 'function') {
        decoded.source.close();
      }
      canvas.width = 0;
      canvas.height = 0;
    }
  }

  // Conversion Queue Management
  function enqueueConversion(item) {
    if (!state.itemsById.has(item.id)) {
      return;
    }
    if (item.debounceTimer) {
      clearTimeout(item.debounceTimer);
      item.debounceTimer = null;
    }

    item.conversionToken += 1;
    item.lastEnqueuedQuality = item.quality;

    // Coalesce any existing queued job for this item
    for (let i = state.queue.length - 1; i >= 0; i--) {
      if (state.queue[i].item.id === item.id) {
        state.queue.splice(i, 1);
      }
    }

    item.status = 'queued';
    item.errorMessage = '';
    state.queue.push({ item, token: item.conversionToken });

    updateCardElement(item);
    updateToolbarSummary();
    if (state.activeModalId === item.id) {
      updateModalContent(item);
    }

    drainQueue();
  }

  function scheduleQualityConversion(item) {
    if (item.debounceTimer) {
      clearTimeout(item.debounceTimer);
    }
    item.debounceTimer = setTimeout(function () {
      item.debounceTimer = null;
      enqueueConversion(item);
    }, QUALITY_DEBOUNCE_MS);
  }

  function drainQueue() {
    while (state.activeWorkers < MAX_CONCURRENCY && state.queue.length > 0) {
      const job = state.queue.shift();
      const item = job.item;

      if (!state.itemsById.has(item.id) || job.token !== item.conversionToken) {
        continue;
      }

      state.activeWorkers += 1;
      item.status = 'converting';
      updateCardElement(item);
      updateToolbarSummary();

      convertItemToWebp(item)
        .then(function (result) {
          if (!state.itemsById.has(item.id) || job.token !== item.conversionToken) {
            return;
          }
          if (item.outputUrl) {
            URL.revokeObjectURL(item.outputUrl);
          }
          item.outputBlob = result.blob;
          item.outputUrl = URL.createObjectURL(result.blob);
          item.outputSize = result.blob.size;
          item.width = result.width;
          item.height = result.height;
          item.hasTransparency = result.hasTransparency;
          item.status = 'done';
          item.errorMessage = '';
        })
        .catch(function (err) {
          if (!state.itemsById.has(item.id) || job.token !== item.conversionToken) {
            return;
          }
          item.status = 'error';
          item.errorMessage = err && err.message ? err.message : '변환 중 오류가 발생했습니다.';
        })
        .finally(function () {
          state.activeWorkers -= 1;
          if (state.itemsById.has(item.id) && job.token === item.conversionToken) {
            updateCardElement(item);
            if (state.activeModalId === item.id) {
              updateModalContent(item);
            }
          }
          updateToolbarSummary();
          drainQueue();
        });
    }
  }

  // Savings Helper
  function computeSavingsDisplay(originalBytes, outputBytes) {
    if (!originalBytes || !Number.isFinite(outputBytes)) {
      return { text: '', className: 'savings-pill is-neutral' };
    }
    const diffPercent = ((outputBytes - originalBytes) / originalBytes) * 100;
    const rounded = Math.round(Math.abs(diffPercent));
    if (diffPercent < -0.5) {
      return { text: '-' + rounded + '% 절감', className: 'savings-pill is-saved' };
    }
    if (diffPercent > 0.5) {
      return { text: '+' + rounded + '% 증가', className: 'savings-pill is-larger' };
    }
    return { text: '0% 동일', className: 'savings-pill is-neutral' };
  }

  function createSvgIcon(pathD, viewBox, className) {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    if (className) {
      svg.setAttribute('class', className);
    }
    svg.setAttribute('viewBox', viewBox || '0 0 20 20');
    svg.setAttribute('fill', 'none');
    svg.setAttribute('stroke', 'currentColor');
    svg.setAttribute('stroke-width', '1.8');
    svg.setAttribute('aria-hidden', 'true');
    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('stroke-linecap', 'round');
    path.setAttribute('stroke-linejoin', 'round');
    path.setAttribute('d', pathD);
    svg.appendChild(path);
    return svg;
  }

  // Build Card DOM safely without HTML string interpolation
  function createCardElement(item) {
    const li = document.createElement('li');
    li.className = 'image-card';
    li.dataset.itemId = String(item.id);

    // 1. Thumbnail button
    const thumbBtn = document.createElement('button');
    thumbBtn.type = 'button';
    thumbBtn.className = 'thumb-button checkerboard';
    thumbBtn.title = '원본과 비교 미리보기';
    thumbBtn.setAttribute('aria-label', item.originalName + ' 비교 미리보기');

    const thumbImg = document.createElement('img');
    thumbImg.className = 'thumb-img';
    thumbImg.src = item.originalUrl;
    thumbImg.alt = item.originalName;
    thumbImg.decoding = 'async';

    const alphaBadge = document.createElement('span');
    alphaBadge.className = 'alpha-badge';
    alphaBadge.textContent = '투명';
    alphaBadge.hidden = true;

    const zoomHint = document.createElement('span');
    zoomHint.className = 'thumb-zoom-hint';
    zoomHint.textContent = '확대';

    thumbBtn.appendChild(thumbImg);
    thumbBtn.appendChild(alphaBadge);
    thumbBtn.appendChild(zoomHint);

    thumbBtn.addEventListener('click', function () {
      openPreviewModal(item.id);
    });

    // 2. Info column
    const infoCol = document.createElement('div');
    infoCol.className = 'card-info';

    const namesRow = document.createElement('div');
    namesRow.className = 'card-names';

    const origNameEl = document.createElement('span');
    origNameEl.className = 'file-name-orig';
    origNameEl.textContent = item.originalName;
    origNameEl.title = item.originalName;

    const arrowEl = document.createElement('span');
    arrowEl.className = 'name-arrow';
    arrowEl.textContent = '→';
    arrowEl.setAttribute('aria-hidden', 'true');

    const webpNameEl = document.createElement('span');
    webpNameEl.className = 'file-name-webp';
    webpNameEl.textContent = item.outputName;
    webpNameEl.title = item.outputName;

    namesRow.appendChild(origNameEl);
    namesRow.appendChild(arrowEl);
    namesRow.appendChild(webpNameEl);

    const metaRow = document.createElement('div');
    metaRow.className = 'card-meta-row';

    const statusBadge = document.createElement('span');
    statusBadge.className = 'status-badge status-queued';
    statusBadge.textContent = '대기 중';

    const dimText = document.createElement('span');
    dimText.className = 'dim-text';
    dimText.hidden = true;

    const sizeText = document.createElement('span');
    sizeText.className = 'size-text';
    sizeText.textContent = formatBytes(item.originalSize);

    const savingsBadge = document.createElement('span');
    savingsBadge.className = 'savings-pill is-neutral';
    savingsBadge.hidden = true;

    metaRow.appendChild(statusBadge);
    metaRow.appendChild(dimText);
    metaRow.appendChild(sizeText);
    metaRow.appendChild(savingsBadge);

    const errorText = document.createElement('p');
    errorText.className = 'card-error-text';
    errorText.hidden = true;

    infoCol.appendChild(namesRow);
    infoCol.appendChild(metaRow);
    infoCol.appendChild(errorText);

    // 3. Per-image quality controls
    const qualityCol = document.createElement('div');
    qualityCol.className = 'card-quality';

    const qualityHeader = document.createElement('div');
    qualityHeader.className = 'card-quality-header';
    const qualityLabel = document.createElement('label');
    const sliderId = 'quality-range-' + item.id;
    qualityLabel.setAttribute('for', sliderId);
    qualityLabel.textContent = '개별 품질 (Quality)';
    qualityHeader.appendChild(qualityLabel);

    const qualityInputs = document.createElement('div');
    qualityInputs.className = 'card-quality-inputs';

    const qualityRange = document.createElement('input');
    qualityRange.type = 'range';
    qualityRange.id = sliderId;
    qualityRange.className = 'quality-slider';
    qualityRange.min = '1';
    qualityRange.max = '100';
    qualityRange.value = String(item.quality);
    qualityRange.setAttribute('aria-label', item.originalName + ' 변환 품질 슬라이더');

    const numWrap = document.createElement('div');
    numWrap.className = 'quality-number-wrap';

    const qualityNumber = document.createElement('input');
    qualityNumber.type = 'number';
    qualityNumber.className = 'quality-number';
    qualityNumber.min = '1';
    qualityNumber.max = '100';
    qualityNumber.value = String(item.quality);
    qualityNumber.setAttribute('aria-label', item.originalName + ' 변환 품질 숫자');

    const unitSpan = document.createElement('span');
    unitSpan.className = 'quality-unit';
    unitSpan.textContent = '%';

    numWrap.appendChild(qualityNumber);
    numWrap.appendChild(unitSpan);
    qualityInputs.appendChild(qualityRange);
    qualityInputs.appendChild(numWrap);

    qualityCol.appendChild(qualityHeader);
    qualityCol.appendChild(qualityInputs);

    // Per-card quality listeners
    qualityRange.addEventListener('input', function () {
      const q = clampQuality(qualityRange.value, item.quality);
      item.quality = q;
      qualityNumber.value = String(q);
      if (state.activeModalId === item.id) {
        dom.modalQualityRange.value = String(q);
        dom.modalQualityNumber.value = String(q);
      }
      scheduleQualityConversion(item);
    });

    qualityRange.addEventListener('change', function () {
      const q = clampQuality(qualityRange.value, item.quality);
      item.quality = q;
      qualityNumber.value = String(q);
      if (state.activeModalId === item.id) {
        dom.modalQualityRange.value = String(q);
        dom.modalQualityNumber.value = String(q);
      }
      if (item.debounceTimer || item.lastEnqueuedQuality !== q) {
        enqueueConversion(item);
      }
    });

    qualityNumber.addEventListener('input', function () {
      const raw = qualityNumber.value.trim();
      if (raw === '') {
        return;
      }
      const parsed = Number(raw);
      if (!Number.isInteger(parsed) || parsed < 1 || parsed > 100) {
        return;
      }
      item.quality = parsed;
      qualityRange.value = String(parsed);
      if (state.activeModalId === item.id) {
        dom.modalQualityRange.value = String(parsed);
        dom.modalQualityNumber.value = String(parsed);
      }
      scheduleQualityConversion(item);
    });

    function commitCardNumberInput() {
      const q = clampQuality(qualityNumber.value, item.quality);
      item.quality = q;
      qualityNumber.value = String(q);
      qualityRange.value = String(q);
      if (state.activeModalId === item.id) {
        dom.modalQualityRange.value = String(q);
        dom.modalQualityNumber.value = String(q);
      }
      if (item.debounceTimer || item.lastEnqueuedQuality !== q) {
        enqueueConversion(item);
      }
    }

    qualityNumber.addEventListener('change', commitCardNumberInput);
    qualityNumber.addEventListener('blur', commitCardNumberInput);

    // 4. Actions column
    const actionsCol = document.createElement('div');
    actionsCol.className = 'card-actions';

    const previewBtn = document.createElement('button');
    previewBtn.type = 'button';
    previewBtn.className = 'btn btn-secondary btn-sm';
    previewBtn.textContent = '미리보기';
    previewBtn.addEventListener('click', function () {
      openPreviewModal(item.id);
    });

    const downloadBtn = document.createElement('button');
    downloadBtn.type = 'button';
    downloadBtn.className = 'btn btn-primary btn-sm';
    downloadBtn.disabled = true;
    downloadBtn.appendChild(
      createSvgIcon(
        'M10 3v9m0 0-3.5-3.5M10 12l3.5-3.5M4 14.5v1A1.5 1.5 0 0 0 5.5 17h9a1.5 1.5 0 0 0 1.5-1.5v-1',
        '0 0 20 20',
        'btn-icon'
      )
    );
    const dlLabel = document.createElement('span');
    dlLabel.textContent = '다운로드';
    downloadBtn.appendChild(dlLabel);
    downloadBtn.addEventListener('click', function () {
      if (item.status === 'done' && item.outputUrl) {
        triggerDownload(item.outputUrl, item.outputName);
      }
    });

    const removeBtn = document.createElement('button');
    removeBtn.type = 'button';
    removeBtn.className = 'btn-icon-only is-danger';
    removeBtn.title = '목록에서 삭제';
    removeBtn.setAttribute('aria-label', item.originalName + ' 삭제');
    removeBtn.appendChild(createSvgIcon('M5 5l10 10M15 5 5 15'));
    removeBtn.addEventListener('click', function () {
      removeItem(item.id);
    });

    actionsCol.appendChild(previewBtn);
    actionsCol.appendChild(downloadBtn);
    actionsCol.appendChild(removeBtn);

    li.appendChild(thumbBtn);
    li.appendChild(infoCol);
    li.appendChild(qualityCol);
    li.appendChild(actionsCol);

    state.cardRefs.set(item.id, {
      li,
      thumbImg,
      alphaBadge,
      statusBadge,
      dimText,
      sizeText,
      savingsBadge,
      errorText,
      qualityRange,
      qualityNumber,
      downloadBtn
    });

    return li;
  }

  function updateCardElement(item) {
    const refs = state.cardRefs.get(item.id);
    if (!refs) {
      return;
    }

    if (item.outputUrl && refs.thumbImg.src !== item.outputUrl) {
      refs.thumbImg.src = item.outputUrl;
    } else if (!item.outputUrl && refs.thumbImg.src !== item.originalUrl) {
      refs.thumbImg.src = item.originalUrl;
    }

    refs.alphaBadge.hidden = !item.hasTransparency;

    const statusLabels = {
      queued: '대기 중',
      converting: '변환 중',
      done: '완료',
      error: '오류'
    };
    refs.statusBadge.className = 'status-badge status-' + item.status;
    refs.statusBadge.textContent = statusLabels[item.status] || '대기 중';

    if (item.width && item.height) {
      refs.dimText.textContent = item.width + '×' + item.height;
      refs.dimText.hidden = false;
    } else {
      refs.dimText.hidden = true;
    }

    if (item.status === 'done' && Number.isFinite(item.outputSize)) {
      refs.sizeText.textContent = formatBytes(item.originalSize) + ' → ' + formatBytes(item.outputSize);
      const savings = computeSavingsDisplay(item.originalSize, item.outputSize);
      refs.savingsBadge.className = savings.className;
      refs.savingsBadge.textContent = savings.text;
      refs.savingsBadge.hidden = false;
    } else {
      refs.sizeText.textContent = formatBytes(item.originalSize);
      refs.savingsBadge.hidden = true;
    }

    if (item.status === 'error' && item.errorMessage) {
      refs.errorText.textContent = item.errorMessage;
      refs.errorText.hidden = false;
    } else {
      refs.errorText.hidden = true;
    }

    if (document.activeElement !== refs.qualityRange) {
      refs.qualityRange.value = String(item.quality);
    }
    if (document.activeElement !== refs.qualityNumber) {
      refs.qualityNumber.value = String(item.quality);
    }

    refs.downloadBtn.disabled = !(item.status === 'done' && item.outputUrl);
  }

  function updateToolbarSummary() {
    const totalCount = state.items.length;
    let doneCount = 0;
    let processedCount = 0;
    let totalOrig = 0;
    let doneOrig = 0;
    let doneWebp = 0;
    let hasActiveJobs = false;

    for (let i = 0; i < state.items.length; i++) {
      const it = state.items[i];
      totalOrig += it.originalSize;
      if (it.status === 'done') {
        doneCount += 1;
        processedCount += 1;
        doneOrig += it.originalSize;
        doneWebp += it.outputSize || 0;
      } else if (it.status === 'error') {
        processedCount += 1;
      } else {
        hasActiveJobs = true;
      }
    }

    dom.emptyState.hidden = totalCount > 0;
    dom.applyGlobalQualityBtn.disabled = totalCount === 0;
    dom.clearAllBtn.disabled = totalCount === 0;
    dom.downloadAllBtn.disabled = doneCount === 0 || state.isZipping;

    dom.summaryCount.textContent = totalCount + '개 파일 · ' + doneCount + '개 완료';

    if (doneCount > 0) {
      const sizeSummary = '원본 ' + formatBytes(doneOrig) + ' → WebP ' + formatBytes(doneWebp);
      dom.summarySize.textContent = sizeSummary;
      const savings = computeSavingsDisplay(doneOrig, doneWebp);
      dom.summarySavings.className = savings.className;
      dom.summarySavings.textContent = savings.text;
      dom.summarySavings.hidden = false;
    } else {
      dom.summarySize.textContent = '원본 ' + formatBytes(totalOrig) + ' → WebP 0 B';
      dom.summarySavings.hidden = true;
    }

    if (totalCount > 0 && hasActiveJobs) {
      const pct = Math.round((processedCount / totalCount) * 100);
      dom.batchProgress.hidden = false;
      dom.batchProgressBar.style.width = pct + '%';
      dom.batchProgressBar.setAttribute('aria-valuenow', String(pct));
    } else {
      dom.batchProgress.hidden = true;
      dom.batchProgressBar.style.width = '0%';
      dom.batchProgressBar.setAttribute('aria-valuenow', '0');
    }
  }

  function addFiles(fileList) {
    const incoming = Array.from(fileList || []);
    if (incoming.length === 0) {
      return;
    }

    let addedCount = 0;
    let rejectedCount = 0;

    for (let i = 0; i < incoming.length; i++) {
      const file = incoming[i];
      if (!isStaticBitmapFile(file)) {
        rejectedCount += 1;
        continue;
      }

      const id = state.nextId++;
      const item = {
        id,
        file,
        originalName: file.name || ('image-' + id),
        outputName: toWebpFileName(file.name || ('image-' + id)),
        originalSize: file.size || 0,
        outputSize: null,
        originalUrl: URL.createObjectURL(file),
        outputUrl: null,
        outputBlob: null,
        width: null,
        height: null,
        hasTransparency: null,
        quality: state.globalQuality,
        lastEnqueuedQuality: null,
        status: 'queued',
        errorMessage: '',
        conversionToken: 0,
        debounceTimer: null
      };

      state.items.push(item);
      state.itemsById.set(id, item);

      const cardEl = createCardElement(item);
      dom.imageList.appendChild(cardEl);
      enqueueConversion(item);
      addedCount += 1;
    }

    updateToolbarSummary();

    if (rejectedCount > 0) {
      showToast(
        '정적 비트맵 이미지가 아닌 파일 ' + rejectedCount + '개를 제외했습니다. (SVG 등 제외)',
        'warning'
      );
    }
    if (addedCount > 0) {
      updateToolbarSummary();
    }
  }

  function removeItem(id) {
    const item = state.itemsById.get(id);
    if (!item) {
      return;
    }
    if (item.debounceTimer) {
      clearTimeout(item.debounceTimer);
      item.debounceTimer = null;
    }
    for (let i = state.queue.length - 1; i >= 0; i--) {
      if (state.queue[i].item.id === id) {
        state.queue.splice(i, 1);
      }
    }
    if (item.originalUrl) {
      URL.revokeObjectURL(item.originalUrl);
    }
    if (item.outputUrl) {
      URL.revokeObjectURL(item.outputUrl);
    }

    state.itemsById.delete(id);
    const idx = state.items.findIndex(function (it) { return it.id === id; });
    if (idx !== -1) {
      state.items.splice(idx, 1);
    }

    const refs = state.cardRefs.get(id);
    if (refs && refs.li && refs.li.parentNode) {
      refs.li.parentNode.removeChild(refs.li);
    }
    state.cardRefs.delete(id);

    if (state.activeModalId === id) {
      closePreviewModal();
    }

    updateToolbarSummary();
  }

  function clearAllItems() {
    for (let i = 0; i < state.items.length; i++) {
      const item = state.items[i];
      if (item.debounceTimer) {
        clearTimeout(item.debounceTimer);
        item.debounceTimer = null;
      }
      if (item.originalUrl) {
        URL.revokeObjectURL(item.originalUrl);
      }
      if (item.outputUrl) {
        URL.revokeObjectURL(item.outputUrl);
      }
    }
    state.items = [];
    state.itemsById.clear();
    state.cardRefs.clear();
    state.queue = [];
    dom.imageList.textContent = '';

    if (state.activeModalId !== null) {
      closePreviewModal();
    }
    updateToolbarSummary();
  }

  // Batch ZIP Download
  function formatArchiveTimestamp(date) {
    const pad = function (n) { return String(n).padStart(2, '0'); };
    return (
      date.getFullYear() +
      pad(date.getMonth() + 1) +
      pad(date.getDate()) +
      '-' +
      pad(date.getHours()) +
      pad(date.getMinutes()) +
      pad(date.getSeconds())
    );
  }

  async function handleDownloadAll() {
    const readyItems = state.items.filter(function (it) {
      return it.status === 'done' && it.outputBlob;
    });
    if (readyItems.length === 0 || state.isZipping) {
      return;
    }

    state.isZipping = true;
    const labelEl = dom.downloadAllBtn.querySelector('span');
    const originalBtnText = labelEl ? labelEl.textContent : '일괄 다운로드 (ZIP)';
    if (labelEl) {
      labelEl.textContent = 'ZIP 생성 중...';
    }
    updateToolbarSummary();

    try {
      const usedNames = new Set();
      const zipEntries = readyItems.map(function (it) {
        return {
          name: deduplicateFileName(it.outputName, usedNames),
          blob: it.outputBlob,
          lastModified: it.file && it.file.lastModified ? it.file.lastModified : Date.now()
        };
      });

      const zipBlob = await createZipBlob(zipEntries);
      const zipUrl = URL.createObjectURL(zipBlob);
      const archiveName = 'webp-converted-' + formatArchiveTimestamp(new Date()) + '.zip';
      triggerDownload(zipUrl, archiveName);
      setTimeout(function () {
        URL.revokeObjectURL(zipUrl);
      }, 10000);
      showToast(readyItems.length + '개의 WebP 이미지를 ZIP으로 저장했습니다.', 'success');
    } catch (err) {
      showToast('ZIP 생성 중 오류가 발생했습니다: ' + (err && err.message ? err.message : ''), 'error');
    } finally {
      state.isZipping = false;
      if (labelEl) {
        labelEl.textContent = originalBtnText;
      }
      updateToolbarSummary();
    }
  }

  // Preview Modal
  function applyModalBackgroundMode(mode) {
    state.modalBgMode = mode;
    const stages = [dom.modalOriginalStage, dom.modalConvertedStage];
    for (let i = 0; i < stages.length; i++) {
      stages[i].classList.remove('checkerboard', 'bg-light', 'bg-dark');
      if (mode === 'light') {
        stages[i].classList.add('bg-light');
      } else if (mode === 'dark') {
        stages[i].classList.add('bg-dark');
      } else {
        stages[i].classList.add('checkerboard');
      }
    }
    for (let i = 0; i < dom.bgModeBtns.length; i++) {
      const btn = dom.bgModeBtns[i];
      btn.classList.toggle('is-active', btn.dataset.bgMode === mode);
    }
  }

  function updateModalContent(item) {
    dom.modalTitle.textContent = item.originalName + ' → ' + item.outputName;
    const parts = [];
    if (item.width && item.height) {
      parts.push(item.width + '×' + item.height);
    }
    if (item.hasTransparency) {
      parts.push('투명 배경 유지');
    }
    parts.push('품질 ' + item.quality + '%');
    dom.modalMeta.textContent = parts.join(' · ');

    if (dom.modalOriginalImg.src !== item.originalUrl) {
      dom.modalOriginalImg.src = item.originalUrl;
    }
    dom.modalOriginalInfo.textContent = formatBytes(item.originalSize);

    if (item.status === 'done' && item.outputUrl) {
      if (dom.modalConvertedImg.src !== item.outputUrl) {
        dom.modalConvertedImg.src = item.outputUrl;
      }
      const savings = computeSavingsDisplay(item.originalSize, item.outputSize);
      dom.modalConvertedInfo.textContent = formatBytes(item.outputSize) + ' (' + savings.text + ')';
      dom.modalDownloadBtn.disabled = false;
    } else if (item.status === 'error') {
      dom.modalConvertedImg.removeAttribute('src');
      dom.modalConvertedInfo.textContent = item.errorMessage || '변환 오류';
      dom.modalDownloadBtn.disabled = true;
    } else {
      dom.modalConvertedInfo.textContent = '변환 중...';
      dom.modalDownloadBtn.disabled = true;
    }

    if (document.activeElement !== dom.modalQualityRange) {
      dom.modalQualityRange.value = String(item.quality);
    }
    if (document.activeElement !== dom.modalQualityNumber) {
      dom.modalQualityNumber.value = String(item.quality);
    }
  }

  function openPreviewModal(itemId) {
    const item = state.itemsById.get(itemId);
    if (!item) {
      return;
    }
    state.activeModalId = itemId;
    applyModalBackgroundMode(state.modalBgMode);
    updateModalContent(item);
    dom.previewModal.hidden = false;
    dom.closeModalBtn.focus();
  }

  function closePreviewModal() {
    state.activeModalId = null;
    dom.previewModal.hidden = true;
    dom.modalOriginalImg.removeAttribute('src');
    dom.modalConvertedImg.removeAttribute('src');
  }

  // Recursive Drag-and-Drop Entry Reader
  function readAllDirectoryEntries(dirEntry) {
    return new Promise(function (resolve) {
      const reader = dirEntry.createReader();
      const collected = [];

      function readBatch() {
        reader.readEntries(
          function (batch) {
            if (!batch || batch.length === 0) {
              resolve(collected);
              return;
            }
            for (let i = 0; i < batch.length; i++) {
              collected.push(batch[i]);
            }
            readBatch();
          },
          function () {
            resolve(collected);
          }
        );
      }

      readBatch();
    });
  }

  async function collectFilesFromEntry(entry) {
    if (!entry) {
      return [];
    }
    if (entry.isFile) {
      return new Promise(function (resolve) {
        entry.file(
          function (file) { resolve([file]); },
          function () { resolve([]); }
        );
      });
    }
    if (entry.isDirectory) {
      const childEntries = await readAllDirectoryEntries(entry);
      const nestedLists = await Promise.all(childEntries.map(collectFilesFromEntry));
      const files = [];
      for (let i = 0; i < nestedLists.length; i++) {
        for (let j = 0; j < nestedLists[i].length; j++) {
          files.push(nestedLists[i][j]);
        }
      }
      return files;
    }
    return [];
  }

  async function extractDroppedFiles(dataTransfer) {
    if (!dataTransfer) {
      return [];
    }

    const fallbackFiles = Array.from(dataTransfer.files || []);
    const items = Array.from(dataTransfer.items || []);

    if (items.length === 0) {
      return fallbackFiles;
    }

    const entries = [];
    const directItemFiles = [];

    for (let i = 0; i < items.length; i++) {
      const item = items[i];
      if (item.kind !== 'file') {
        continue;
      }
      const entry = typeof item.webkitGetAsEntry === 'function' ? item.webkitGetAsEntry() : null;
      if (entry) {
        entries.push(entry);
      } else {
        const f = typeof item.getAsFile === 'function' ? item.getAsFile() : null;
        if (f) {
          directItemFiles.push(f);
        }
      }
    }

    if (entries.length === 0) {
      return directItemFiles.length > 0 ? directItemFiles : fallbackFiles;
    }

    const entryFileGroups = await Promise.all(entries.map(collectFilesFromEntry));
    const collected = directItemFiles.slice();
    for (let i = 0; i < entryFileGroups.length; i++) {
      for (let j = 0; j < entryFileGroups[i].length; j++) {
        collected.push(entryFileGroups[i][j]);
      }
    }

    return collected.length > 0 ? collected : fallbackFiles;
  }

  function hasFilesInDataTransfer(dt) {
    if (!dt || !dt.types) {
      return false;
    }
    const types = Array.from(dt.types);
    return types.includes('Files') || types.includes('application/x-moz-file');
  }

  function bindEvents() {
    // Dropzone click / keyboard open
    dom.dropzone.addEventListener('click', function (e) {
      if (e.target === dom.fileInput) {
        return;
      }
      dom.fileInput.click();
    });

    dom.dropzone.addEventListener('keydown', function (e) {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        dom.fileInput.click();
      }
    });

    dom.fileInput.addEventListener('change', function () {
      if (dom.fileInput.files && dom.fileInput.files.length > 0) {
        addFiles(dom.fileInput.files);
      }
      dom.fileInput.value = '';
    });

    // Global Drag & Drop + Dropzone highlight
    window.addEventListener('dragenter', function (e) {
      if (!hasFilesInDataTransfer(e.dataTransfer)) {
        return;
      }
      e.preventDefault();
      state.dragDepth += 1;
      dom.dragOverlay.classList.add('is-visible');
      dom.dropzone.classList.add('is-dragover');
    });

    window.addEventListener('dragover', function (e) {
      if (hasFilesInDataTransfer(e.dataTransfer)) {
        e.preventDefault();
        e.dataTransfer.dropEffect = 'copy';
      }
    });

    window.addEventListener('dragleave', function (e) {
      if (e.relatedTarget === null) {
        state.dragDepth = 0;
        dom.dragOverlay.classList.remove('is-visible');
        dom.dropzone.classList.remove('is-dragover');
        return;
      }
      if (state.dragDepth === 0) {
        return;
      }
      state.dragDepth = Math.max(0, state.dragDepth - 1);
      if (state.dragDepth === 0) {
        dom.dragOverlay.classList.remove('is-visible');
        dom.dropzone.classList.remove('is-dragover');
      }
    });

    window.addEventListener('drop', function (e) {
      e.preventDefault();
      state.dragDepth = 0;
      dom.dragOverlay.classList.remove('is-visible');
      dom.dropzone.classList.remove('is-dragover');

      extractDroppedFiles(e.dataTransfer).then(function (files) {
        if (files.length > 0) {
          addFiles(files);
        }
      });
    });

    // Clipboard Paste
    window.addEventListener('paste', function (e) {
      const clipboard = e.clipboardData;
      if (!clipboard) {
        return;
      }
      const pastedFiles = [];
      const items = Array.from(clipboard.items || []);
      for (let i = 0; i < items.length; i++) {
        if (items[i].kind === 'file') {
          const f = items[i].getAsFile();
          if (f) {
            if (!f.name) {
              const named = new File([f], 'clipboard-image-' + (state.clipboardSeq++) + '.png', {
                type: f.type || 'image/png',
                lastModified: Date.now()
              });
              pastedFiles.push(named);
            } else {
              pastedFiles.push(f);
            }
          }
        }
      }
      if (pastedFiles.length > 0) {
        addFiles(pastedFiles);
      }
    });

    // Global Quality Controls
    dom.globalQualityRange.addEventListener('input', function () {
      const q = clampQuality(dom.globalQualityRange.value, state.globalQuality);
      state.globalQuality = q;
      dom.globalQualityNumber.value = String(q);
    });

    dom.globalQualityNumber.addEventListener('input', function () {
      const raw = dom.globalQualityNumber.value.trim();
      if (raw === '') {
        return;
      }
      const parsed = Number(raw);
      if (Number.isInteger(parsed) && parsed >= 1 && parsed <= 100) {
        state.globalQuality = parsed;
        dom.globalQualityRange.value = String(parsed);
      }
    });

    function commitGlobalNumber() {
      const q = clampQuality(dom.globalQualityNumber.value, state.globalQuality);
      state.globalQuality = q;
      dom.globalQualityNumber.value = String(q);
      dom.globalQualityRange.value = String(q);
    }

    dom.globalQualityNumber.addEventListener('change', commitGlobalNumber);
    dom.globalQualityNumber.addEventListener('blur', commitGlobalNumber);

    dom.applyGlobalQualityBtn.addEventListener('click', function () {
      commitGlobalNumber();
      if (state.items.length === 0) {
        return;
      }
      for (let i = 0; i < state.items.length; i++) {
        const item = state.items[i];
        item.quality = state.globalQuality;
        const refs = state.cardRefs.get(item.id);
        if (refs) {
          refs.qualityRange.value = String(item.quality);
          refs.qualityNumber.value = String(item.quality);
        }
        enqueueConversion(item);
      }
      showToast('모든 이미지 품질을 ' + state.globalQuality + '%로 적용했습니다.', 'success');
    });

    // Batch actions
    dom.downloadAllBtn.addEventListener('click', handleDownloadAll);
    dom.clearAllBtn.addEventListener('click', clearAllItems);

    // Modal controls
    dom.closeModalBtn.addEventListener('click', closePreviewModal);
    dom.previewModal.addEventListener('click', function (e) {
      if (e.target === dom.previewModal) {
        closePreviewModal();
      }
    });

    window.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && !dom.previewModal.hidden) {
        closePreviewModal();
      }
    });

    for (let i = 0; i < dom.bgModeBtns.length; i++) {
      dom.bgModeBtns[i].addEventListener('click', function (e) {
        const mode = e.currentTarget.dataset.bgMode || 'checkerboard';
        applyModalBackgroundMode(mode);
      });
    }

    dom.modalQualityRange.addEventListener('input', function () {
      const item = state.itemsById.get(state.activeModalId);
      if (!item) {
        return;
      }
      const q = clampQuality(dom.modalQualityRange.value, item.quality);
      item.quality = q;
      dom.modalQualityNumber.value = String(q);
      const refs = state.cardRefs.get(item.id);
      if (refs) {
        refs.qualityRange.value = String(q);
        refs.qualityNumber.value = String(q);
      }
      scheduleQualityConversion(item);
    });

    dom.modalQualityRange.addEventListener('change', function () {
      const item = state.itemsById.get(state.activeModalId);
      if (!item) {
        return;
      }
      const q = clampQuality(dom.modalQualityRange.value, item.quality);
      item.quality = q;
      if (item.debounceTimer || item.lastEnqueuedQuality !== q) {
        enqueueConversion(item);
      }
    });

    dom.modalQualityNumber.addEventListener('input', function () {
      const item = state.itemsById.get(state.activeModalId);
      if (!item) {
        return;
      }
      const raw = dom.modalQualityNumber.value.trim();
      if (raw === '') {
        return;
      }
      const parsed = Number(raw);
      if (!Number.isInteger(parsed) || parsed < 1 || parsed > 100) {
        return;
      }
      item.quality = parsed;
      dom.modalQualityRange.value = String(parsed);
      const refs = state.cardRefs.get(item.id);
      if (refs) {
        refs.qualityRange.value = String(parsed);
        refs.qualityNumber.value = String(parsed);
      }
      scheduleQualityConversion(item);
    });

    function commitModalNumber() {
      const item = state.itemsById.get(state.activeModalId);
      if (!item) {
        return;
      }
      const q = clampQuality(dom.modalQualityNumber.value, item.quality);
      item.quality = q;
      dom.modalQualityNumber.value = String(q);
      dom.modalQualityRange.value = String(q);
      const refs = state.cardRefs.get(item.id);
      if (refs) {
        refs.qualityRange.value = String(q);
        refs.qualityNumber.value = String(q);
      }
      if (item.debounceTimer || item.lastEnqueuedQuality !== q) {
        enqueueConversion(item);
      }
    }

    dom.modalQualityNumber.addEventListener('change', commitModalNumber);
    dom.modalQualityNumber.addEventListener('blur', commitModalNumber);

    dom.modalDownloadBtn.addEventListener('click', function () {
      const item = state.itemsById.get(state.activeModalId);
      if (item && item.status === 'done' && item.outputUrl) {
        triggerDownload(item.outputUrl, item.outputName);
      }
    });
  }

  function init() {
    cacheDom();
    if (!checkWebpEncodingSupport()) {
      dom.browserWarning.hidden = false;
    }
    bindEvents();
    updateToolbarSummary();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
