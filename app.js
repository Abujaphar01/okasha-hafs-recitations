// Okasha Kameny Hafs Recitations App Engine (v1.3 Deluxe)

const playlist = [
  {
    id: 1,
    surahNum: 6,
    nameEn: "Al-An'am",
    nameAr: "الأنعام",
    meaning: "The Cattle",
    ayahRange: "Verses 29-59",
    type: "Tarawih (Philadelphia)",
    file: "audio/006_Al-Anam_29_59_Hafs.mp3",
    duration: "12:52"
  },
  {
    id: 2,
    surahNum: 15,
    nameEn: "Al-Hijr",
    nameAr: "الحجر",
    meaning: "The Rocky Tract",
    ayahRange: "Verses 89-99",
    type: "Salat-ul Isha (Darul Hijrah)",
    file: "audio/015_Al-Hijr.mp3",
    duration: "1:53"
  },
  {
    id: 3,
    surahNum: 20,
    nameEn: "Taha",
    nameAr: "طه",
    meaning: "Ta-Ha",
    ayahRange: "Verses 1-16",
    type: "Salah in Pennsylvania",
    file: "audio/020_Taha_1_16_Hafs.mp3",
    duration: "3:25"
  },
  {
    id: 4,
    surahNum: 23,
    nameEn: "Al-Mu'minun",
    nameAr: "المؤمنون",
    meaning: "The Believers",
    ayahRange: "Verses 84-90",
    type: "Al-Hirz Qira'at Studio",
    file: "audio/023_Al-Muminun_84_90_Hafs.mp3",
    duration: "1:17"
  },
  {
    id: 5,
    surahNum: 35,
    nameEn: "Fatir (Part 1)",
    nameAr: "فاطر",
    meaning: "The Originator",
    ayahRange: "Verses 10-14",
    type: "Maghrib Rak'ah 1 (Philadelphia)",
    file: "audio/035_Fatir_Hafs.mp3",
    duration: "4:11"
  },
  {
    id: 6,
    surahNum: 35,
    nameEn: "Fatir (Part 2)",
    nameAr: "فاطر",
    meaning: "The Originator",
    ayahRange: "Verses 15-24",
    type: "Maghrib Rak'ah 2 (Philadelphia)",
    file: "audio/035_Fatir_15_24_Hafs.mp3",
    duration: "1:58"
  },
  {
    id: 7,
    surahNum: 37,
    nameEn: "As-Saffat",
    nameAr: "الصافات",
    meaning: "Those Ranged in Ranks",
    ayahRange: "Verses 75-113",
    type: "Al-Minhaal Center (Famous)",
    file: "audio/037_As-Saffat_Hafs.mp3",
    duration: "6:38"
  },
  {
    id: 8,
    surahNum: 40,
    nameEn: "Ghafir",
    nameAr: "غافر",
    meaning: "The Forgiver",
    ayahRange: "Verses 38-50",
    type: "Al-Hirz Center Salah",
    file: "audio/040_Ghafir_38_50_Hafs.mp3",
    duration: "5:19"
  },
  {
    id: 9,
    surahNum: 66,
    nameEn: "At-Tahrim",
    nameAr: "التحريم",
    meaning: "The Prohibition",
    ayahRange: "1-12 (Complete Surah)",
    type: "Qira'at Project Studio (Al-Hirz)",
    file: "audio/066_At-Tahrim_Complete.mp3",
    duration: "6:19"
  }
];

let currentIndex = 0;
let isPlaying = false;
let playbackSpeed = 1.0;
const speeds = [1.0, 1.25, 1.5, 0.75];

// 3-State Loop Controller: 'all' (Repeat Playlist) -> 'one' (Repeat Surah) -> 'off' (Stop at end)
let loopMode = 'all';
const loopModes = ['all', 'one', 'off'];

// DOM Elements
const audio = document.getElementById('audioPlayer');
const surahListEl = document.getElementById('surahList');
const searchInput = document.getElementById('searchInput');
const clearSearchBtn = document.getElementById('clearSearchBtn');
const playPauseBtn = document.getElementById('playPauseBtn');
const playIcon = document.getElementById('playIcon');
const pauseIcon = document.getElementById('pauseIcon');
const prevBtn = document.getElementById('prevBtn');
const nextBtn = document.getElementById('nextBtn');
const skipBackBtn = document.getElementById('skipBackBtn');
const skipFwdBtn = document.getElementById('skipFwdBtn');
const seekBar = document.getElementById('seekBar');
const currentTimeEl = document.getElementById('currentTime');
const durationTimeEl = document.getElementById('durationTime');
const currentSurahNum = document.getElementById('currentSurahNum');
const currentTrackTitle = document.getElementById('currentTrackTitle');
const currentTrackSub = document.getElementById('currentTrackSub');
const nowPlayingThumb = document.getElementById('nowPlayingThumb');
const playingBadge = document.getElementById('playingBadge');
const speedBtn = document.getElementById('speedBtn');
const loopBtn = document.getElementById('loopBtn');
const loopModeBadge = document.getElementById('loopModeBadge');
const playAllBtn = document.getElementById('playAllBtn');
const shuffleBtn = document.getElementById('shuffleBtn');
const trackCountBadge = document.getElementById('trackCountBadge');
const toastEl = document.getElementById('toastEl');
const toastIcon = document.getElementById('toastIcon');
const toastText = document.getElementById('toastText');

let toastTimeout = null;
function showToast(message, icon = '🔁') {
  if (toastTimeout) clearTimeout(toastTimeout);
  toastIcon.textContent = icon;
  toastText.textContent = message;
  toastEl.classList.remove('hidden', 'toast-out');
  toastEl.classList.add('toast-in');
  toastTimeout = setTimeout(() => {
    toastEl.classList.remove('toast-in');
    toastEl.classList.add('toast-out');
    setTimeout(() => toastEl.classList.add('hidden'), 250);
  }, 2200);
}

// Render Surah Cards
function renderList(items) {
  surahListEl.innerHTML = '';
  if (items.length === 0) {
    surahListEl.innerHTML = `
      <div class="text-center py-12 rounded-2xl bg-emerald-900/20 border border-emerald-800/30 text-emerald-400/70 text-sm">
        No recitations found matching your search.
      </div>
    `;
    return;
  }

  items.forEach((item) => {
    const isCurrent = playlist[currentIndex].id === item.id;
    const card = document.createElement('div');
    card.className = `group flex items-center justify-between p-3.5 sm:p-4 rounded-2xl border transition-all duration-200 cursor-pointer select-none ${
      isCurrent
        ? 'bg-gradient-to-r from-emerald-850 via-emerald-800/60 to-emerald-850 border-gold-500/80 shadow-lg shadow-emerald-950/60 ring-1 ring-gold-500/30'
        : 'bg-emerald-900/20 hover:bg-emerald-800/30 border-emerald-800/30 hover:border-emerald-700/60'
    }`;
    
    card.onclick = () => {
      const globalIdx = playlist.findIndex(p => p.id === item.id);
      if (globalIdx === currentIndex && isPlaying) {
        pauseTrack();
      } else {
        loadAndPlay(globalIdx);
      }
    };

    card.innerHTML = `
      <div class="flex items-center gap-3.5 min-w-0">
        <!-- Number or Equalizer Waves -->
        <div class="w-10 h-10 rounded-xl flex items-center justify-center font-bold text-sm shrink-0 transition-all ${
          isCurrent && isPlaying
            ? 'bg-gold-500 text-emerald-950 shadow-md shadow-gold-500/40' 
            : isCurrent
            ? 'bg-emerald-800 text-gold-300 border border-gold-500/50'
            : 'bg-emerald-950/70 border border-emerald-800/40 text-emerald-300 group-hover:text-gold-400'
        }">
          ${isCurrent && isPlaying ? `
            <div class="flex items-end gap-0.5 h-3.5">
              <span class="w-1 bg-emerald-950 rounded-full wave-bar-1"></span>
              <span class="w-1 bg-emerald-950 rounded-full wave-bar-2"></span>
              <span class="w-1 bg-emerald-950 rounded-full wave-bar-3"></span>
              <span class="w-1 bg-emerald-950 rounded-full wave-bar-4"></span>
            </div>
          ` : String(item.surahNum).padStart(2, '0')}
        </div>

        <!-- Track Info -->
        <div class="truncate min-w-0">
          <div class="flex items-center gap-2">
            <h3 class="font-semibold text-white text-sm sm:text-base truncate ${isCurrent ? 'text-gold-300' : ''}">
              Surah ${item.nameEn}
            </h3>
            <span class="text-[11px] font-medium text-emerald-400/80 shrink-0">
              ${item.ayahRange}
            </span>
          </div>
        </div>
      </div>

      <!-- Right: Arabic Calligraphy & Duration -->
      <div class="flex items-center gap-3 shrink-0 ml-3 text-right">
        <span class="font-['Amiri'] text-xl sm:text-2xl font-bold ${isCurrent ? 'text-gold-300' : 'text-emerald-100'} group-hover:text-gold-300 transition-colors">
          ${item.nameAr}
        </span>
        <span class="text-xs text-emerald-400/60 font-mono hidden sm:inline-block w-12 text-right">
          ${item.duration}
        </span>
      </div>
    `;

    surahListEl.appendChild(card);
  });
}

// Format Seconds to MM:SS
function formatTime(seconds) {
  if (isNaN(seconds) || seconds < 0) return '0:00';
  const mins = Math.floor(seconds / 60);
  const secs = Math.floor(seconds % 60);
  return `${mins}:${secs < 10 ? '0' : ''}${secs}`;
}

// Load track
function loadTrack(index, autoPlay = false) {
  currentIndex = index;
  const track = playlist[currentIndex];
  audio.src = track.file;
  audio.playbackRate = playbackSpeed;

  currentSurahNum.textContent = String(track.surahNum).padStart(2, '0');
  currentTrackTitle.textContent = `Surah ${track.nameEn}`;
  currentTrackSub.textContent = `سورة ${track.nameAr} • ${track.ayahRange}`;
  durationTimeEl.textContent = track.duration;

  updateMediaSession(track);
  renderList(getFilteredList());

  if (autoPlay) {
    playTrack();
  }
}

function playTrack() {
  audio.play().then(() => {
    isPlaying = true;
    playIcon.classList.add('hidden');
    pauseIcon.classList.remove('hidden');
    playingBadge.classList.remove('hidden');
    renderList(getFilteredList());
  }).catch(err => {
    console.log("Audio playback error:", err);
  });
}

function pauseTrack() {
  audio.pause();
  isPlaying = false;
  playIcon.classList.remove('hidden');
  pauseIcon.classList.add('hidden');
  playingBadge.classList.add('hidden');
  renderList(getFilteredList());
}

function loadAndPlay(index) {
  loadTrack(index, true);
}

// Play / Pause Toggle
playPauseBtn.onclick = () => {
  if (isPlaying) {
    pauseTrack();
  } else {
    playTrack();
  }
};

// Next / Previous Navigation
function nextTrack() {
  currentIndex = (currentIndex + 1) % playlist.length;
  loadAndPlay(currentIndex);
}

function prevTrack() {
  currentIndex = (currentIndex - 1 + playlist.length) % playlist.length;
  loadAndPlay(currentIndex);
}

prevBtn.onclick = prevTrack;
nextBtn.onclick = nextTrack;

// Skip +/- 10 Seconds
skipBackBtn.onclick = () => {
  if (!isNaN(audio.duration)) {
    audio.currentTime = Math.max(0, audio.currentTime - 10);
    showToast("-10 Seconds", "⏪");
  }
};

skipFwdBtn.onclick = () => {
  if (!isNaN(audio.duration)) {
    audio.currentTime = Math.min(audio.duration, audio.currentTime + 10);
    showToast("+10 Seconds", "⏩");
  }
};

// 3-State Loop Controller: ALL -> ONE -> OFF -> ALL
function updateLoopUI() {
  if (loopMode === 'all') {
    loopBtn.className = "relative flex items-center gap-1 px-2.5 py-1.5 rounded-xl transition-all border border-gold-500/70 bg-gold-500/15 text-gold-300 shadow-sm";
    loopModeBadge.textContent = "ALL";
    loopModeBadge.className = "text-[10px] font-extrabold font-mono text-gold-300";
  } else if (loopMode === 'one') {
    loopBtn.className = "relative flex items-center gap-1 px-2.5 py-1.5 rounded-xl transition-all border border-gold-400 bg-gold-500/30 text-gold-200 shadow-md shadow-gold-500/20";
    loopModeBadge.textContent = "1";
    loopModeBadge.className = "text-[10px] font-black font-mono text-gold-200 bg-emerald-950 px-1 rounded";
  } else {
    loopBtn.className = "relative flex items-center gap-1 px-2.5 py-1.5 rounded-xl transition-all border border-emerald-700/40 text-emerald-400/50 hover:text-emerald-300 hover:bg-emerald-900/40";
    loopModeBadge.textContent = "OFF";
    loopModeBadge.className = "text-[10px] font-extrabold font-mono text-emerald-400/60";
  }
}

loopBtn.onclick = () => {
  const nextIdx = (loopModes.indexOf(loopMode) + 1) % loopModes.length;
  loopMode = loopModes[nextIdx];
  updateLoopUI();
  
  if (loopMode === 'all') {
    showToast("Loop Mode: Repeat All (Continuous)", "🔁");
  } else if (loopMode === 'one') {
    showToast("Loop Mode: Repeat Current Surah", "🔂");
  } else {
    showToast("Loop Mode: Off (Stop at End)", "➡️");
  }
};

// Auto Advance / Loop on End
audio.onended = () => {
  if (loopMode === 'one') {
    audio.currentTime = 0;
    playTrack();
  } else if (loopMode === 'all') {
    nextTrack();
  } else {
    // 'off'
    if (currentIndex < playlist.length - 1) {
      nextTrack();
    } else {
      pauseTrack();
      audio.currentTime = 0;
    }
  }
};

// Playback Speed Toggle
speedBtn.onclick = () => {
  const nextIdx = (speeds.indexOf(playbackSpeed) + 1) % speeds.length;
  playbackSpeed = speeds[nextIdx];
  audio.playbackRate = playbackSpeed;
  speedBtn.textContent = `${playbackSpeed}x`;
  showToast(`Speed: ${playbackSpeed}x`, "⚡");
};

// Play All Button
playAllBtn.onclick = () => {
  loadAndPlay(0);
  showToast("Playing all 9 recitations in order", "▶");
};

// Shuffle Play Button
shuffleBtn.onclick = () => {
  const randIdx = Math.floor(Math.random() * playlist.length);
  loadAndPlay(randIdx);
  showToast("Shuffled playlist", "🔀");
};

// Audio Time Updates
audio.ontimeupdate = () => {
  if (!isNaN(audio.duration) && audio.duration > 0) {
    const progress = (audio.currentTime / audio.duration) * 100;
    seekBar.value = progress;
    currentTimeEl.textContent = formatTime(audio.currentTime);
    durationTimeEl.textContent = formatTime(audio.duration);
  }
};

// Seek Bar Scrubbing
seekBar.oninput = () => {
  if (!isNaN(audio.duration)) {
    const seekTime = (seekBar.value / 100) * audio.duration;
    audio.currentTime = seekTime;
  }
};

// Search Filter
function getFilteredList() {
  const query = searchInput.value.trim().toLowerCase();
  clearSearchBtn.classList.toggle('hidden', !query);
  if (!query) {
    if (trackCountBadge) trackCountBadge.textContent = `${playlist.length} Recitations`;
    return playlist;
  }
  const filtered = playlist.filter(item => 
    item.nameEn.toLowerCase().includes(query) ||
    item.nameAr.includes(query) ||
    item.ayahRange.toLowerCase().includes(query) ||
    String(item.surahNum) === query
  );
  if (trackCountBadge) trackCountBadge.textContent = `${filtered.length} found`;
  return filtered;
}

searchInput.oninput = () => {
  renderList(getFilteredList());
};

clearSearchBtn.onclick = () => {
  searchInput.value = '';
  renderList(getFilteredList());
};

// Media Session API for Lock Screen & Notification Controls
function updateMediaSession(track) {
  if ('mediaSession' in navigator) {
    navigator.mediaSession.metadata = new MediaMetadata({
      title: `Surah ${track.nameEn} (${track.nameAr})`,
      artist: 'Sheikh Okasha Kameny (الشيخ عكاشة كميني)',
      album: "Hafs 'An-Asim Recitations (حفص عن عاصم)",
      artwork: [
        { src: 'img/sheikh_okasha_thumb.jpg', sizes: '160x160', type: 'image/jpeg' },
        { src: 'img/sheikh_okasha.jpg', sizes: '512x512', type: 'image/jpeg' },
        { src: 'icon-512.png', sizes: '512x512', type: 'image/png' }
      ]
    });

    navigator.mediaSession.setActionHandler('play', () => playTrack());
    navigator.mediaSession.setActionHandler('pause', () => pauseTrack());
    navigator.mediaSession.setActionHandler('previoustrack', () => prevTrack());
    navigator.mediaSession.setActionHandler('nexttrack', () => nextTrack());
    navigator.mediaSession.setActionHandler('seekbackward', () => {
      audio.currentTime = Math.max(0, audio.currentTime - 10);
    });
    navigator.mediaSession.setActionHandler('seekforward', () => {
      audio.currentTime = Math.min(audio.duration, audio.currentTime + 10);
    });
  }
}

// Global Keyboard Shortcuts (Desktop UX)
window.addEventListener('keydown', (e) => {
  if (['input', 'textarea'].includes(document.activeElement.tagName.toLowerCase())) return;

  if (e.code === 'Space') {
    e.preventDefault();
    playPauseBtn.click();
  } else if (e.code === 'ArrowRight') {
    skipFwdBtn.click();
  } else if (e.code === 'ArrowLeft') {
    skipBackBtn.click();
  } else if (e.key === 'l' || e.key === 'L') {
    loopBtn.click();
  } else if (e.key === 's' || e.key === 'S') {
    speedBtn.click();
  }
});

// Initial Setup
updateLoopUI();
loadTrack(0, false);

// ==========================================
// PWA & Service Worker Engine
// ==========================================

// Register Service Worker
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('./sw.js')
      .then((reg) => {
        console.log('[PWA] Service Worker active with scope:', reg.scope);
      })
      .catch((err) => {
        console.warn('[PWA] Service Worker registration failed:', err);
      });
  });
}

// PWA Install Prompt Handler
let deferredPrompt = null;
const pwaInstallBtn = document.getElementById('pwaInstallBtn');

window.addEventListener('beforeinstallprompt', (e) => {
  e.preventDefault();
  deferredPrompt = e;
  if (pwaInstallBtn) {
    pwaInstallBtn.classList.remove('hidden');
    pwaInstallBtn.classList.add('inline-flex');
  }
});

if (pwaInstallBtn) {
  pwaInstallBtn.addEventListener('click', async () => {
    if (!deferredPrompt) {
      showToast("To install, use browser menu -> 'Install app'", "ℹ️");
      return;
    }
    deferredPrompt.prompt();
    const { outcome } = await deferredPrompt.userChoice;
    if (outcome === 'accepted') {
      showToast("Installing Okasha Hafs App...", "📥");
      pwaInstallBtn.classList.add('hidden');
    }
    deferredPrompt = null;
  });
}

window.addEventListener('appinstalled', () => {
  if (pwaInstallBtn) pwaInstallBtn.classList.add('hidden');
  showToast("Okasha Hafs App Installed!", "✨");
});

// Online / Offline Detection
const networkBadge = document.getElementById('networkBadge');
function updateOnlineStatus() {
  if (!networkBadge) return;
  if (navigator.onLine) {
    networkBadge.innerHTML = '<span class="w-2 h-2 rounded-full bg-emerald-400"></span><span>Online</span>';
    networkBadge.className = 'inline-flex items-center gap-1.5 text-[11px] bg-emerald-900/60 border border-emerald-700/50 text-emerald-300 px-2.5 py-1 rounded-full font-medium';
  } else {
    networkBadge.innerHTML = '<span class="w-2 h-2 rounded-full bg-amber-400 animate-pulse"></span><span>Offline Mode</span>';
    networkBadge.className = 'inline-flex items-center gap-1.5 text-[11px] bg-amber-950/80 border border-amber-600/50 text-amber-300 px-2.5 py-1 rounded-full font-medium';
    showToast("Using offline cache", "📡");
  }
}
window.addEventListener('online', updateOnlineStatus);
window.addEventListener('offline', updateOnlineStatus);
updateOnlineStatus();

// Offline Audio Cacher
const cacheAllBtn = document.getElementById('cacheAllBtn');
const cacheAllText = document.getElementById('cacheAllText');
let isCachingAll = false;

if (cacheAllBtn && cacheAllText) {
  // Check if all tracks are cached
  if ('caches' in window) {
    caches.open('okasha-hafs-v2.0').then(async (cache) => {
      const keys = await cache.keys();
      const allCached = playlist.every(t => keys.some(k => k.url.includes(t.file)));
      if (allCached) {
        cacheAllText.textContent = "✓ Saved Offline";
        cacheAllBtn.classList.add('bg-emerald-800/80', 'border-gold-500/50');
      }
    }).catch(() => {});
  }

  cacheAllBtn.addEventListener('click', async () => {
    if (isCachingAll) return;
    if (!('caches' in window)) {
      showToast("Offline caching not supported in this browser", "⚠️");
      return;
    }

    isCachingAll = true;
    cacheAllText.textContent = "Saving 0/9...";
    showToast("Downloading all 9 recitations into offline storage...", "📥");

    try {
      const cache = await caches.open('okasha-hafs-v2.0');
      for (let i = 0; i < playlist.length; i++) {
        cacheAllText.textContent = `Saving ${i + 1}/${playlist.length}...`;
        const res = await fetch(playlist[i].file);
        if (res.ok) {
          await cache.put(playlist[i].file, res);
        }
      }
      cacheAllText.textContent = "✓ Saved Offline";
      cacheAllBtn.classList.add('bg-emerald-800/80', 'border-gold-500/50');
      showToast("All recitations saved for 100% offline play!", "✨");
    } catch (err) {
      console.error('Cache error:', err);
      cacheAllText.textContent = "Save Offline";
      showToast("Download interrupted. Check connection.", "⚠️");
    } finally {
      isCachingAll = false;
    }
  });
}
