/* ==========================
     Constants / Storage Keys
     ========================== */
const AUTH_KEY = "fm_auth_v1";
const ENC_SALT_KEY = "fm_enc_salt";
const TX_ENC_KEY = "transactions_enc";
const REM_ENC_KEY = "reminders_enc";
const PBKDF2_ITER = 100000;

/* ==========================
     WebCrypto helpers
     ========================== */
async function genSalt(len = 16) {
  const arr = crypto.getRandomValues(new Uint8Array(len));
  return Array.from(arr)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
function hexToBuf(hex) {
  const bytes = new Uint8Array(hex.match(/.{1,2}/g).map((b) => parseInt(b, 16)));
  return bytes.buffer;
}
function bufToBase64(buf) {
  const bytes = new Uint8Array(buf);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}
function base64ToBuf(b64) {
  const binary = atob(b64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}
async function sha256Hex(text) {
  const enc = new TextEncoder();
  const data = enc.encode(text);
  const hash = await crypto.subtle.digest("SHA-256", data);
  const bytes = new Uint8Array(hash);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
async function hashWithSalt(password, salt) {
  return await sha256Hex(salt + password);
}
async function deriveKey(password, saltHex) {
  const enc = new TextEncoder();
  const passKey = await crypto.subtle.importKey("raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveKey"]);
  const saltBuf = hexToBuf(saltHex);
  return await crypto.subtle.deriveKey({ name: "PBKDF2", salt: saltBuf, iterations: PBKDF2_ITER, hash: "SHA-256" }, passKey, { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
}
async function encryptObject(obj, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const data = enc.encode(JSON.stringify(obj));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data);
  return { ciphertext: bufToBase64(ct), iv: bufToBase64(iv.buffer) };
}
async function decryptObject(ciphertextB64, ivB64, key) {
  const ctBuf = base64ToBuf(ciphertextB64);
  const ivBuf = base64ToBuf(ivB64);
  const plainBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv: ivBuf }, key, ctBuf);
  const dec = new TextDecoder();
  return JSON.parse(dec.decode(plainBuf));
}

/* ==========================
     Utility: Day name & format
     ========================== */
function getDayName(dateStr) {
  const dateObj = new Date(dateStr);
  const hari = ["Minggu", "Senin", "Selasa", "Rabu", "Kamis", "Jumat", "Sabtu"];
  return hari[dateObj.getDay()];
}
function formatFullDate(dateStr) {
  const d = new Date(dateStr);
  return d.toLocaleDateString("id-ID", { day: "2-digit", month: "long", year: "numeric" });
}

/* ==========================
     Auth & Encryption Salt Setup
     ========================== */
async function setAuth(password) {
  const salt = await genSalt(12);
  const hash = await hashWithSalt(password, salt);
  const obj = { salt, hash, createdAt: new Date().toISOString() };
  localStorage.setItem(AUTH_KEY, JSON.stringify(obj));
  const encSalt = await genSalt(16);
  localStorage.setItem(ENC_SALT_KEY, encSalt);
}
async function verifyAuth(password) {
  const raw = localStorage.getItem(AUTH_KEY);
  if (!raw) return false;
  try {
    const obj = JSON.parse(raw);
    const check = await hashWithSalt(password, obj.salt);
    return check === obj.hash;
  } catch (e) {
    return false;
  }
}
async function getEncSalt() {
  let s = localStorage.getItem(ENC_SALT_KEY);
  if (!s) {
    s = await genSalt(16);
    localStorage.setItem(ENC_SALT_KEY, s);
  }
  return s;
}

/* ==========================
     Encrypted storage helpers
     ========================== */
async function saveEncryptedObject(obj, password, storageKey) {
  const encSalt = await getEncSalt();
  const key = await deriveKey(password, encSalt);
  const enc = await encryptObject(obj, key);
  localStorage.setItem(storageKey, JSON.stringify({ ciphertext: enc.ciphertext, iv: enc.iv, encSalt }));
}
async function loadEncrypted(storageKey, password) {
  const raw = localStorage.getItem(storageKey);
  if (!raw) return null;
  const obj = JSON.parse(raw);
  const { ciphertext, iv, encSalt } = obj;
  const key = await deriveKey(password, encSalt);
  return await decryptObject(ciphertext, iv, key);
}

/* ==========================
     Elements & State
     ========================== */
const authScreen = document.getElementById("auth-screen");
const authTitle = document.getElementById("auth-title");
const authDesc = document.getElementById("auth-desc");
const setupForm = document.getElementById("setup-form");
const setupPass = document.getElementById("setup-password");
const setupPassC = document.getElementById("setup-password-confirm");
const loginForm = document.getElementById("login-form");
const loginPass = document.getElementById("login-password");
const forgotBtn = document.getElementById("forgot-btn");

const appContainer = document.getElementById("app-container");
const formTx = document.getElementById("transaction-form");
const descEl = document.getElementById("desc");
const amountEl = document.getElementById("amount");
const typeEl = document.getElementById("type");
const dateEl = document.getElementById("date");
const balanceEl = document.getElementById("balance");
const listEl = document.getElementById("transaction-list");
const filterMonth = document.getElementById("filter-month");
const exportBtn = document.getElementById("export-btn");
const reportEl = document.getElementById("monthly-report");
const ctx = document.getElementById("financeChart").getContext("2d");

const reminderForm = document.getElementById("reminder-form");
const reminderList = document.getElementById("reminder-list");
const reminderAlert = document.getElementById("reminder-alert");

const backupBtnEl = document.getElementById("backup-btn");
const restoreBtn = document.getElementById("restore-btn");
const restoreFile = document.getElementById("restore-file");

const themeToggle = document.getElementById("theme-toggle");
const changePinBtn = document.getElementById("change-pin");
const logoutBtn = document.getElementById("logout");

let transactions = [];
let reminders = [];
let currentPassword = null; // in-memory for session
let chart;
let darkMode = localStorage.getItem("darkMode") === "true";
if (darkMode) document.body.classList.add("dark");
themeToggle.textContent = darkMode ? "☀️" : "🌙";
themeToggle.addEventListener("click", () => {
  document.body.classList.toggle("dark");
  darkMode = document.body.classList.contains("dark");
  localStorage.setItem("darkMode", darkMode);
  themeToggle.textContent = darkMode ? "☀️" : "🌙";
});

/* ==========================
     Show auth or setup
     ========================== */
function hasAuth() {
  return !!localStorage.getItem(AUTH_KEY);
}
async function showAuth() {
  const exists = hasAuth();
  if (!exists) {
    authTitle.textContent = "Buat PIN / Password";
    authDesc.textContent = "Belum ada PIN. Silakan buat PIN atau password untuk mengamankan data Anda.";
    setupForm.style.display = "block";
    loginForm.style.display = "none";
  } else {
    authTitle.textContent = "Login";
    authDesc.textContent = "Masukkan PIN / Password untuk membuka aplikasi.";
    setupForm.style.display = "none";
    loginForm.style.display = "block";
  }
  authScreen.style.display = "flex";
  appContainer.style.display = "none";
}

/* ==========================
     Setup / Login
     ========================== */
setupForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const p1 = setupPass.value.trim();
  const p2 = setupPassC.value.trim();
  if (!p1 || p1 !== p2) return alert("PIN/password kosong atau tidak cocok.");
  await setAuth(p1);
  alert("PIN berhasil dibuat. Silakan login.");
  setupPass.value = setupPassC.value = "";
  showAuth();
});

loginForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const p = loginPass.value.trim();
  if (!p) return;
  const ok = await verifyAuth(p);
  if (!ok) return alert("PIN salah. Jika lupa, gunakan Reset Data untuk menghapus semuanya dan buat PIN baru.");
  currentPassword = p;
  await loadEncryptedDataToMemory();
  loginPass.value = "";
  authScreen.style.display = "none";
  appContainer.style.display = "block";
  updateUI();
  updateReminders();
  startInactivityMonitor(); // start auto-lock after login
});

forgotBtn.addEventListener("click", () => {
  if (confirm("Reset akan menghapus semua data (transaksi, reminder, dan PIN). Lanjutkan?")) {
    localStorage.removeItem(AUTH_KEY);
    localStorage.removeItem(ENC_SALT_KEY);
    localStorage.removeItem(TX_ENC_KEY);
    localStorage.removeItem(REM_ENC_KEY);
    localStorage.removeItem("darkMode");
    alert("Data dan PIN dihapus. Aplikasi akan reload agar bisa membuat PIN baru.");
    location.reload();
  }
});

/* ==========================
     Load encrypted data into memory
     ========================== */
async function loadEncryptedDataToMemory() {
  // Migrate old plain data if exists (for backward compatibility)
  const plainTx = localStorage.getItem("transactions");
  const plainRem = localStorage.getItem("reminders");

  if (plainTx && !localStorage.getItem(TX_ENC_KEY)) {
    try {
      const parsed = JSON.parse(plainTx);
      // ensure day exists for old items
      parsed.forEach((t) => {
        if (!t.day && t.date) t.day = getDayName(t.date);
      });
      const encSalt = await getEncSalt();
      const key = await deriveKey(currentPassword, encSalt);
      const enc = await encryptObject(parsed, key);
      localStorage.setItem(TX_ENC_KEY, JSON.stringify({ ciphertext: enc.ciphertext, iv: enc.iv, encSalt }));
      localStorage.removeItem("transactions");
    } catch (e) {
      console.error("Migrate tx failed", e);
    }
  }

  if (plainRem && !localStorage.getItem(REM_ENC_KEY)) {
    try {
      const parsed = JSON.parse(plainRem);
      const encSalt = await getEncSalt();
      const key = await deriveKey(currentPassword, encSalt);
      const enc = await encryptObject(parsed, key);
      localStorage.setItem(REM_ENC_KEY, JSON.stringify({ ciphertext: enc.ciphertext, iv: enc.iv, encSalt }));
      localStorage.removeItem("reminders");
    } catch (e) {
      console.error("Migrate rem failed", e);
    }
  }

  try {
    const txs = await loadEncrypted(TX_ENC_KEY, currentPassword);
    transactions = txs || [];
    // ensure day exists for each transaction
    transactions.forEach((t) => {
      if (!t.day && t.date) t.day = getDayName(t.date);
    });
  } catch (e) {
    alert("Gagal mendekripsi data transaksi. PIN mungkin salah atau data korup.");
    transactions = [];
  }

  try {
    const rms = await loadEncrypted(REM_ENC_KEY, currentPassword);
    reminders = rms || [];
  } catch (e) {
    alert("Gagal mendekripsi data reminder. PIN mungkin salah atau data korup.");
    reminders = [];
  }
}

/* ==========================
     Persist (encrypt & store) after any change
     ========================== */
async function persistData() {
  if (!currentPassword) return;
  const encSalt = await getEncSalt();
  const key = await deriveKey(currentPassword, encSalt);
  const encTx = await encryptObject(transactions, key);
  localStorage.setItem(TX_ENC_KEY, JSON.stringify({ ciphertext: encTx.ciphertext, iv: encTx.iv, encSalt }));
  const encRem = await encryptObject(reminders, key);
  localStorage.setItem(REM_ENC_KEY, JSON.stringify({ ciphertext: encRem.ciphertext, iv: encRem.iv, encSalt }));
}

/* ==========================
     UI: transactions / chart / report
     ========================== */
function updateUI(filtered = transactions) {
  listEl.innerHTML = "";
  let income = 0,
    expense = 0;
  filtered.forEach((t, i) => {
    const div = document.createElement("div");
    div.className = "transaction";
    // show day + full date + description
    const dateText = `${t.day || getDayName(t.date)}, ${formatFullDate(t.date)}`;
    div.innerHTML = `<div>
          <span class="tx-desc">${dateText} - ${escapeHtml(t.desc)}</span>
          <span class="tx-sub">${t.type === "income" ? "Pemasukan" : "Pengeluaran"}</span>
        </div>
        <div style="text-align:right">
          <span class="${t.type === "income" ? "income" : "expense"}" style="font-weight:700;">
            ${t.type === "income" ? "+" : "-"}Rp${t.amount.toLocaleString("id-ID")}
          </span>
          <br/>
          <button style="border:0;background:transparent;cursor:pointer;margin-top:6px;" onclick="deleteTransaction(${i})">🗑️</button>
        </div>`;
    listEl.appendChild(div);
    if (t.type === "income") income += t.amount;
    else expense += t.amount;
  });
  const bal = income - expense;
  balanceEl.textContent = `Rp${bal.toLocaleString("id-ID")}`;
  updateChart(income, expense);
  updateReport(filtered);
  persistData().catch((e) => console.error("Persist error", e));
}

// basic HTML-escape for descriptions (avoid simple injection)
function escapeHtml(s) {
  if (!s) return "";
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

window.deleteTransaction = function (index) {
  transactions.splice(index, 1);
  updateUI(filterData());
};

function updateChart(income, expense) {
  if (chart) chart.destroy();
  chart = new Chart(ctx, {
    type: "doughnut",
    data: { labels: ["Pemasukan", "Pengeluaran"], datasets: [{ data: [income, expense], backgroundColor: ["#16a34a", "#dc2626"] }] },
    options: { responsive: true, plugins: { legend: { position: "bottom" } } },
  });
}

function updateReport(data) {
  if (data.length === 0) {
    reportEl.innerHTML = "<p>Tidak ada data untuk bulan ini.</p>";
    return;
  }
  const byMonth = {};
  data.forEach((t) => {
    const m = t.date.slice(0, 7);
    if (!byMonth[m]) byMonth[m] = { income: 0, expense: 0 };
    if (t.type === "income") byMonth[m].income += t.amount;
    else byMonth[m].expense += t.amount;
  });
  reportEl.innerHTML = "";
  Object.keys(byMonth)
    .sort()
    .forEach((m) => {
      const { income, expense } = byMonth[m];
      const bal = income - expense;
      const monthText = new Date(m + "-01").toLocaleDateString("id-ID", { month: "long", year: "numeric" });
      reportEl.innerHTML += `
        <span><strong>${monthText}</strong></span>
        <span>Pemasukan: <strong class="income">Rp${income.toLocaleString("id-ID")}</strong></span>
        <span>Pengeluaran: <strong class="expense">Rp${expense.toLocaleString("id-ID")}</strong></span>
        <span>Selisih: <strong>${bal >= 0 ? "Rp" + bal.toLocaleString("id-ID") : "<span style='color:red'>-Rp" + Math.abs(bal).toLocaleString("id-ID") + "</span>"}</strong></span>
        <hr>`;
    });
}

function filterData() {
  const sel = filterMonth.value;
  if (!sel) return transactions;
  return transactions.filter((t) => t.date.startsWith(sel));
}

// Use date input (not month) for per-transaction date — changed earlier
formTx.addEventListener("submit", (e) => {
  e.preventDefault();
  const d = dateEl.value; // YYYY-MM-DD
  if (!d) return alert("Pilih tanggal transaksi.");
  const newT = {
    desc: descEl.value.trim(),
    amount: +amountEl.value,
    type: typeEl.value,
    date: d,
    day: getDayName(d),
  };
  transactions.push(newT);
  updateUI(filterData());
  formTx.reset();
});

filterMonth.addEventListener("change", () => updateUI(filterData()));

/* ==========================
     Reminders
     ========================== */
function updateReminders() {
  reminderList.innerHTML = "";
  const today = new Date().toISOString().split("T")[0];
  let upcoming = [];
  reminders.forEach((r, i) => {
    const div = document.createElement("div");
    div.className = "reminder-item";
    div.innerHTML = `<span>${escapeHtml(r.name)} - ${r.date}</span>
        <button style="border:0;background:transparent;cursor:pointer;" onclick="deleteReminder(${i})">🗑️</button>`;
    reminderList.appendChild(div);
    if (r.date <= today) upcoming.push(r.name);
  });
  if (upcoming.length > 0) {
    reminderAlert.textContent = `⚠️ Tagihan jatuh tempo: ${upcoming.join(", ")}`;
    reminderAlert.style.display = "block";
  } else reminderAlert.style.display = "none";
  persistData().catch((e) => console.error("Persist error", e));
}

window.deleteReminder = function (i) {
  reminders.splice(i, 1);
  updateReminders();
};

reminderForm.addEventListener("submit", (e) => {
  e.preventDefault();
  const n = document.getElementById("reminder-name").value.trim();
  const d = document.getElementById("reminder-date").value;
  reminders.push({ name: n, date: d });
  updateReminders();
  reminderForm.reset();
});

/* ==========================
     Export / Backup / Restore
     ========================== */
exportBtn.addEventListener("click", () => {
  // Export decrypted transactions (including 'day' and 'date')
  const dataToExport = transactions.map((t) => ({
    date: t.date,
    day: t.day || getDayName(t.date),
    desc: t.desc,
    type: t.type,
    amount: t.amount,
  }));
  const wb = XLSX.utils.book_new();
  const ws = XLSX.utils.json_to_sheet(dataToExport);
  XLSX.utils.book_append_sheet(wb, ws, "Transaksi");
  XLSX.writeFile(wb, "data_keuangan.xlsx");
});

backupBtnEl.addEventListener("click", async () => {
  if (!currentPassword) return alert("Login terlebih dahulu.");
  const txRaw = localStorage.getItem(TX_ENC_KEY);
  const remRaw = localStorage.getItem(REM_ENC_KEY);
  const data = { transactions_enc: txRaw, reminders_enc: remRaw };
  const blob = new Blob([JSON.stringify(data)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "backup_keuangan_encrypted.json";
  a.click();
});

restoreBtn.addEventListener("click", async () => {
  const file = restoreFile.files[0];
  if (!file) return alert("Pilih file backup terlebih dahulu!");
  const reader = new FileReader();
  reader.onload = async (e) => {
    try {
      const parsed = JSON.parse(e.target.result);
      if (!parsed.transactions_enc || !parsed.reminders_enc) return alert("File backup tidak valid.");
      if (!currentPassword) return alert("Login terlebih dahulu dengan PIN yang sesuai untuk merestore.");
      localStorage.setItem(TX_ENC_KEY, parsed.transactions_enc);
      localStorage.setItem(REM_ENC_KEY, parsed.reminders_enc);
      try {
        await loadEncryptedDataToMemory();
        updateUI();
        updateReminders();
        alert("Restore berhasil (data terenkripsi sudah disimpan).");
      } catch (err) {
        alert("Restore gagal: tidak dapat mendekripsi data dengan PIN saat ini. Pastikan menggunakan PIN yang benar.");
      }
    } catch (err) {
      alert("File backup tidak valid.");
    }
  };
  reader.readAsText(file);
});

/* ==========================
     Change PIN
     ========================== */
changePinBtn.addEventListener("click", async () => {
  if (!currentPassword) return alert("Login dulu untuk mengubah PIN.");
  const cur = prompt("Masukkan PIN saat ini:");
  if (!cur) return;
  const ok = await verifyAuth(cur);
  if (!ok) return alert("PIN lama salah.");
  const np = prompt("Masukkan PIN baru:");
  if (!np) return;
  const np2 = prompt("Ulangi PIN baru:");
  if (np !== np2) return alert("PIN baru tidak cocok.");
  try {
    const txPlain = transactions;
    const remPlain = reminders;
    await setAuth(np);
    const newEncSalt = await getEncSalt();
    const newKey = await deriveKey(np, newEncSalt);
    const encTx = await encryptObject(txPlain, newKey);
    const encRem = await encryptObject(remPlain, newKey);
    localStorage.setItem(TX_ENC_KEY, JSON.stringify({ ciphertext: encTx.ciphertext, iv: encTx.iv, encSalt: newEncSalt }));
    localStorage.setItem(REM_ENC_KEY, JSON.stringify({ ciphertext: encRem.ciphertext, iv: encRem.iv, encSalt: newEncSalt }));
    currentPassword = np;
    alert("PIN berhasil diubah dan data terenkripsi ulang.");
  } catch (e) {
    alert("Gagal mengubah PIN: " + (e.message || e));
  }
});

/* ==========================
     Logout
     ========================== */
logoutBtn.addEventListener("click", () => {
  currentPassword = null;
  transactions = [];
  reminders = [];
  stopInactivityMonitor();
  showAuth();
});

/* ==========================
     AUTO-SAVE + AUTO-LOCK
     ========================== */
let inactivityTime = 5 * 60 * 1000; // default 5 minutes; change if needed
let inactivityTimer = null;
let activityEvents = ["click", "mousemove", "keydown", "touchstart"];

async function autoSaveBeforeLock() {
  try {
    await persistData();
    console.log("Auto-save: data disimpan sebelum terkunci.");
  } catch (e) {
    console.error("Auto-save gagal:", e);
  }
}

function lockSystemAuto() {
  autoSaveBeforeLock().finally(() => {
    currentPassword = null;
    transactions = [];
    reminders = [];
    stopInactivityMonitor();
    showAuth();
    alert("🔒 Sistem terkunci otomatis karena tidak ada aktivitas.");
  });
}

function resetInactivityTimer() {
  if (inactivityTimer) clearTimeout(inactivityTimer);
  inactivityTimer = setTimeout(lockSystemAuto, inactivityTime);
}

function startInactivityMonitor() {
  activityEvents.forEach((evt) => document.addEventListener(evt, resetInactivityTimer));
  resetInactivityTimer();
  // ======== AUTO-LOCK PREFERENCE SYSTEM ========

  // Elemen dropdown
  const autoLockSelect = document.getElementById("auto-lock-time");

  // Ambil preferensi dari localStorage (default 5 menit)
  let autoLockMinutes = parseInt(localStorage.getItem("autoLockMinutes")) || 5;
  autoLockSelect.value = autoLockMinutes.toString();

  // Update waktu auto-lock global
  let inactivityTime = autoLockMinutes * 60 * 1000;

  // Saat user mengganti durasi auto-lock
  autoLockSelect.addEventListener("change", () => {
    autoLockMinutes = parseInt(autoLockSelect.value);
    localStorage.setItem("autoLockMinutes", autoLockMinutes);
    inactivityTime = autoLockMinutes * 60 * 1000;
    resetInactivityTimer();
    alert(`✅ Auto-lock diatur menjadi ${autoLockMinutes} menit.`);
  });
}

function stopInactivityMonitor() {
  if (inactivityTimer) {
    clearTimeout(inactivityTimer);
    inactivityTimer = null;
  }
  activityEvents.forEach((evt) => document.removeEventListener(evt, resetInactivityTimer));
}

/* ==========================
     Initial show
     ========================== */
(async function () {
  await showAuth();
})();
