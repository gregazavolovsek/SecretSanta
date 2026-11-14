(() => {
  'use strict';

  // Must match SALT in organizer/draw.mjs.
  const SALT = 'skrivni-miklavz-2026';
  // 5. 12. 2026, 00:00 (Ljubljana, CET).
  const EVENT = new Date('2026-12-05T00:00:00+01:00');

  const $ = (id) => document.getElementById(id);
  const enc = (s) => new TextEncoder().encode(s);

  function show(id) {
    for (const s of document.querySelectorAll('.state')) s.hidden = s.id !== id;
  }

  function showError(msg) {
    $('error-text').textContent = msg;
    show('error');
  }

  function b64urlToBytes(s) {
    const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4);
    return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  }
  function b64ToBytes(s) {
    return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  }
  function toHex(buf) {
    return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, '0')).join('');
  }

  async function decryptFor(token) {
    const subtle = window.crypto && window.crypto.subtle;
    if (!subtle) throw new Error('nocrypto');

    const ikm = await subtle.importKey('raw', b64urlToBytes(token), 'HKDF', false, ['deriveBits', 'deriveKey']);
    const salt = enc(SALT);
    const id = toHex(await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info: enc('id') }, ikm, 256));

    const blob = window.MIKLAVZ_DATA && window.MIKLAVZ_DATA.entries && window.MIKLAVZ_DATA.entries[id];
    if (!blob) throw new Error('notfound');

    const key = await subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt, info: enc('aes-gcm-key') },
      ikm, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
    );
    const bytes = b64ToBytes(blob);
    const plain = await subtle.decrypt(
      { name: 'AES-GCM', iv: bytes.slice(0, 12), additionalData: enc(id) },
      key, bytes.slice(12)
    );
    return JSON.parse(new TextDecoder().decode(plain));
  }

  function startCountdown() {
    const pad = (n) => String(n).padStart(2, '0');
    const tick = () => {
      const ms = EVENT - Date.now();
      if (ms <= 0) {
        $('countdown').hidden = true;
        $('arrived').hidden = false;
        return false;
      }
      const s = Math.floor(ms / 1000);
      $('cd-d').textContent = Math.floor(s / 86400);
      $('cd-h').textContent = pad(Math.floor((s % 86400) / 3600));
      $('cd-m').textContent = pad(Math.floor((s % 3600) / 60));
      $('cd-s').textContent = pad(s % 60);
      return true;
    };
    if (tick()) {
      const timer = setInterval(() => { if (!tick()) clearInterval(timer); }, 1000);
    }
  }

  async function main() {
    const token =
      new URLSearchParams(location.search).get('t') ||
      new URLSearchParams(location.hash.slice(1)).get('t');

    if (!token) {
      showError('Ta povezava je nepopolna. Odpri točno tisto povezavo, ki si jo prejel(a) od organizatorja.');
      return;
    }
    if (!/^[A-Za-z0-9_-]{43}$/.test(token.trim())) {
      showError('Te povezave ne prepoznamo. Preveri, da si kopiral(a) celotno povezavo, brez manjkajočih znakov.');
      return;
    }

    let data;
    try {
      data = await decryptFor(token.trim());
    } catch (e) {
      if (e && e.message === 'nocrypto') {
        showError('Tvoj brskalnik ne podpira potrebnega šifriranja. Odpri povezavo v posodobljenem brskalniku (prek https).');
      } else {
        showError('Te povezave ne prepoznamo. Preveri, da si kopiral(a) celotno povezavo, ali se obrni na organizatorja.');
      }
      return;
    }

    $('name').textContent = data.g;
    $('recipient').textContent = data.r;
    show('greet');
    $('info').hidden = false;
    startCountdown();

    $('reveal').addEventListener('click', () => show('result'), { once: true });
  }

  main();
})();
