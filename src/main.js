import { cipher, keyExpansion } from './aes.js';

document.addEventListener('DOMContentLoaded', () => {
  const passwordInput = document.getElementById('password');
  const aesVersionInput = document.getElementById('aesVersion');
  const plaintextInput = document.getElementById('plainTextInput');
  const cipherInput = document.getElementById('cipherTextInput');

  const encryptBtn = document.getElementById('encryptBtn');
  const decryptBtn = document.getElementById('decryptBtn');
  const clearPlaintextBtn = document.getElementById('clearPlaintext');
  const clearCipherBtn = document.getElementById('clearCipher');
  const copyPlaintextBtn = document.getElementById('copyPlaintext');
  const copyCipherBtn = document.getElementById('copyCipher');
  const pastePlaintextBtn = document.getElementById('pastePlaintext');
  const pasteCipherBtn = document.getElementById('pasteCipher');

  // Encryption
  encryptBtn.addEventListener('click', () => {
    if (!passwordInput.value) {
      alert('Password cannot be empty.');
      return;
    }
    if (!plaintextInput.value) {
      alert('Plain text cannot be empty.');
      return;
    }

    const nBits = parseInt(aesVersionInput.value, 10);
    console.log('Encrypting...');
    const ciphertext = encrypt(plaintextInput.value, passwordInput.value, nBits);
    console.log('Encryption completed');
    cipherInput.value = ciphertext;
  });

  // Decryption with error handling
  decryptBtn.addEventListener('click', () => {
    if (!passwordInput.value) {
      alert('Password cannot be empty.');
      return;
    }
    if (!cipherInput.value) {
      alert('Cipher text cannot be empty.');
      return;
    }

    try {
      const nBits = parseInt(aesVersionInput.value, 10);
      console.log('Decrypting...');
      const plaintext = decrypt(cipherInput.value, passwordInput.value, nBits);
      console.log('Decryption completed');
      plaintextInput.value = plaintext;
    } catch (error) {
      plaintextInput.value = 'Decryption failed';
      console.error('Decryption error:', error);
    }
  });

  // Clear text fields
  clearPlaintextBtn.addEventListener('click', () => {
    plaintextInput.value = '';
  });
  clearCipherBtn.addEventListener('click', () => {
    cipherInput.value = '';
  });

  // Copy and paste from clipboard
  copyPlaintextBtn.addEventListener('click', () => {
    copyToClipboard(plaintextInput.value);
  });
  copyCipherBtn.addEventListener('click', () => {
    copyToClipboard(cipherInput.value);
  });
  pastePlaintextBtn.addEventListener('click', async () => {
    plaintextInput.value = await pasteFromClipboard();
  });
  pasteCipherBtn.addEventListener('click', async () => {
    cipherInput.value = await pasteFromClipboard();
  });

  // Functions for copying and pasting from clipboard
  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text).then(() => alert('Copied to clipboard'));
  };
  const pasteFromClipboard = async () => {
    return await navigator.clipboard.readText();
  };

  // UTF-8 encoding and decoding
  const utf8Encode = (str) => unescape(encodeURIComponent(str));
  const utf8Decode = (str) => {
    try {
      return decodeURIComponent(escape(str));
    } catch {
      console.error('Invalid UTF-8 sequence encountered.');
      return str;
    }
  };

  // Base64 encoding and decoding
  const base64Encode = (str) => btoa(utf8Encode(str));
  const base64Decode = (str) => {
    try {
      return utf8Decode(atob(str));
    } catch (e) {
      console.error('Base64 decode error:', e);
      return str;
    }
  };

  // Encrypt text
  const encrypt = (plaintext, password, nBits) => {
    if (![128, 192, 256].includes(nBits)) return '';

    plaintext = utf8Encode(plaintext);
    password = utf8Encode(password);
    const nBytes = nBits / 8;
    const pwBytes = new Uint8Array(nBytes).map((_, i) => isNaN(password.charCodeAt(i)) ? 0 : password.charCodeAt(i));
    const keySchedule = keyExpansion(pwBytes);

    const counterBlock = new Uint8Array(16);
    const nonce = new Date().getTime();
    counterBlock.set([nonce % 1000 >>> 8, nonce % 1000 & 0xff, Math.floor(Math.random() * 0xffff) >>> 8, Math.floor(Math.random() * 0xffff) & 0xff,
              (nonce / 1000 >>> 24) & 0xff, (nonce / 1000 >>> 16) & 0xff, (nonce / 1000 >>> 8) & 0xff, nonce / 1000 & 0xff]);
  
    const ctrTxt = String.fromCharCode(...counterBlock.slice(0, 8));
    const blockSize = 16;
    const blockCount = Math.ceil(plaintext.length / blockSize);
    const ciphertxt = Array(blockCount).fill('').map((_, b) => {
      counterBlock.set([(b >>> 24) & 0xff, (b >>> 16) & 0xff, (b >>> 8) & 0xff, b & 0xff], 12);
      const cipherCntr = cipher(counterBlock, keySchedule);
      return String.fromCharCode(...Array.from({ length: b < blockCount - 1 ? blockSize : (plaintext.length - 1) % blockSize + 1 },
                           (_, i) => cipherCntr[i] ^ plaintext.charCodeAt(b * blockSize + i)));
    });
    return base64Encode(ctrTxt + ciphertxt.join(''));
  };

  // Decrypt text
  const decrypt = (ciphertext, password, nBits) => {
    if (![128, 192, 256].includes(nBits)) return '';

    ciphertext = base64Decode(ciphertext);
    password = utf8Encode(password);
    const nBytes = nBits / 8;
    const pwBytes = new Uint8Array(nBytes).map((_, i) => isNaN(password.charCodeAt(i)) ? 0 : password.charCodeAt(i));
    const keySchedule = keyExpansion(pwBytes);
    let key = keySchedule.slice(0, nBytes);

    const counterBlock = new Uint8Array(16);
    ciphertext.slice(0, 8).split('').forEach((c, i) => counterBlock[i] = c.charCodeAt(0));

    const ciphertextBytes = new Uint8Array(ciphertext.slice(8).split('').map(c => c.charCodeAt(0)));
    const blockSize = 16;
    const blockCount = Math.ceil(ciphertextBytes.length / blockSize);
    const plaintxt = Array(blockCount).fill('').map((_, b) => {
      counterBlock.set([(b >>> 24) & 0xff, (b >>> 16) & 0xff, (b >>> 8) & 0xff, b & 0xff], 12);
      const cipherCntr = cipher(counterBlock, keySchedule);
      return String.fromCharCode(...Array.from({ length: b < blockCount - 1 ? blockSize : (ciphertextBytes.length - 1) % blockSize + 1 },
                           (_, i) => cipherCntr[i] ^ ciphertextBytes[b * blockSize + i]));
    });

    return utf8Decode(plaintxt.join(''));
  };

});
