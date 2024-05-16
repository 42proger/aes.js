import { sBox, rCon } from "./data/constants.js";

const cipher = (input, w) => {
  const Nb = 4;                   // Block size: fixed at 4 for AES
  const Nr = w.length / Nb - 1;   // Number of rounds: 10/12/14 for 128/192/256-bit keys

  // Convert input into a 2D array "state"
  let state = Array.from({ length: 4 }, () => new Array(Nb).fill(0));
  for (let i = 0; i < 4 * Nb; i++) {
    state[i % 4][Math.floor(i / 4)] = input[i];
  }

  // Perform round operations
  for (let round = 0; round <= Nr; round++) {
    console.log(`Round ${round}.`, 'Before:', state);
    state = subBytes(state);
    console.log('After subBytes:', state);
    state = shiftRows(state, Nb);
    console.log('After shiftRows:', state);
    if (round < Nr) {
      state = mixColumns(state, Nb);
      console.log('After mixColumns:', state);
    }
    state = addRoundKey(state, w, round, Nb);
    console.log('After addRoundKey:', state);
  }

  return state.flat();
};

const keyExpansion = (key) => {
  const Nb = 4;                   // Block size: fixed at 4 for AES
  const Nk = key.length / 4;      // Key length: 4/6/8 for 128/192/256-bit keys
  const Nr = Nk + 6;              // Number of rounds: 10/12/14 for 128/192/256-bit keys

  const w = new Array(Nb * (Nr + 1));

  // Initialise first Nk words
  for (let i = 0; i < Nk; i++) {
    w[i] = key.slice(i * 4, (i + 1) * 4);
  }

  // Expand the key
  for (let i = Nk; i < Nb * (Nr + 1); i++) {
    let temp = w[i - 1].slice();
    if (i % Nk === 0) {
      temp = [temp[1], temp[2], temp[3], temp[0]].map((byte) => sBox[byte]);
      for (let t = 0; t < 4; t++) temp[t] ^= rCon[i / Nk][t];
    } else if (Nk > 6 && i % Nk === 4) {
      temp = temp.map((byte) => sBox[byte]);
    }
    w[i] = new Array(4);

    // Xor w[i] with w[i-1] and w[i-Nk]
    for (let t = 0; t < 4; t++) w[i][t] = w[i - Nk][t] ^ temp[t];
  }

  return w;
};

// Apply SBox to "state"
const subBytes = (state) => state.map((row) => row.map((byte) => sBox[byte]));

// Shift rows (r) of the "state" left by "r" bytes
const shiftRows = (state, Nb) =>
  state.map((row, r) => row.map((_, c) => state[r][(c + r) % Nb]));

// Mix columns of the "state"
const mixColumns = (state, Nb) => {
  const newState = state.map(row => [...row]);
  for (let c = 0; c < 4; c++) {
    // "a" is a copy of the current column from "state"
    const a = state.map(row => row[c]);
    // "b" is a•{02} in GF(2^8)
    const b = a.map(byte => byte & 0x80 ? (byte << 1) ^ 0x011b : byte << 1);

    newState[0][c] = b[0] ^ a[1] ^ b[1] ^ a[2] ^ a[3];    // {02}•a0 + {03}•a1 + a2 + a3
    newState[1][c] = a[0] ^ b[1] ^ a[2] ^ b[2] ^ a[3];    // a0 • {02}•a1 + {03}•a2 + a3
    newState[2][c] = a[0] ^ a[1] ^ b[2] ^ a[3] ^ b[3];    // a0 + a1 + {02}•a2 + {03}•a3
    newState[3][c] = a[0] ^ b[0] ^ a[1] ^ a[2] ^ b[3];    // {03}•a0 + a1 + a2 + {02}•a3
  }
  return newState;
};

// Xor Round Key into "state"
const addRoundKey = (state, w, rnd, Nb) => {
  const newState = [];
  for (let r = 0; r < 4; r++) {
    const row = [];
    for (let c = 0; c < Nb; c++) {
      row.push(state[r][c] ^ w[rnd * 4 + c][r]);
    }
    newState.push(row);
  }
  return newState;
};

export { cipher, keyExpansion };
