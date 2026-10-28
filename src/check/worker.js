// One of the check page's solvers: tries nonces start, start + step, …
// (base 36) until SHA-256(challenge + nonce) starts with `difficulty` zero
// bits. Batched: each digest is a promise.
const BATCH = 64;
const encoder = new TextEncoder();

const zeroBits = (bytes) => {
    let bits = 0;
    for (const byte of bytes) {
        if (byte === 0) {
            bits += 8;
            continue;
        }
        return bits + Math.clz32(byte) - 24;
    }
    return bits;
};

self.onmessage = async ({ data: { challenge, difficulty, start, step } }) => {
    for (let n = start; ; n += step * BATCH) {
        const nonces = Array.from({ length: BATCH }, (_, i) => (n + i * step).toString(36));
        const digests = await Promise.all(
            nonces.map((nonce) => crypto.subtle.digest('SHA-256', encoder.encode(challenge + nonce))),
        );
        for (let i = 0; i < BATCH; i++) {
            if (zeroBits(new Uint8Array(digests[i])) >= difficulty) {
                self.postMessage(nonces[i]);
                return;
            }
        }
    }
};
