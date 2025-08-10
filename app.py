from flask import Flask, request, render_template
import hashlib, struct

app = Flask(__name__)

def rol32(x, r):
    return ((x << r) & 0xffffffff) | (x >> (32 - r))

def custom_hash(plaintext: str, out_hex_len: int = 32) -> str:
    data = plaintext.encode('utf-8')
    seeds = [0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344,
             0xA4093822, 0x299F31D0, 0x082EFA98, 0xEC4E6C89]
    state = seeds.copy()
    for i, byte in enumerate(data):
        idx = i & 7
        mix = (byte + ((i << 3) & 0xffffffff)) & 0xffffffff
        v = state[idx] ^ mix
        v = (v * (0x9D7F3D99 | (byte + 1))) & 0xffffffff
        neigh = (state[(idx + 1) & 7] + state[(idx - 1) & 7]) & 0xffffffff
        v = (v ^ (neigh >> ((byte % 7) + 1))) & 0xffffffff
        r = ((byte % 31) + 1)
        state[idx] = rol32(v, r)
        state[(idx + 1) & 7] = (state[(idx + 1) & 7] ^ rol32(v, (r*3) % 32)) & 0xffffffff
    for j in range(16):
        for k in range(8):
            x = (state[k] + ((j + 1) * (k + 0x9))) & 0xffffffff
            x = (x ^ state[(k + 3) & 7]) & 0xffffffff
            x = (x * (0x9E3779B1 ^ ((j<<1) + k))) & 0xffffffff
            state[k] = rol32(x, ((j + k) % 31) + 1)
    digest_bytes = b''.join(struct.pack('<I', w) for w in state)
    out_bytes_len = out_hex_len // 2
    out = bytearray(out_bytes_len)
    for i, bval in enumerate(digest_bytes):
        out[i % out_bytes_len] ^= bval
    return out.hex()

@app.route("/", methods=["GET", "POST"])
def index():
    hash_val = None
    sha_val = None
    if request.method == "POST":
        text = request.form.get("text", "")
        hash_val = custom_hash(text)
        sha_val = hashlib.sha256(text.encode()).hexdigest()
    return render_template("index.html", custom_hash=hash_val, sha256=sha_val)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
