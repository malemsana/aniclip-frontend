const CACHE_NAME = 'aniclip-stream-cache-v1';
const keysStore = new Map();

self.addEventListener("install", (event) => {
    // Activate worker immediately
    self.skipWaiting();
});

self.addEventListener("activate", (event) => {
    // Become available to all pages
    event.waitUntil(self.clients.claim());
});

self.addEventListener("message", async (event) => {
    if (event.data.type === "REGISTER_KEY") {
        const { clipId, keyBytes, ivBytes, realUrl } = event.data;
        try {
            const key = await crypto.subtle.importKey("raw", keyBytes, { name: "AES-CTR" }, false, ["decrypt"]);
            keysStore.set(clipId, { key, iv: new Uint8Array(ivBytes), realUrl });
        } catch (e) {
            console.error("SW Key Import Error:", e);
        }
    }
});

self.addEventListener("fetch", (event) => {
    const url = new URL(event.request.url);
    
    // Intercept our fake virtual streaming endpoints
    if (url.pathname.startsWith("/stream-decrypt/")) {
        event.respondWith(handleStream(event.request, url));
    }
});

// Helper to increment the 16-byte AES-CTR IV array
function incrementIv(baseIv, blockOffset) {
    const iv = new Uint8Array(baseIv);
    // Python's cryptography library uses a big-endian counter over the entire 16 bytes.
    let carry = BigInt(blockOffset);
    for (let i = 15; i >= 0 && carry > 0n; i--) {
        const sum = BigInt(iv[i]) + carry;
        iv[i] = Number(sum & 0xffn);
        carry = sum >> 8n;
    }
    return iv;
}

async function handleStream(request, url) {
    const clipId = url.pathname.split('/').pop().replace('.mp4', '').replace('.webp', '');
    const meta = keysStore.get(clipId);
    
    if (!meta) {
        return new Response("Key not found. Ensure frontend registers the key first.", { status: 404 });
    }
    
    // Parse Range request from the video player
    const rangeHeader = request.headers.get("Range");
    let reqStart = 0;
    let reqEnd = '';
    
    if (rangeHeader) {
        const parts = rangeHeader.replace(/bytes=/, "").split("-");
        reqStart = parseInt(parts[0], 10);
        reqEnd = parts[1] ? parseInt(parts[1], 10) : '';
    }
    
    // AES-CTR operates on 16-byte blocks. We MUST align our fetch range to 16 bytes backwards to decrypt properly.
    const alignedStart = Math.floor(reqStart / 16) * 16;
    
    // Prepare the fetch to the backend storage
    const headers = new Headers();
    if (rangeHeader) {
        headers.set("Range", `bytes=${alignedStart}-${reqEnd}`);
    }
    
    let res;
    try {
        res = await fetch(meta.realUrl, { headers });
    } catch {
        return new Response("Network error fetching encrypted source", { status: 502 });
    }
    
    // Extract actual file size from the Content-Range header
    const contentRange = res.headers.get("Content-Range");
    let totalSize = '*';
    let resEnd = '';
    if (contentRange) {
        totalSize = contentRange.split('/')[1];
        resEnd = contentRange.split('/')[0].split('-')[1];
    }
    
    const encryptedBuffer = await res.arrayBuffer();
    
    // Calculate the exact IV state for this specific byte offset
    const blockOffset = Math.floor(alignedStart / 16);
    const chunkIv = incrementIv(meta.iv, blockOffset);
    
    // Decrypt just this chunk
    let decryptedBuffer;
    try {
        decryptedBuffer = await crypto.subtle.decrypt(
            { name: "AES-CTR", counter: chunkIv, length: 128 },
            meta.key,
            encryptedBuffer
        );
    } catch (e) {
        return new Response("Decryption failed", { status: 500 });
    }
    
    // Slice off any padding we grabbed at the start of the 16-byte block
    const sliceOffset = reqStart - alignedStart;
    const finalBuffer = decryptedBuffer.slice(sliceOffset);
    
    const responseHeaders = new Headers();
    const isDownload = url.searchParams.get('download') === '1';
    const ext = url.pathname.endsWith('.webp') ? 'webp' : 'mp4';
    const contentType = url.pathname.endsWith('.webp') ? "image/webp" : "video/mp4";
    
    responseHeaders.set("Content-Type", contentType);
    responseHeaders.set("Accept-Ranges", "bytes");
    responseHeaders.set("Access-Control-Allow-Origin", "*");

    if (isDownload) {
        // Trigger direct download behavior
        const filename = url.searchParams.get('filename') || `${clipId}.${ext}`;
        responseHeaders.set("Content-Disposition", `attachment; filename="${filename}"`);
    }
    
    if (rangeHeader || res.status === 206) {
        responseHeaders.set("Content-Range", `bytes=${reqStart}-${resEnd || (reqStart + finalBuffer.byteLength - 1)}/${totalSize}`);
        responseHeaders.set("Content-Length", finalBuffer.byteLength);
        return new Response(finalBuffer, { status: 206, headers: responseHeaders });
    } else {
        responseHeaders.set("Content-Length", finalBuffer.byteLength);
        return new Response(finalBuffer, { status: 200, headers: responseHeaders });
    }
}
