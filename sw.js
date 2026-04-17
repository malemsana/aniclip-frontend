const CACHE_NAME = 'aniclip-stream-cache-v1';
const keysStore = new Map(); // FAST TRACK RAM LAYER

// Minimal IndexedDB Wrapper for long-term key persistence
const IDB = {
    async get(id) {
        return new Promise((resolve) => {
            const req = indexedDB.open('streamKeys', 1);
            req.onupgradeneeded = (e) => e.target.result.createObjectStore('keys');
            req.onsuccess = (e) => {
                const db = e.target.result;
                if (!db.objectStoreNames.contains('keys')) return resolve(null);
                const getReq = db.transaction('keys').objectStore('keys').get(id);
                getReq.onsuccess = () => resolve(getReq.result);
                getReq.onerror = () => resolve(null);
            };
            req.onerror = () => resolve(null);
        });
    },
    async set(id, val) {
        return new Promise((resolve) => {
            const req = indexedDB.open('streamKeys', 1);
            req.onupgradeneeded = (e) => e.target.result.createObjectStore('keys');
            req.onsuccess = (e) => {
                const putReq = e.target.result.transaction('keys', 'readwrite').objectStore('keys').put(val, id);
                putReq.onsuccess = () => resolve();
            };
        });
    }
};

self.addEventListener("install", (event) => {
    self.skipWaiting();
});

self.addEventListener("activate", (event) => {
    event.waitUntil(clients.claim());
});

self.addEventListener("message", async (event) => {
    if (event.data.type === "REGISTER_KEY") {
        const { clipId, keyBytes, ivBytes, realUrl } = event.data;
        try {
            const key = await crypto.subtle.importKey("raw", keyBytes, { name: "AES-CTR" }, false, ["decrypt", "encrypt"]);
            const memoryVal = { key, iv: new Uint8Array(ivBytes), realUrl };
            
            // 1. Save to ultra-fast RAM immediately
            keysStore.set(clipId, memoryVal); 
            
            // 2. Persist to Hard Drive in the background (prevents micro-sleep data loss)
            IDB.set(clipId, memoryVal).catch(e => console.warn("IDB sync delayed", e));
        } catch (e) {
            console.error("SW Key Import Error:", e);
        }
    }
});

self.addEventListener("fetch", (event) => {
    const url = new URL(event.request.url);
    if (url.pathname.startsWith("/stream-decrypt/")) {
        event.respondWith(handleStream(event.request, url));
    }
});

function incrementIv(baseIv, blockOffset) {
    const iv = new Uint8Array(baseIv);
    let carry = BigInt(blockOffset);
    for (let i = 15; i >= 0 && carry > 0n; i--) {
        const sum = BigInt(iv[i]) + carry;
        iv[i] = Number(sum & 0xffn);
        carry = sum >> 8n;
    }
    return iv;
}

async function handleStream(request, url) {
    const clipId = url.pathname.split('/').pop().split('.')[0];
    
    // INSTANT LOOKUP
    let meta = keysStore.get(clipId);
    
    // BACKGROUND RECOVERY (If SW went to sleep)
    if (!meta) {
        meta = await IDB.get(clipId);
        if (meta) keysStore.set(clipId, meta); // Restore to fast track
    }
    
    if (!meta) {
        return new Response("Key not found. Refresh the page.", {
            status: 404,
            headers: { "Content-Type": "text/plain", "Access-Control-Allow-Origin": "*" }
        });
    }

    const rangeHeader = request.headers.get("Range");
    
    // Fetch the ENTIRE encrypted string for mathematical stability
    let res;
    try {
        res = await fetch(meta.realUrl);
    } catch (e) {
        return new Response("Storage error", { status: 502 });
    }

    if (!res.ok) return res;

    let encryptedBuffer;
    let decryptedBuffer;
    
    try {
        encryptedBuffer = await res.arrayBuffer();
        // Run a single, unified decryption pass exactly like the original code did
        decryptedBuffer = await crypto.subtle.decrypt(
            { name: "AES-CTR", counter: meta.iv, length: 128 },
            meta.key,
            encryptedBuffer
        );
    } catch (e) {
        console.error("SW Decryption completely failed:", e);
        return new Response("Decryption fault", { status: 500 });
    }

    const finalBytes = new Uint8Array(decryptedBuffer);
    const totalSize = finalBytes.length;

    const isDownload = url.searchParams.get('download') === '1';
    const responseHeaders = new Headers();
    responseHeaders.set("Content-Type", url.pathname.endsWith('.webp') ? "image/webp" : "video/mp4");
    responseHeaders.set("Accept-Ranges", "bytes");
    responseHeaders.set("Access-Control-Allow-Origin", "*");

    if (isDownload) {
        const filename = url.searchParams.get('filename') || `${clipId}.mp4`;
        responseHeaders.set("Content-Disposition", `attachment; filename="${filename}"`);
    }

    // Serve Range requests directly out of the perfectly decrypted buffer
    if (rangeHeader) {
        const parts = rangeHeader.replace(/bytes=/, "").split("-");
        const reqStart = parseInt(parts[0], 10);
        const reqEnd = parts[1] ? parseInt(parts[1], 10) : totalSize - 1;
        
        const chunk = finalBytes.slice(reqStart, reqEnd + 1);
        
        responseHeaders.set("Content-Range", `bytes=${reqStart}-${reqEnd}/${totalSize}`);
        responseHeaders.set("Content-Length", chunk.byteLength);
        return new Response(chunk, { status: 206, headers: responseHeaders });
    } else {
        responseHeaders.set("Content-Length", totalSize);
        return new Response(finalBytes, { status: 200, headers: responseHeaders });
    }
}
