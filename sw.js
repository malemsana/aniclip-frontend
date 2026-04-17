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
            // FIX 1: Store pure bytes, NOT the un-serializable CryptoKey
            const memoryVal = { keyBytes, iv: new Uint8Array(ivBytes), realUrl };
            
            // Save to ultra-fast RAM immediately
            keysStore.set(clipId, memoryVal); 
            
            // Persist to Hard Drive in the background
            IDB.set(clipId, memoryVal).catch(e => console.warn("IDB sync delayed", e));
            
            // FIX 6: Send Acknowledgement back synchronously
            if (event.source) {
                event.source.postMessage({ type: 'KEY_READY', clipId });
            }
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

    // Natively import the key just-in-time from raw bytes
    let importedKey;
    try {
        importedKey = await crypto.subtle.importKey(
            "raw",
            meta.keyBytes,
            { name: "AES-CTR" },
            false,
            ["decrypt"]
        );
    } catch (e) {
        return new Response("Key import failed", { status: 500 });
    }

    // FIX 3: Parse and forward Range request
    const rangeHeader = request.headers.get("Range");
    let reqStart = 0;
    let reqEnd = '';
    
    if (rangeHeader) {
        const parts = rangeHeader.replace(/bytes=/, "").split("-");
        reqStart = parseInt(parts[0], 10);
        reqEnd = parts[1] ? parseInt(parts[1], 10) : '';
    }
    
    // FIX 2: Align start to 16-byte boundary for AES-CTR Counter Math
    const alignedStart = Math.floor(reqStart / 16) * 16;
    const fetchHeaders = new Headers();
    if (rangeHeader) {
        fetchHeaders.set("Range", `bytes=${alignedStart}-${reqEnd}`);
    }
    
    // Fetch specifically requested range
    let res;
    try {
        res = await fetch(meta.realUrl, { headers: fetchHeaders });
    } catch (e) {
        return new Response("Storage error", { status: 502 });
    }

    // FIX 5: Safer status check
    if (!(res.status === 200 || res.status === 206)) {
        return res;
    }

    const contentRange = res.headers.get("Content-Range");
    const totalSize = contentRange ? parseInt(contentRange.split('/')[1], 10) : parseInt(res.headers.get("Content-Length") || "0", 10);
    const actualResEnd = contentRange ? parseInt(contentRange.split('/')[0].split('-')[1], 10) : (totalSize > 0 ? totalSize - 1 : 0);

    // Initial IV for the exact chunk offset we are downloading
    const blockOffset = Math.floor(alignedStart / 16);
    let currentIv = incrementIv(meta.iv, blockOffset);
    
    // FIX 6: Safety bounding for slice math
    let skipBytes = Math.max(0, reqStart - alignedStart); 
    
    let remainder = new Uint8Array(0);
    
    // FIX 4: True Streaming Transform with Anti-Fragmentation buffering
    const { readable, writable } = new TransformStream({
        async transform(chunk, controller) {
            const data = new Uint8Array(remainder.length + chunk.length);
            data.set(remainder);
            data.set(chunk, remainder.length);
            
            // Wait for at least ~64KB of buffer to avoid overwhelming SubtleCrypto async
            const aesBlocks = Math.floor(data.length / 16);
            if (aesBlocks < 4096 && data.length < 65536) { 
                remainder = data;
                return;
            }
            
            const bytesToProcess = aesBlocks * 16;
            
            if (bytesToProcess === 0) {
                remainder = data;
                return;
            }
            
            const processChunk = data.slice(0, bytesToProcess);
            remainder = data.slice(bytesToProcess);
            
            try {
                const decrypted = await crypto.subtle.decrypt(
                    { name: "AES-CTR", counter: currentIv, length: 128 },
                    importedKey,
                    processChunk
                );
                
                let toSend = new Uint8Array(decrypted);
                
                if (skipBytes > 0) {
                    toSend = toSend.slice(skipBytes);
                    skipBytes = 0;
                }
                
                if (toSend.length > 0) {
                    controller.enqueue(toSend);
                }
                
                currentIv = incrementIv(currentIv, aesBlocks);
            } catch (e) {
                console.error("SW Decryption transform error:", e);
                controller.error(e);
            }
        },
        async flush(controller) {
            if (remainder.length > 0) {
                try {
                    const decrypted = await crypto.subtle.decrypt(
                        { name: "AES-CTR", counter: currentIv, length: 128 },
                        importedKey,
                        remainder
                    );
                    let toSend = new Uint8Array(decrypted);
                    if (skipBytes > 0) {
                        toSend = toSend.slice(skipBytes);
                    }
                    if (toSend.length > 0) {
                        controller.enqueue(toSend);
                    }
                } catch (e) {
                    console.error("SW Decryption flush error:", e);
                }
            }
        }
    });

    res.body.pipeTo(writable).catch(e => {
        // Silently ignore drop/abort
    });

    // FIX 5: Streaming Headers
    const isDownload = url.searchParams.get('download') === '1';
    const responseHeaders = new Headers();
    responseHeaders.set("Content-Type", url.pathname.endsWith('.webp') ? "image/webp" : "video/mp4");
    responseHeaders.set("Accept-Ranges", "bytes");
    responseHeaders.set("Access-Control-Allow-Origin", "*");
    responseHeaders.set("Cache-Control", "no-store");
    responseHeaders.set("Connection", "keep-alive");
    // FIX 4: Identity encoding to stop Chrome mangling the byte stream
    responseHeaders.set("Content-Encoding", "identity");

    if (isDownload) {
        const filename = url.searchParams.get('filename') || `${clipId}.mp4`;
        responseHeaders.set("Content-Disposition", `attachment; filename="${filename}"`);
    }

    if (rangeHeader || res.status === 206) {
        // FIX 1 & 2: Correct Range end and Content-Length math
        const contentLength = Math.max(0, actualResEnd - reqStart + 1);
        responseHeaders.set("Content-Range", `bytes=${reqStart}-${actualResEnd}/${totalSize}`);
        responseHeaders.set("Content-Length", contentLength.toString());
        return new Response(readable, { status: 206, headers: responseHeaders });
    } else {
        const contentLength = totalSize;
        responseHeaders.set("Content-Length", contentLength.toString());
        return new Response(readable, { status: 200, headers: responseHeaders });
    }
}
