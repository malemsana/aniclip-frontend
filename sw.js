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
    let reqStart = 0;
    let reqEnd = '';

    if (rangeHeader) {
        const parts = rangeHeader.replace(/bytes=/, "").split("-");
        reqStart = parseInt(parts[0], 10);
        reqEnd = parts[1] ? parseInt(parts[1], 10) : '';
    }

    // Align start to 16-byte boundary for AES-CTR
    const alignedStart = Math.floor(reqStart / 16) * 16;
    const headers = new Headers();
    if (rangeHeader) {
        headers.set("Range", `bytes=${alignedStart}-${reqEnd}`);
    }

    let res;
    try {
        res = await fetch(meta.realUrl, { headers });
    } catch (e) {
        return new Response("Storage error", { status: 502 });
    }

    if (!res.ok && res.status !== 206) return res;

    const contentRange = res.headers.get("Content-Range");
    const totalSize = contentRange ? contentRange.split('/')[1] : res.headers.get("Content-Length");
    const actualResEnd = contentRange ? contentRange.split('/')[0].split('-')[1] : (parseInt(totalSize) - 1);

    // Initial IV for the start of this stream request
    let currentIv = incrementIv(meta.iv, Math.floor(alignedStart / 16));
    let skipBytes = reqStart - alignedStart;
    
    let remainder = new Uint8Array(0);
    
    const { readable, writable } = new TransformStream({
        async transform(chunk, controller) {
            // Combine previous remainder with new network chunk
            const data = new Uint8Array(remainder.length + chunk.length);
            data.set(remainder);
            data.set(chunk, remainder.length);
            
            // For AES-CTR with SubtleCrypto, we must process exact 16-byte multiples
            const completeBlocks = Math.floor(data.length / 16);
            const bytesToProcess = completeBlocks * 16;
            
            if (bytesToProcess === 0) {
                remainder = data; // Wait for more data
                return;
            }
            
            const processChunk = data.slice(0, bytesToProcess);
            remainder = data.slice(bytesToProcess);
            
            try {
                const decrypted = await crypto.subtle.decrypt(
                    { name: "AES-CTR", counter: currentIv, length: 128 },
                    meta.key,
                    processChunk
                );
                
                let toSend = new Uint8Array(decrypted);
                
                // If this is the very first chunk of a misaligned range request, slice off the padding prefix
                if (skipBytes > 0) {
                    toSend = toSend.slice(skipBytes);
                    skipBytes = 0;
                }
                
                controller.enqueue(toSend);
                
                // Update IV for the next chunk precisely by the number of complete blocks
                currentIv = incrementIv(currentIv, completeBlocks);
            } catch (e) {
                console.error("Decryption transform error:", e);
                controller.error(e);
            }
        },
        async flush(controller) {
            if (remainder.length > 0) {
                try {
                    const decrypted = await crypto.subtle.decrypt(
                        { name: "AES-CTR", counter: currentIv, length: 128 },
                        meta.key,
                        remainder
                    );
                    let toSend = new Uint8Array(decrypted);
                    if (skipBytes > 0) {
                        toSend = toSend.slice(skipBytes);
                    }
                    controller.enqueue(toSend);
                } catch (e) {
                    console.error("Decryption flush error:", e);
                    // Don't error the controller here, just drop the trailing bytes to prevent pipeline crash
                }
            }
        }
    });

    res.body.pipeTo(writable).catch(e => {
        // Silently ignore standard aborts from the player dropping the stream (e.g. user unhovers)
    });

    const isDownload = url.searchParams.get('download') === '1';
    const responseHeaders = new Headers();
    responseHeaders.set("Content-Type", url.pathname.endsWith('.webp') ? "image/webp" : "video/mp4");
    responseHeaders.set("Accept-Ranges", "bytes");
    responseHeaders.set("Access-Control-Allow-Origin", "*");

    if (isDownload) {
        const filename = url.searchParams.get('filename') || `${clipId}.mp4`;
        responseHeaders.set("Content-Disposition", `attachment; filename="${filename}"`);
    }

    if (rangeHeader || res.status === 206) {
        responseHeaders.set("Content-Range", `bytes=${reqStart}-${actualResEnd}/${totalSize}`);
        return new Response(readable, { status: 206, headers: responseHeaders });
    } else {
        return new Response(readable, { status: 200, headers: responseHeaders });
    }
}
