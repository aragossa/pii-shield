const fs = require('fs');
const { WASI } = require('wasi');
const path = require('path');

class PiiShield {
    constructor(wasmInstance, memory, allocate, free_mem, init_config, redact_fn, failPolicy) {
        this.instance = wasmInstance;
        this.memory = memory;
        this.allocate = allocate;
        this.free_mem = free_mem;
        this.init_config = init_config;
        this.redact_fn = redact_fn;
        this.failPolicy = failPolicy || "open";
    }

    static async create(config = {}, wasmPath = null) {
        if (!wasmPath) {
            wasmPath = path.join(__dirname, 'pii-shield-wasi.wasm');
        }

        const wasi = new WASI({
            version: 'preview1',
            args: [],
            env: {},
        });

        const wasmBuffer = fs.readFileSync(wasmPath);
        const { instance } = await WebAssembly.instantiate(wasmBuffer, {
            wasi_snapshot_preview1: wasi.wasiImport
        });

        wasi.initialize(instance);

        const memory = instance.exports.memory;
        const allocate = instance.exports.allocate;
        const free_mem = instance.exports.free;
        const init_config = instance.exports.init_config;
        const redact_fn = instance.exports.redact;

        const shield = new PiiShield(instance, memory, allocate, free_mem, init_config, redact_fn, config.failPolicy);

        // Serialize config and pass to WASM
        const cfgObj = {};
        if (config.entropyThreshold) cfgObj.entropy_threshold = config.entropyThreshold;
        if (config.salt) cfgObj.salt = config.salt;
        if (config.confidenceScore) cfgObj.confidence_score = config.confidenceScore;
        if (config.minSecretLength) cfgObj.min_secret_length = config.minSecretLength;
        if (config.sensitiveKeys) cfgObj.sensitive_keys = config.sensitiveKeys;
        if (config.disableBigramCheck !== undefined) cfgObj.disable_bigram_check = config.disableBigramCheck;
        if (config.adaptiveThreshold !== undefined) cfgObj.adaptive_threshold = config.adaptiveThreshold;
        if (config.sensitiveKeyPatterns) cfgObj.sensitive_key_patterns = config.sensitiveKeyPatterns;
        if (config.customRegexes) cfgObj.custom_regexes = config.customRegexes;
        if (config.safeRegexes) cfgObj.safe_regexes = config.safeRegexes;

        const cfgJson = JSON.stringify(cfgObj);
        const cfgBytes = new TextEncoder().encode(cfgJson);
        const cfgPtr = shield.allocate(cfgBytes.length);
        
        if (cfgPtr !== 0) {
            const memArr = new Uint8Array(shield.memory.buffer);
            memArr.set(cfgBytes, cfgPtr);
            shield.init_config(cfgPtr, cfgBytes.length);
            // Note: init_config does not allocate new memory that we must free.
            // But we should free cfgPtr? Wait, `init_config` reads it,
            // we should probably free `cfgPtr` because it was allocated by `allocate()`!
            shield.free_mem(cfgPtr, cfgBytes.length);
        }

        return shield;
    }

    redact(input) {
        if (!input) return input;
        
        try {
            const inputBytes = new TextEncoder().encode(input);
            const inputPtr = this.allocate(inputBytes.length);
            
            if (inputPtr === 0) {
                if (this.failPolicy === "closed") {
                    return "[PII_SHIELD_DROP: FATAL_ERROR]";
                }
                return input;
            }

            const memArr = new Uint8Array(this.memory.buffer);
            memArr.set(inputBytes, inputPtr);

            // Call WebAssembly
            const packedResult = this.redact_fn(inputPtr, inputBytes.length);
            
            // PackedResult is a BigInt. BigInt shifting
            const resultPtr = Number(packedResult >> 32n);
            const resultLen = Number(packedResult & 0xFFFFFFFFn);
            
            let resultString = input; // fallback

            if (resultPtr !== 0 && resultLen !== 0) {
                // Must read memory AGAIN because memory.buffer could have grown!
                const outMemArr = new Uint8Array(this.memory.buffer);
                const outBytes = outMemArr.subarray(resultPtr, resultPtr + resultLen);
                resultString = new TextDecoder("utf-8").decode(outBytes);
                
                // Free the exported memory
                this.free_mem(resultPtr, resultLen);
            }
            
            // We should also free the inputPtr we allocated!
            this.free_mem(inputPtr, inputBytes.length);
            
            return resultString;

        } catch (error) {
            if (this.failPolicy === "closed") {
                 return "[PII_SHIELD_DROP: FATAL_ERROR]";
            }
            return input;
        }
    }
}

module.exports = { PiiShield };
