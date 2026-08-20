export interface PiiShieldConfig {
    entropyThreshold?: number;
    salt?: string;
    confidenceScore?: number;
    failPolicy?: "open" | "closed";
    /** Minimum candidate token length before entropy checks apply. */
    minSecretLength?: number;
    /** Key names whose values are always redacted (case-insensitive). Replaces the defaults. */
    sensitiveKeys?: string[];
    /** Disable English bigram analysis (useful for non-English logs). */
    disableBigramCheck?: boolean;
    /** Enable experimental statistical adaptive-threshold mode. */
    adaptiveThreshold?: boolean;
    /** Emit [HIDDEN:<type>:<hash>] markers (type is card/key/context/url/regex/entropy). Off by default. */
    entityTypeLabels?: boolean;
    /** Regex patterns matched against key names to detect sensitive keys. */
    sensitiveKeyPatterns?: string[];
    /** Custom rules forcing redaction of matching tokens. */
    customRegexes?: CustomRegexRule[];
    /** Whitelist rules exempting matching tokens from redaction. */
    safeRegexes?: CustomRegexRule[];
}

export interface CustomRegexRule {
    /** RE2 pattern. An invalid pattern is ignored rather than throwing. */
    pattern: string;
    /** Label for the rule. */
    name: string;
}

export class PiiShield {
    /**
     * Instantiates the WebAssembly module and synchronizes configuration.
     * @param config The PII Shield configuration overrides.
     * @param wasmPath Optional path to the pii-shield-wasi.wasm binary.
     */
    static create(config?: PiiShieldConfig, wasmPath?: string): Promise<PiiShield>;

    /**
     * Redact sensitive information from the given input string.
     * @param input Raw log line or string containing potential PII/secrets.
     * @returns The redacted string.
     */
    redact(input: string): string;
}
