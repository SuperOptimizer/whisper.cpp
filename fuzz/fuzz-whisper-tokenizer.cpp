/*
 * Fuzz harness for whisper.cpp tokenization.
 *
 * This harness tests the tokenizer functionality:
 * - Text to token conversion
 * - Token to text conversion
 * - UTF-8 handling
 * - Special character handling
 *
 * Key vulnerability areas:
 * - Buffer overflows in tokenization
 * - Invalid UTF-8 handling
 * - Special token edge cases
 *
 * Note: This requires a valid model to initialize the tokenizer.
 */

#include "whisper.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

// Suppress whisper.cpp logging during fuzzing
static void null_log_callback(enum ggml_log_level level, const char* text, void* user_data) {
    (void)level;
    (void)text;
    (void)user_data;
}

// Static context - initialized once with a valid model
static struct whisper_context* g_ctx = nullptr;
static bool g_init_attempted = false;

static void init_context() {
    if (g_init_attempted) return;
    g_init_attempted = true;

    whisper_log_set(null_log_callback, nullptr);

    // Try to load a model from common paths
    const char* model_paths[] = {
        "/home/forrest/fuzzers2/corpus/whisper-gguf/ggml-tiny.bin",
        "/home/forrest/fuzzers2/corpus/whisper-gguf/ggml-tiny.en.bin",
        "models/ggml-tiny.bin",
        "models/ggml-tiny.en.bin",
        nullptr
    };

    struct whisper_context_params params = whisper_context_default_params();
    params.use_gpu = false;
    params.flash_attn = false;

    for (int i = 0; model_paths[i] != nullptr; i++) {
        g_ctx = whisper_init_from_file_with_params(model_paths[i], params);
        if (g_ctx) break;
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Initialize context once
    init_context();
    if (!g_ctx) return 0;  // Can't test without a model

    // Need at least some text
    if (size < 1) return 0;

    // Cap input size
    if (size > 64 * 1024) return 0;

    // Create null-terminated string from fuzz input
    char* text = (char*)malloc(size + 1);
    if (!text) return 0;
    memcpy(text, data, size);
    text[size] = '\0';

    // Allocate token buffer
    int max_tokens = 1024;
    whisper_token* tokens = (whisper_token*)malloc(max_tokens * sizeof(whisper_token));
    if (!tokens) {
        free(text);
        return 0;
    }

    // Tokenize the text
    int n_tokens = whisper_tokenize(g_ctx, text, tokens, max_tokens);

    // If tokenization succeeded, convert tokens back to text
    if (n_tokens > 0 && n_tokens <= max_tokens) {
        for (int i = 0; i < n_tokens; i++) {
            const char* token_str = whisper_token_to_str(g_ctx, tokens[i]);
            (void)token_str;
        }
    }

    // Also try with token count estimation
    (void)whisper_token_count(g_ctx, text);

    // Test language-related functions with fuzzed input (treated as language code)
    if (size >= 2 && size <= 32) {
        // Try to interpret as language code
        (void)whisper_lang_id(text);
    }

    free(tokens);
    free(text);

    return 0;
}

#ifndef FUZZ_WITH_LIBFUZZER
int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    FILE* f = fopen(argv[1], "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (size <= 0 || size > 100 * 1024 * 1024) {
        fclose(f);
        return 1;
    }

    uint8_t* data = (uint8_t*)malloc(size);
    if (!data) {
        fclose(f);
        return 1;
    }

    if (fread(data, 1, size, f) != (size_t)size) {
        free(data);
        fclose(f);
        return 1;
    }
    fclose(f);

    int result = LLVMFuzzerTestOneInput(data, size);

    free(data);
    return result;
}
#endif
