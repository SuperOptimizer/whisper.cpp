/*
 * Fuzz harness for whisper.cpp PCM to mel spectrogram conversion.
 *
 * This harness tests the audio processing pipeline:
 * - PCM to log mel spectrogram conversion
 * - FFT/DSP operations
 * - Floating point edge cases (NaN, Inf, denormals)
 *
 * Key vulnerability areas:
 * - Buffer overflows in FFT buffers
 * - Floating point exceptions
 * - Integer overflow in sample count calculations
 *
 * Note: This requires a valid model to initialize the context.
 * We use a minimal model or skip if model loading fails.
 */

#include "whisper.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>

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

    // Need at least some audio samples (as floats)
    if (size < sizeof(float) * 4) return 0;

    // Cap input size to prevent excessive processing time
    // 16000 samples = 1 second at 16kHz, allow up to 5 seconds
    if (size > sizeof(float) * 16000 * 5) return 0;

    // Interpret input as float samples
    int n_samples = size / sizeof(float);
    const float* samples = reinterpret_cast<const float*>(data);

    // Create a state for this fuzz run
    struct whisper_state* state = whisper_init_state(g_ctx);
    if (!state) return 0;

    // Convert PCM to mel spectrogram
    int result = whisper_pcm_to_mel_with_state(
        g_ctx,
        state,
        samples,
        n_samples,
        1  // single thread for fuzzing
    );

    if (result == 0) {
        // Get mel length to exercise accessor
        (void)whisper_n_len_from_state(state);
    }

    // Free the state
    whisper_free_state(state);

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
