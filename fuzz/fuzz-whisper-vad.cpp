/*
 * Fuzz harness for whisper.cpp Voice Activity Detection (VAD).
 *
 * This harness tests the VAD functionality:
 * - VAD model loading (GGUF format)
 * - Speech detection from audio samples
 * - VAD segment extraction
 *
 * Key vulnerability areas:
 * - Buffer overflows in VAD processing
 * - Invalid probability handling
 * - Segment boundary edge cases
 *
 * Uses memfd_create() to avoid temp file pollution during fuzzing.
 */

#include "whisper.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <unistd.h>
#include <sys/mman.h>

// Create an anonymous in-memory file with the fuzzed data
static int create_memfd(const uint8_t* data, size_t size) {
    int fd = memfd_create("fuzz_whisper_vad", MFD_CLOEXEC);
    if (fd < 0) return -1;

    if (ftruncate(fd, size) < 0) {
        close(fd);
        return -1;
    }

    ssize_t written = write(fd, data, size);
    if (written != (ssize_t)size) {
        close(fd);
        return -1;
    }

    lseek(fd, 0, SEEK_SET);
    return fd;
}

// Get the path to an fd via /proc/self/fd/
static void get_fd_path(int fd, char* buf, size_t buf_size) {
    snprintf(buf, buf_size, "/proc/self/fd/%d", fd);
}

// Suppress whisper.cpp logging during fuzzing
static void null_log_callback(enum ggml_log_level level, const char* text, void* user_data) {
    (void)level;
    (void)text;
    (void)user_data;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Need at least a minimal GGUF header
    if (size < 32) return 0;

    // Cap input size to prevent OOM during fuzzing
    if (size > 10 * 1024 * 1024) return 0;

    // Suppress logging
    whisper_log_set(null_log_callback, nullptr);

    // Create memfd with fuzzed data
    int fd = create_memfd(data, size);
    if (fd < 0) return 0;

    char path[64];
    get_fd_path(fd, path, sizeof(path));

    // Set up VAD context params
    struct whisper_vad_context_params params = whisper_vad_default_context_params();
    params.use_gpu = false;
    params.n_threads = 1;

    // Attempt to load the VAD model
    struct whisper_vad_context* vctx = whisper_vad_init_from_file_with_params(path, params);

    if (vctx) {
        // Get number of probs (exercises model accessors)
        int n_probs = whisper_vad_n_probs(vctx);
        (void)n_probs;

        // Get probability array
        float* probs = whisper_vad_probs(vctx);
        (void)probs;

        // Test with some dummy audio samples if model loaded
        float dummy_samples[1600];  // 100ms at 16kHz
        memset(dummy_samples, 0, sizeof(dummy_samples));

        // Simple sine wave
        for (int i = 0; i < 1600; i++) {
            dummy_samples[i] = 0.1f * sinf(2.0f * 3.14159f * 440.0f * i / 16000.0f);
        }

        // Detect speech
        bool has_speech = whisper_vad_detect_speech(vctx, dummy_samples, 1600);
        (void)has_speech;

        // Get segments from probs
        struct whisper_vad_params vad_params = whisper_vad_default_params();
        struct whisper_vad_segments* segments = whisper_vad_segments_from_probs(vctx, vad_params);

        if (segments) {
            int n_segments = whisper_vad_segments_n_segments(segments);
            for (int i = 0; i < n_segments && i < 10; i++) {
                (void)whisper_vad_segments_get_segment_t0(segments, i);
                (void)whisper_vad_segments_get_segment_t1(segments, i);
            }
            whisper_vad_free_segments(segments);
        }

        // Also try segments from samples
        segments = whisper_vad_segments_from_samples(vctx, vad_params, dummy_samples, 1600);
        if (segments) {
            whisper_vad_free_segments(segments);
        }

        // Free the VAD context
        whisper_vad_free(vctx);
    }

    // Cleanup
    close(fd);

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
