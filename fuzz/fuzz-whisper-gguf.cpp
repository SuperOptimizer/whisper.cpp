/*
 * Fuzz harness for whisper.cpp GGUF model loading.
 *
 * This harness tests whisper.cpp's model loading path which includes:
 * - GGUF parsing and validation
 * - Model hyperparameter loading
 * - Mel filter bank loading
 * - Vocabulary loading
 * - Tensor loading and validation
 *
 * Key vulnerability areas:
 * - Integer overflow in tensor size calculations
 * - Buffer overflow in string/metadata parsing
 * - Invalid tensor type handling
 * - Memory exhaustion via large allocation requests
 *
 * Uses memfd_create() to avoid temp file pollution during fuzzing.
 */

#include "whisper.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <sys/mman.h>

// Create an anonymous in-memory file with the fuzzed data
static int create_memfd(const uint8_t* data, size_t size) {
    int fd = memfd_create("fuzz_whisper_gguf", MFD_CLOEXEC);
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

    // Set up context params
    struct whisper_context_params params = whisper_context_default_params();
    params.use_gpu = false;
    params.flash_attn = false;

    // Attempt to load the model
    struct whisper_context* ctx = whisper_init_from_file_with_params(path, params);

    if (ctx) {
        // Exercise metadata accessors to trigger any lazy parsing
        (void)whisper_n_vocab(ctx);
        (void)whisper_n_text_ctx(ctx);
        (void)whisper_n_audio_ctx(ctx);
        (void)whisper_is_multilingual(ctx);

        // Model info accessors
        (void)whisper_model_n_vocab(ctx);
        (void)whisper_model_n_audio_ctx(ctx);
        (void)whisper_model_n_audio_state(ctx);
        (void)whisper_model_n_audio_head(ctx);
        (void)whisper_model_n_audio_layer(ctx);
        (void)whisper_model_n_text_ctx(ctx);
        (void)whisper_model_n_text_state(ctx);
        (void)whisper_model_n_text_head(ctx);
        (void)whisper_model_n_text_layer(ctx);
        (void)whisper_model_n_mels(ctx);
        (void)whisper_model_ftype(ctx);
        (void)whisper_model_type(ctx);

        // Get model type as string
        (void)whisper_model_type_readable(ctx);

        // Get special tokens
        (void)whisper_token_eot(ctx);
        (void)whisper_token_sot(ctx);
        (void)whisper_token_prev(ctx);
        (void)whisper_token_nosp(ctx);
        (void)whisper_token_not(ctx);
        (void)whisper_token_beg(ctx);

        // Query a few tokens if vocab exists
        int n_vocab = whisper_n_vocab(ctx);
        if (n_vocab > 0 && n_vocab < 100000) {
            for (int i = 0; i < n_vocab && i < 10; i++) {
                (void)whisper_token_to_str(ctx, i);
            }
        }

        // Print system info (exercises some code paths)
        (void)whisper_print_system_info();

        // Free the context
        whisper_free(ctx);
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
