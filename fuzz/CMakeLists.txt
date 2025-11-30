# Fuzz targets for whisper.cpp
#
# Build with: cmake -DWHISPER_BUILD_FUZZ=ON ..

find_package(Threads REQUIRED)

# Common settings for fuzz targets
set(FUZZ_COMPILE_FLAGS "")
set(FUZZ_LINK_FLAGS "")

# fuzz-whisper-gguf: GGUF model loading fuzzer
set(FUZZ_TARGET fuzz-whisper-gguf)
add_executable(${FUZZ_TARGET} ${FUZZ_TARGET}.cpp)
target_link_libraries(${FUZZ_TARGET} PRIVATE whisper Threads::Threads)
target_include_directories(${FUZZ_TARGET} PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/ggml/include
    ${CMAKE_SOURCE_DIR}/src
)

# fuzz-whisper-pcm: PCM to mel spectrogram fuzzer
set(FUZZ_TARGET fuzz-whisper-pcm)
add_executable(${FUZZ_TARGET} ${FUZZ_TARGET}.cpp)
target_link_libraries(${FUZZ_TARGET} PRIVATE whisper Threads::Threads)
target_include_directories(${FUZZ_TARGET} PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/ggml/include
    ${CMAKE_SOURCE_DIR}/src
)

# fuzz-whisper-tokenizer: Tokenization fuzzer
set(FUZZ_TARGET fuzz-whisper-tokenizer)
add_executable(${FUZZ_TARGET} ${FUZZ_TARGET}.cpp)
target_link_libraries(${FUZZ_TARGET} PRIVATE whisper Threads::Threads)
target_include_directories(${FUZZ_TARGET} PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/ggml/include
    ${CMAKE_SOURCE_DIR}/src
)

# fuzz-whisper-vad: Voice Activity Detection fuzzer
set(FUZZ_TARGET fuzz-whisper-vad)
add_executable(${FUZZ_TARGET} ${FUZZ_TARGET}.cpp)
target_link_libraries(${FUZZ_TARGET} PRIVATE whisper Threads::Threads)
target_include_directories(${FUZZ_TARGET} PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/ggml/include
    ${CMAKE_SOURCE_DIR}/src
)

# Install fuzz targets to bin directory
install(TARGETS fuzz-whisper-gguf fuzz-whisper-pcm fuzz-whisper-tokenizer fuzz-whisper-vad
    RUNTIME DESTINATION bin
)
