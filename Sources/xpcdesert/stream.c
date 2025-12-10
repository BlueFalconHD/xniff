#include "stream.h"
#include <string.h>
#include <stdlib.h>

stream_t *stream_create(uint8_t *buffer, size_t size) {
    stream_t *stream = (stream_t *)malloc(sizeof(stream_t));
    if (!stream) {
        return NULL;
    }
    stream->buffer = buffer;
    stream->size = size;
    stream->position = 0;
    return stream;
}

void stream_destroy(stream_t *stream) {
    if (stream) {
        free(stream);
    }
}

size_t stream_read(stream_t *stream, void *out_buffer, size_t bytes_to_read) {
    if (!stream || !out_buffer) {
        return 0;
    }
    size_t remaining = stream->size - stream->position;
    size_t to_read = (bytes_to_read > remaining) ? remaining : bytes_to_read;
    memcpy(out_buffer, stream->buffer + stream->position, to_read);
    stream->position += to_read;
    return to_read;
}

int stream_seek(stream_t *stream, size_t position) {
    if (!stream || position > stream->size) {
        return -1;
    }
    stream->position = position;
    return 0;
}

size_t stream_tell(stream_t *stream) {
    if (!stream) {
        return 0;
    }
    return stream->position;
}

size_t stream_remaining(stream_t *stream) {
    if (!stream) {
        return 0;
    }
    return stream->size - stream->position;
}

uint8_t stream_read_u8(stream_t *stream) {
    uint8_t value = 0;
    stream_read(stream, &value, sizeof(uint8_t));
    return value;
}

uint32_t stream_read_u32_le(stream_t *stream) {
    uint32_t value = 0;
    stream_read(stream, &value, sizeof(uint32_t));
    return value;
}

uint64_t stream_read_u64_le(stream_t *stream) {
    uint64_t value = 0;
    stream_read(stream, &value, sizeof(uint64_t));
    return value;
}

void stream_align_to_next_4_bytes(stream_t *stream) {
    size_t pos = stream_tell(stream);
    size_t aligned_pos = (pos + 3) & ~3;
    stream_seek(stream, aligned_pos);
}
