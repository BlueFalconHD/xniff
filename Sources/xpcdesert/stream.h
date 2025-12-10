#ifndef STREAM_H
#define STREAM_H

#include <stdint.h>
#include <stdlib.h>

// a stream is a view of file data with a cursor and functionality to read data

typedef struct {
    uint8_t *buffer;
    size_t size;
    size_t position;
} stream_t;

stream_t *stream_create(uint8_t *buffer, size_t size);
void stream_destroy(stream_t *stream);
size_t stream_read(stream_t *stream, void *out_buffer, size_t bytes_to_read);
int stream_seek(stream_t *stream, size_t position);
size_t stream_tell(stream_t *stream);
size_t stream_remaining(stream_t *stream);

uint8_t stream_read_u8(stream_t *stream);
uint32_t stream_read_u32_le(stream_t *stream);
uint64_t stream_read_u64_le(stream_t *stream);

#endif /* STREAM_H */
