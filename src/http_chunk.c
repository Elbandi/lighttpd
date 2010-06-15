/**
 * the HTTP chunk-API
 *
 *
 */

#include "server.h"
#include "chunk.h"
#include "http_chunk.h"
#include "log.h"

#include <sys/types.h>
#include <sys/stat.h>

#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#include <stdio.h>
#include <errno.h>
#include <string.h>

static int http_chunk_append_len(server *srv, connection *con, size_t len) {
	size_t i, olen = len, j;
	buffer *b;

	b = srv->tmp_chunk_len;

	if (len == 0) {
		buffer_copy_string_len(b, CONST_STR_LEN("0"));
	} else {
		for (i = 0; i < 8 && len; i++) {
			len >>= 4;
		}

		/* i is the number of hex digits we have */
		buffer_prepare_copy(b, i + 1);

		for (j = i-1, len = olen; j+1 > 0; j--) {
			b->ptr[j] = (len & 0xf) + (((len & 0xf) <= 9) ? '0' : 'a' - 10);
			len >>= 4;
		}
		b->used = i;
		b->ptr[b->used++] = '\0';
	}

	buffer_append_string_len(b, CONST_STR_LEN("\r\n"));
	chunkqueue_append_buffer(con->write_queue, b);

	return 0;
}


int http_chunk_append_file(server *srv, connection *con, buffer *fn, off_t offset, off_t len) {
	chunkqueue *cq;

	if (!con) return -1;

	cq = con->write_queue;


	chunkqueue_append_file(cq, fn, offset, len);

	return 0;
}

int http_chunk_append_buffer(server *srv, connection *con, buffer *mem) {
	chunkqueue *cq;

	if (!con) return -1;

	cq = con->write_queue;


	chunkqueue_append_buffer(cq, mem);

	return 0;
}

int http_chunk_append_mem(server *srv, connection *con, const char * mem, size_t len) {
	chunkqueue *cq;

	if (!con) return -1;

	cq = con->write_queue;

	if (len == 0) {
		return 0;
	}

	chunkqueue_append_mem(cq, mem, len);

	return 0;
}


off_t http_chunkqueue_length(server *srv, connection *con) {
	if (!con) {
		log_error_write(srv, __FILE__, __LINE__, "s", "connection is NULL!!");

		return 0;
	}

	return chunkqueue_length(con->write_queue);
}
