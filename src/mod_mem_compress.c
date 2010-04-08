/* 
Copyright (c) 2007, 2009 QUE Hongyu

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:
1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
SUCH DAMAGE.

*/

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include "config.h"
#include "base.h"
#include "log.h"
#include "buffer.h"
#include "response.h"
#include "stat_cache.h"
#include "status_counter.h"
#include "plugin.h"

#if defined(HAVE_PCRE_H)
#include <pcre.h>
#endif

#include "crc32.h"
#include "etag.h"

#if defined HAVE_ZLIB_H && defined HAVE_LIBZ
# define USE_ZLIB
# include <zlib.h>
#endif

#include "sys-mmap.h"
#include "version.h"

/* request: accept-encoding */
#define HTTP_ACCEPT_ENCODING_GZIP     BV(0)
#define HTTP_ACCEPT_ENCODING_DEFLATE  BV(1)

#define CONFIG_MEM_COMPRESS_ENABLE "mem-compress.enable"
#define CONFIG_MEM_COMPRESS_MAX_MEMORY "mem-compress.max-memory"
#define CONFIG_MEM_COMPRESS_MAX_FILE_SIZE "mem-compress.max-file-size"
#define CONFIG_MEM_COMPRESS_LRU_REMOVE_COUNT "mem-compress.lru-remove-count"
#define CONFIG_MEM_COMPRESS_COMPRESSION_LEVEL "mem-compress.compression-level"
#define CONFIG_MEM_COMPRESS_NOCOMPRESS_URL "mem-compress.no-compress-url"
#define CONFIG_MEM_COMPRESS_FILE_TYPES "mem-compress.filetypes"

#define MEMCOMPRESS_USED "mem-compress.used-memory(KB)"
#define MEMCOMPRESS_ITEMS "mem-compress.cached-items"
#define MEMCOMPRESS_HITRATE "mem-compress.hitrate(%)"

#ifdef LIGHTTPD_V15
data_integer *memcompress_used;
data_integer *memcompress_items;
data_integer *memcompress_hitrate;
#endif

typedef struct
{
	/* mem-compress.filetypes */
	array  *compress;
	/* mem-compress.no-compress-url */
	buffer 	*nocompress_url;
#if defined(HAVE_PCRE_H)
	pcre	*nocompress_regex;
#endif
	/* mem-compress.enable */
	unsigned short enable;
	/* number of cache items removed by lru when memory is full */
	/* mem-compress.lru-remove-count */
	unsigned short lru_remove_count;
	/* mem-compress.compression-level */
	short compression_level;
	/* mem-compress.max-memory */
	uint32_t maxmemory; /* maxium total used memory in MB */
	/* memcomprss.max-file-size */
	uint32_t maxfilesize; /* maxium file size will put into memory */
} plugin_config;

#define MEM_CACHE_NUM 65536 /* 2^16 */
#define MEM_HASH_MASK (MEM_CACHE_NUM-1)

static int lruheader, lruend;
static uint32_t reqcount, reqhit, cachenumber, usedmemory;
static char nulltrailer = '\0';

struct gzip_cache
{
	short inuse;
	/* cached gzip data */
	buffer *content;

	struct gzip_cache *scnext;

	/* lru info */
	unsigned int prev;
	unsigned int next;

	/*file info*/
	buffer *path;

	time_t last_modified;
};

static struct gzip_cache *memcache = NULL;

typedef struct
{
	PLUGIN_DATA;
	buffer *b;
	
	plugin_config **config_storage;
	plugin_config conf; 
} plugin_data;

/* init cache_entry table */
static struct gzip_cache *
global_gzip_cache_init(void)
{
	struct gzip_cache *c;
	c = (struct gzip_cache *) calloc(MEM_CACHE_NUM + 1, sizeof(struct gzip_cache));
	return c;
}

/* free cache_entry */
static void
gzip_cache_free(struct gzip_cache *cache)
{
	if (cache == NULL) return;
	cachenumber --;
	if (cache->content) {
		usedmemory -= cache->content->size;
		buffer_free(cache->content);
		cache->content = NULL;
	}
	buffer_free(cache->path);
	memset(cache, 0, sizeof(struct gzip_cache));
}

/* reset cache_entry to initial state */
static void
init_gzip_cache(struct gzip_cache *cache)
{
	if (cache == NULL) return;
	if (cache->content == NULL) {
		cache->content = buffer_init();
	} else if (cache->content->ref_count > 1) {
		/* another guy is using old content, we need to put it away from struct first */
		cache->content->ref_count --; // lower content->ref_count, makes it to be freed later
		/* allocate new content buffer */
		cache->content = buffer_init();
	} else {
		cache->content->ref_count = 0;
	}

	if (cache->path == NULL) cache->path = buffer_init();
}

INIT_FUNC(mod_mem_compress_init)
{
	plugin_data *p;
	
#ifdef LIGHTTPD_V15
	UNUSED(srv);
	memcompress_used = status_counter_get_counter(CONST_STR_LEN(MEMCOMPRESS_USED));
	memcompress_items = status_counter_get_counter(CONST_STR_LEN(MEMCOMPRESS_ITEMS));
	memcompress_hitrate = status_counter_get_counter(CONST_STR_LEN(MEMCOMPRESS_HITRATE));
#endif

	p = calloc(1, sizeof(*p));
	p->b = buffer_init();
	memcache = global_gzip_cache_init();
	lruheader = lruend = usedmemory = cachenumber = 0;
	reqcount = reqhit = 1;
	return p;
}

void
free_gzip_cache_chain(struct gzip_cache *p)
{
	struct gzip_cache *c1, *c2;

	c1 = p;
	while(c1) {
		c2 = c1->scnext;
		gzip_cache_free(c1);
		if (c1 != p) free(c1);
		c1 = c2;
	}
}

FREE_FUNC(mod_mem_compress_free)
{
	plugin_data *p = p_d;
	size_t i;
	
	UNUSED(srv);

	if (!p) return HANDLER_GO_ON;
	
	buffer_free(p->b);
	
	if (p->config_storage) {
		for (i = 0; i < srv->config_context->used; i++) {
			plugin_config *s = p->config_storage[i];

			if (!s) continue;
			
			array_free(s->compress);
			buffer_free(s->nocompress_url);
#if defined(HAVE_PCRE_H)
	       	if (s->nocompress_regex) pcre_free(s->nocompress_regex);
#endif
			free(s);
		}
		free(p->config_storage);
	}
	free(p);
	for (i = 0; i<=MEM_CACHE_NUM; i++) {
		free_gzip_cache_chain(memcache+i);
	}
	free(memcache);
	return HANDLER_GO_ON;
}

SETDEFAULTS_FUNC(mod_mem_compress_setdefaults)
{
	plugin_data *p = p_d;
	size_t i = 0;
	
	config_values_t cv[] = { 
		{ CONFIG_MEM_COMPRESS_FILE_TYPES,	NULL, T_CONFIG_ARRAY, T_CONFIG_SCOPE_CONNECTION }, /* 0 */
		{ CONFIG_MEM_COMPRESS_MAX_FILE_SIZE,	NULL, T_CONFIG_SHORT, T_CONFIG_SCOPE_CONNECTION }, /* 1 */
		{ CONFIG_MEM_COMPRESS_MAX_MEMORY,	NULL, T_CONFIG_SHORT, T_CONFIG_SCOPE_CONNECTION }, /* 2 */
		{ CONFIG_MEM_COMPRESS_NOCOMPRESS_URL,	NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION }, /* 3 */
		{ CONFIG_MEM_COMPRESS_ENABLE,		NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION }, /* 4 */
		{ CONFIG_MEM_COMPRESS_LRU_REMOVE_COUNT,	NULL, T_CONFIG_SHORT, T_CONFIG_SCOPE_CONNECTION }, /* 5 */
		{ CONFIG_MEM_COMPRESS_COMPRESSION_LEVEL,	NULL, T_CONFIG_SHORT, T_CONFIG_SCOPE_CONNECTION }, /* 6 */
		{ NULL, NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
	};
	
	p->config_storage = calloc(1, srv->config_context->used * sizeof(specific_config *));
	
	for (i = 0; i < srv->config_context->used; i++) {
		plugin_config *s;
#if defined(HAVE_PCRE_H)
		const char *errptr;
		int erroff;
#endif
		
		s = calloc(1, sizeof(plugin_config));
		s->compress = array_init();
		s->maxfilesize = 4096; /* default 4M */
		s->maxmemory = 256; /* default max 256 MB */
		s->nocompress_url = buffer_init();
		s->enable = 1;
		s->lru_remove_count = 500; /* default 500 */
		s->compression_level = Z_DEFAULT_COMPRESSION;
#if defined(HAVE_PCRE_H)
		s->nocompress_regex = NULL;
#endif
		
		cv[0].destination = s->compress;
		cv[1].destination = &(s->maxfilesize);
		cv[2].destination = &(s->maxmemory);
		cv[3].destination = s->nocompress_url;
		cv[4].destination = &(s->enable);
		cv[5].destination = &(s->lru_remove_count);
		cv[6].destination = &(s->compression_level);
		
		p->config_storage[i] = s;
	
		if (0 != config_insert_values_global(srv, ((data_config *)srv->config_context->data[i])->value, cv)) {
			return HANDLER_ERROR;
		}

		if((s->compression_level < 1 || s->compression_level > 9) &&
			s->compression_level != Z_DEFAULT_COMPRESSION) {
			log_error_write(srv, __FILE__, __LINE__, "s", "reset compress-level to DEFAULT");
			s->compression_level = Z_DEFAULT_COMPRESSION;
		}

		if (s->maxfilesize <= 0) s->maxfilesize = 4096;
		s->maxfilesize *= 1024; /*Kbytes*/

		if (s->maxmemory <=0 ) s->maxmemory = 256;
		s->maxmemory *= 1024*1024; /* Mbytes */

#if defined(HAVE_PCRE_H)		
		if (!buffer_is_empty(s->nocompress_url)) {
			if (NULL == (s->nocompress_regex = pcre_compile(s->nocompress_url->ptr,
								      0, &errptr, &erroff, NULL))) {
				
				log_error_write(srv, __FILE__, __LINE__, "sbsd", "compiling regex for nocompress-url failed:", 
									s->nocompress_url, "pos:", erroff);
				return HANDLER_ERROR;
			}
		}
#endif
	}
	
	return HANDLER_GO_ON;
	
}

#ifdef USE_ZLIB
/*fix me later */
static int 
memdeflate_file_to_buffer_gzip(server *srv, connection *con, plugin_data *p, void *start, off_t st_size, time_t mtime)
{
	unsigned char *c;
	unsigned long crc;
	z_stream z;

	UNUSED(srv);
	UNUSED(con);

	z.zalloc = Z_NULL;
	z.zfree = Z_NULL;
	z.opaque = Z_NULL;

	if (Z_OK != deflateInit2(&z, 
				 p->conf.compression_level,
				 Z_DEFLATED, 
				 -MAX_WBITS,  /* supress zlib-header */
				 8,
				 Z_DEFAULT_STRATEGY)) {
		return -1;
	}

	z.next_in = (unsigned char *)start;
	z.avail_in = st_size;
	z.total_in = 0;

	buffer_prepare_copy(p->b, (z.avail_in * 1.1) + 12 + 18);
	/* write gzip header */
	c = (unsigned char *)p->b->ptr;
	c[0] = 0x1f;
	c[1] = 0x8b;
	c[2] = Z_DEFLATED;
	c[3] = 0; /* options */
	c[4] = (mtime >>  0) & 0xff;
	c[5] = (mtime >>  8) & 0xff;
	c[6] = (mtime >> 16) & 0xff;
	c[7] = (mtime >> 24) & 0xff;
	c[8] = 0x00; /* extra flags */
	c[9] = 0x03; /* UNIX */

	p->b->used = 10;
	z.next_out = (unsigned char *)p->b->ptr + p->b->used;
	z.avail_out = p->b->size - p->b->used - 8;
	z.total_out = 0;

	if (Z_STREAM_END != deflate(&z, Z_FINISH)) {
		deflateEnd(&z);
		return -1;
	}

	/* trailer */
	p->b->used += z.total_out;

	crc = generate_crc32c(start, st_size);
	c = (unsigned char *)p->b->ptr + p->b->used;
		
	c[0] = (crc >>  0) & 0xff;
	c[1] = (crc >>  8) & 0xff;
	c[2] = (crc >> 16) & 0xff;
	c[3] = (crc >> 24) & 0xff;
	c[4] = (z.total_in >>  0) & 0xff;
	c[5] = (z.total_in >>  8) & 0xff;
	c[6] = (z.total_in >> 16) & 0xff;
	c[7] = (z.total_in >> 24) & 0xff;
	p->b->used += 8;

	if (Z_OK != deflateEnd(&z)) {
		return -1;
	}

	return 0;
}

#endif

static int
memdeflate_file_to_buffer(server *srv, connection *con, plugin_data *p, buffer *fn, stat_cache_entry *sce)
{
	int ifd;
	int ret = -1;
	void *start;

	/* overflow */
	if ((off_t)(sce->st.st_size * 1.1) < sce->st.st_size) return -1;

	/* don't mmap files > 128M
	 * we could use a sliding window, but currently there is no need for it
	 */

	if (sce->st.st_size > 128 * 1024 * 1024) return -1;
	if (-1 == (ifd = open(fn->ptr, O_RDONLY | O_BINARY))) {
		log_error_write(srv, __FILE__, __LINE__, "sbss", "opening plain-file", fn, "failed", strerror(errno));
		return -1;
	}

	start = mmap(NULL, sce->st.st_size, PROT_READ, MAP_SHARED, ifd, 0);
	close(ifd);

	if (MAP_FAILED == start) {
		log_error_write(srv, __FILE__, __LINE__, "sbss", "mmaping", fn, "failed", strerror(errno));
		return -1;
	}
#ifdef USE_ZLIB
	ret = memdeflate_file_to_buffer_gzip(srv, con, p, start, sce->st.st_size, sce->st.st_mtime);
#endif
	munmap(start, sce->st.st_size);
	if (ret != 0) return -1;
	return 0;
}

#ifndef PATCH_OPTION
#define PATCH_OPTION(x) \
		p->conf.x = s->x
#endif

static int
mod_mem_compress_patch_connection(server *srv, connection *con, plugin_data *p)
{
	size_t i, j;
	plugin_config *s = p->config_storage[0];

	PATCH_OPTION(compress);
	PATCH_OPTION(enable);
	PATCH_OPTION(maxfilesize);
	PATCH_OPTION(lru_remove_count);
	PATCH_OPTION(maxmemory);
	PATCH_OPTION(compression_level);
#if defined(HAVE_PCRE_H)
	PATCH_OPTION(nocompress_regex);
#endif	
	
	/* skip the first, the global context */
	for (i = 1; i < srv->config_context->used; i++) {
		data_config *dc = (data_config *)srv->config_context->data[i];
		s = p->config_storage[i];
		
		/* condition didn't match */
		if (!config_check_cond(srv, con, dc)) continue;
		
		/* merge config */
		for (j = 0; j < dc->value->used; j++) {
			data_unset *du = dc->value->data[j];
			
			if (buffer_is_equal_string(du->key, CONST_STR_LEN(CONFIG_MEM_COMPRESS_FILE_TYPES))) {
				PATCH_OPTION(compress);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN(CONFIG_MEM_COMPRESS_ENABLE))) {
				PATCH_OPTION(enable);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN(CONFIG_MEM_COMPRESS_COMPRESSION_LEVEL))) {
				PATCH_OPTION(compression_level);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN(CONFIG_MEM_COMPRESS_MAX_MEMORY))) {
				PATCH_OPTION(maxmemory);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN(CONFIG_MEM_COMPRESS_LRU_REMOVE_COUNT))) {
				PATCH_OPTION(lru_remove_count);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN(CONFIG_MEM_COMPRESS_NOCOMPRESS_URL))) {
#if defined(HAVE_PCRE_H)
				PATCH_OPTION(nocompress_regex);
#endif
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN(CONFIG_MEM_COMPRESS_MAX_FILE_SIZE))) {
				PATCH_OPTION(maxfilesize);
			}
		}
	}
	
	return 0;
}

static void
free_all_cache_entry(server *srv)
{
	int j;
	
	UNUSED(srv);
	for (j = 0; j<=MEM_CACHE_NUM; j++) {
		free_gzip_cache_chain(memcache+j);
	}

	memset(memcache, 0, sizeof(struct gzip_cache)*(MEM_CACHE_NUM+1));
	lruheader = lruend = cachenumber = usedmemory = 0;
#ifdef LIGHTTPD_V14
	status_counter_set(srv, CONST_STR_LEN(MEMCOMPRESS_USED), usedmemory >> 10);
	status_counter_set(srv, CONST_STR_LEN(MEMCOMPRESS_ITEMS), cachenumber);
	log_error_write(srv, __FILE__, __LINE__, "s", "free all memcompress cache data due to data inconsistence");
#else
	COUNTER_SET(memcompress_used, usedmemory >> 10);
	COUNTER_SET(memcompress_items, cachenumber);
	TRACE("%s", "free all memcompress cache data due to data inconsistence");
#endif
}

static void
free_gzip_cache_by_lru(server *srv, const int num)
{
	int i, d1;

	if (lruheader == 0 || lruend == 0) return;
	d1 = lruheader;
	for(i = 0; i < num; i++, d1=lruheader) {
		lruheader = memcache[d1].next;
		if (memcache[d1].inuse) {
			memcache[d1].next = memcache[d1].prev = 0;
			free_gzip_cache_chain(memcache+d1);
			memcache[d1].inuse = 0;
			memset(memcache+d1, 0, sizeof(struct gzip_cache));
		} else { /* wrong lru data */
			free_all_cache_entry(srv);
			break;
		}
		if (lruheader == 0) { lruheader = lruend = cachenumber = usedmemory = 0; break; }
	}

#ifdef LIGHTTPD_V14
	status_counter_set(srv, CONST_STR_LEN(MEMCOMPRESS_USED), usedmemory >> 10);
	status_counter_set(srv, CONST_STR_LEN(MEMCOMPRESS_ITEMS), cachenumber);
#else
	COUNTER_SET(memcompress_used, usedmemory >> 10);
	COUNTER_SET(memcompress_items, cachenumber);
#endif
}

static void
update_memcompress_lru(server *srv, int i)
{
	int d1, d2;

	if (i == 0 || memcache[i].inuse == 0) return;
	if (lruheader == 0 || lruend == 0) { 
		/* first item */
		memcache[i].prev = memcache[i].next = 0;
		lruheader = lruend = i;
       	} else if (i != lruend && i != lruheader){ 
		/* re-order lru */
		d1 = memcache[i].prev;
		d2 = memcache[i].next;
		if (d1 == 0 && d2 == 0) { /* new item */
			memcache[i].prev = lruend;
			memcache[i].next = 0;
			memcache[lruend].next = i;
			lruend = i;
		} else if (d1 == 0 || d2 == 0) {
			/* wrong lru list, free all cached data and reset lru*/
			free_all_cache_entry(srv);
		} else {
			/* link prev->next */
			memcache[d1].next = d2;
			memcache[d2].prev = d1;
			/* append to end of lru */
			memcache[lruend].next = i;
			memcache[i].next = 0;
			memcache[i].prev = lruend;
			lruend = i;
		}
	} else if (i == lruend) { 
		/* end of lru, no change */
	} else if (i == lruheader) { 
		/* move header to the end*/
		lruheader = memcache[i].next;
		memcache[lruheader].prev = 0;
		memcache[i].prev = lruend;
		memcache[i].next = 0;
		memcache[lruend].next = i;
		lruend = i;
	}
}

/* get new cache */
static struct gzip_cache *
check_memcompress_cache_entry(connection *con, const unsigned int i) {
	struct gzip_cache *c1, *c2;
	int status = 0;

	c1 = memcache+i;
	
	/* try to find matched item first */
	while(c1) {
		if (c1->inuse && c1->path && buffer_is_equal(c1->path, con->physical.path)) {
			status = 1;
			break;
		}
		c1 = c1->scnext;
	}
	if (status) return c1;

	/* no matched item, try to get first unused item */
	c1 = c2 = memcache + i;
	while (c1 && c1->inuse) {
		c2 = c1;
		c1 = c1->scnext;
	}
	if (c1) return c1;

	/* we need allocate new cache_entry */
	c1 = (struct gzip_cache *)calloc(1, sizeof(struct gzip_cache));
	/* put new cache_entry into hash table chain*/
	c2->scnext = c1;
	return c1;
}

handler_t
mod_mem_compress_uri_handler(server *srv, connection *con, void *p_d)
{
	plugin_data *p = p_d;
	size_t m, i;
	stat_cache_entry *sce = NULL;
	int compression_type = 0, success=0;
	unsigned int hash;
	struct gzip_cache *cache = NULL;
#if defined(HAVE_PCRE_H)
	int n;
#define N 10
	int ovec[N * 3];
#endif
	
	/* only GET and POST can get compressed */
	if (con->request.http_method != HTTP_METHOD_GET && 
	    con->request.http_method != HTTP_METHOD_POST) {
		return HANDLER_GO_ON;
	}

	if (con->physical.path->used == 0) return HANDLER_GO_ON;

	/* someone else has handled this request */
	if (con->mode != DIRECT) return HANDLER_GO_ON;
#ifdef LIGHTTPD_V14
	if (con->file_finished)
		return HANDLER_GO_ON;
#else
	if (con->send->is_closed)
		return HANDLER_GO_ON;
#endif

	/* don't compress Range request */
	if (con->conf.range_requests && NULL != array_get_element(con->request.headers, ("Range")))
		return HANDLER_GO_ON;
	
	mod_mem_compress_patch_connection(srv, con, p);
	
	if (p->conf.enable == 0) return HANDLER_GO_ON;

#if defined(HAVE_PCRE_H)
	if(p->conf.nocompress_regex) { /*check no compress regex now */
		if ((n = pcre_exec(p->conf.nocompress_regex, NULL, con->uri.path->ptr, con->uri.path->used - 1, 0, 0, ovec, 3 * N)) < 0) {
			if (n != PCRE_ERROR_NOMATCH) {
				log_error_write(srv, __FILE__, __LINE__, "sd", "execution error while matching:", n);
				return HANDLER_ERROR;
			}
		} else {
			return HANDLER_GO_ON;
		}
	}
#endif
	if (HANDLER_ERROR == stat_cache_get_entry(srv, con, con->physical.path, &sce))
		return HANDLER_GO_ON;

	if (sce->st.st_size > p->conf.maxfilesize) return HANDLER_GO_ON;
 	if (sce->st.st_size < 128) return HANDLER_GO_ON;
		
	if (con->conf.log_request_handling)
 		log_error_write(srv, __FILE__, __LINE__, "s", "-- mod_mem_compress_uri_handler called");

	/* check if mimetype is in compress-config */
	for (m = 0; m < p->conf.compress->used; m++) {
		data_string *compress_ds = (data_string *)p->conf.compress->data[m];
		
		if (sce->content_type->used
			&& (strncmp(compress_ds->value->ptr, sce->content_type->ptr, compress_ds->value->used-1) == 0)) {
			/* mimetype found */
			data_string *ds;

			if (NULL != (ds = (data_string *)array_get_element(con->request.headers, ("Accept-Encoding")))) {
				int accept_encoding = 0;
				int srv_encodings = 0;
				int matched_encodings = 0;
				
				/* get client side support encodings */
				if (NULL != strstr(ds->value->ptr, "gzip")) accept_encoding |= HTTP_ACCEPT_ENCODING_GZIP;
				if (NULL != strstr(ds->value->ptr, "deflate")) accept_encoding |= HTTP_ACCEPT_ENCODING_DEFLATE;
				
				/* get server side supported ones */
#ifdef USE_ZLIB
				srv_encodings |= HTTP_ACCEPT_ENCODING_GZIP;
				srv_encodings |= HTTP_ACCEPT_ENCODING_DEFLATE;
#endif
				
				/* find matching entries */
				matched_encodings = accept_encoding & srv_encodings;
				/* select best matching encoding */
				if (matched_encodings & HTTP_ACCEPT_ENCODING_GZIP) {
					compression_type = HTTP_ACCEPT_ENCODING_GZIP;
				} else if (matched_encodings & HTTP_ACCEPT_ENCODING_DEFLATE) {
					compression_type = HTTP_ACCEPT_ENCODING_DEFLATE;
				}
				break;
			}
		}
	}

	if (compression_type) {
		/* extension matched */
		buffer *mtime = strftime_cache_get(srv, sce->st.st_mtime);
 		etag_mutate(con->physical.etag, sce->etag); 
		response_header_overwrite(srv, con, CONST_STR_LEN("Last-Modified"), CONST_BUF_LEN(mtime));
		response_header_overwrite(srv, con, CONST_STR_LEN("ETag"), CONST_BUF_LEN(con->physical.etag));

		/* perhaps we don't even have to compress the file as the browser still has the current version */
       	if (HANDLER_FINISHED == http_response_handle_cachable(srv, con, mtime, con->physical.etag))
	       	return HANDLER_FINISHED;

		/* check cache in memory */
		hash = hashme(con->physical.path);
		/* don't forget to plus 1 */
		i = (hash & MEM_HASH_MASK) + 1;
		cache = check_memcompress_cache_entry(con, i);
		reqcount ++;
		if (cache == NULL) /* not enough memory */
			return HANDLER_GO_ON;

		if (cache->inuse && (cache->last_modified == sce->st.st_mtime) && cache->content && (cache->content->used > 1)) {
			/* CACHE FOUND */
			success = 1;
			reqhit ++;
			response_header_overwrite(srv, con, CONST_STR_LEN("X-Cache"), CONST_STR_LEN("BY MEMCOMPRESS"));
		} else {
			/* gzip it to memory */
			if (0 == memdeflate_file_to_buffer(srv, con, p, con->physical.path, sce)) {
				if (cache->inuse == 0) cachenumber ++;
				/* free old cache data first */
				init_gzip_cache(cache);
				usedmemory -= cache->content->size;
				buffer_copy_string_buffer(cache->content, p->b);
				usedmemory += cache->content->size;
				cache->content->ref_count = 1; /* setup shared flag */
				buffer_append_memory(cache->content, &nulltrailer, 1); // append null trail '0'
				success = 1;
				cache->inuse = 1;
				cache->last_modified = sce->st.st_mtime;
				buffer_copy_string_buffer(cache->path, con->physical.path);
				response_header_overwrite(srv, con, CONST_STR_LEN("X-Cache"), CONST_STR_LEN("TO MEMCOMPRESS"));
			} else {
				log_error_write(srv, __FILE__, __LINE__, "sd", "fail to compress file into memory for hash:", hash);
				return HANDLER_GO_ON;
			}
		}

		if (success == 1 && cache->inuse) {
			if (HTTP_ACCEPT_ENCODING_GZIP == compression_type) {
				/* use share buffer for gziped response */
#ifdef LIGHTTPD_V14
				chunkqueue_append_shared_buffer(con->write_queue, cache->content); // use shared buffer
#else
				chunkqueue_append_shared_buffer(con->send, cache->content); // use shared buffer
#endif
				response_header_overwrite(srv, con, CONST_STR_LEN("Content-Encoding"), CONST_STR_LEN("gzip"));

			} else if (HTTP_ACCEPT_ENCODING_DEFLATE == compression_type) {
				buffer *b = NULL;
				/* don't use share buffer for defalted response */
#ifdef LIGHTTPD_V14
				b = chunkqueue_get_append_buffer(con->write_queue);
#else
				b = chunkqueue_get_append_buffer(con->send);
#endif
				buffer_append_memory(b, cache->content->ptr+10, cache->content->used - 18);
				buffer_append_memory(b, &nulltrailer, 1);
				response_header_overwrite(srv, con, CONST_STR_LEN("Content-Encoding"), CONST_STR_LEN("deflate"));
			}

			buffer_reset(con->physical.path);
			update_memcompress_lru(srv, i);

			response_header_overwrite(srv, con, CONST_STR_LEN("Content-Type"), CONST_BUF_LEN(sce->content_type));
			response_header_insert(srv, con, CONST_STR_LEN("Vary"), CONST_STR_LEN("Accept-Encoding"));

#ifdef LIGHTTPD_V14
			status_counter_set(srv, CONST_STR_LEN(MEMCOMPRESS_HITRATE), ((float)reqhit/(float)reqcount)*100);
			status_counter_set(srv, CONST_STR_LEN(MEMCOMPRESS_USED), usedmemory >> 10);
			status_counter_set(srv, CONST_STR_LEN(MEMCOMPRESS_ITEMS), cachenumber);
			con->file_finished = 1;
#else
			COUNTER_SET(memcompress_hitrate, ((float)reqhit/(float)reqcount)*100);
			COUNTER_SET(memcompress_used, usedmemory >> 10);
			COUNTER_SET(memcompress_items, cachenumber);
			con->send->is_closed = 1;
#endif
			buffer_reset(p->b);

			if (usedmemory > p->conf.maxmemory) /* free least used compressed items */
				free_gzip_cache_by_lru(srv, p->conf.lru_remove_count);

			return HANDLER_FINISHED;
		}
	}
	
	return HANDLER_GO_ON;
}

int
mod_mem_compress_plugin_init(plugin *p)
{
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = buffer_init_string("mem_compress");
	
	p->init        = mod_mem_compress_init;
	p->set_defaults = mod_mem_compress_setdefaults;
	p->handle_physical  = mod_mem_compress_uri_handler;
	p->cleanup     = mod_mem_compress_free;
	
	p->data        = NULL;
	
	return 0;
}
