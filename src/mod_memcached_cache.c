/* 
Copyright (c) 2006, 2008 QUE Hongyu

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

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>

#include "base.h"
#include "log.h"
#include "buffer.h"

#include "plugin.h"

#include "stat_cache.h"
#include "etag.h"
#include "response.h"
#include "status_counter.h"

#include <memcache.h>

#define LIGHTTPD_V14 1

#ifdef LIGHTTPD_V14
#include "splaytree.h"
#endif

#define CONFIG_MEMCACHED_CACHE_ENABLE "memcached-cache.enable"
#define CONFIG_MEMCACHED_CACHE_MAX_MEM "memcached-cache.max-memory"
#define CONFIG_MEMCACHED_CACHE_MAX_FILE_SIZE "memcached-cache.max-file-size"
#define CONFIG_MEMCACHED_CACHE_LRU_REMOVE_COUNT "memcached-cache.lru-remove-count"
#define CONFIG_MEMCACHED_CACHE_EXPIRE_TIME "memcached-cache.expire-time"
#define CONFIG_MEMCACHED_CACHE_FILE_TYPES "memcached-cache.filetypes"
#define CONFIG_MEMCACHED_CACHE_SLRU_THRESOLD "memcached-cache.slru-thresold"
#define CONFIG_MEMCACHED_CACHE_HOSTS "memcached-cache.memcache-hosts"
#define CONFIG_MEMCACHED_CACHE_NAMESPACE "memcached-cache.memcache-namespace"

#define MEMCACHED_CACHE_USED_MB "memcached-cache.used-memory(MB)"
#define MEMCACHED_CACHE_USED "memcached-cache.usedmemory"
#define MEMCACHED_CACHE_ITEMS "memcached-cache.cached-items"
#define MEMCACHED_CACHE_NUMBER "memcached-cache.cachenumber"
#define MEMCACHED_CACHE_HITRATE "memcached-cache.hitrate(%)"
#define MEMCACHED_CACHE_HITPERCENT "memcached-cache.hitpercent"

typedef struct {
	/* number of cache items removed by lru when memory is full */
	unsigned short lru_remove_count;
	unsigned short enable;
	short thresold;
	uint64_t maxmemory; /* maxium total used memory in MB */
	int32_t maxmemory_2;
	uint32_t maxfilesize; /* maxium file size will put into memory */
	unsigned int expires;
	array  *filetypes;

	struct memcache *mc;
	array  *mc_hosts;
	buffer *mc_namespace;
} plugin_config;

#define MEMCACHED_SIZE 65536 /* 2^16 */
#define MEMCACHE_MASK (MEMCACHED_SIZE-1)
#define LRUDEBUG 0

static int lruheader, lruend;
static uint64_t reqcount, reqhit;
static uint32_t cachenumber;
static unsigned int cachefile = 0;

#ifdef LIGHTTPD_V15
typedef struct tree_node {
    struct tree_node * left, * right;
    int key;
    int size;   /* maintained to be the number of nodes rooted here */

    void *data;
} splay_tree;

#define splaytree_size(x) (((x)==NULL) ? 0 : ((x)->size))

#endif
/* This macro returns the size of a node.  Unlike "x->size",     */
/* it works even if x=NULL.  The test could be avoided by using  */
/* a special version of NULL which was a real node with size 0.  */

/* use hash idea as danga's memcached */
struct cache_entry{
	short inuse;
	/* cache data */
	buffer *content_name;
	struct memcache *mc;
	off_t size;

	/* pointer for next when hash collided */
	struct cache_entry *scnext;

	/* lru info */
	unsigned int prev;
	unsigned int next;

	/* cache store time */
	time_t ct;
	/* file name */
	buffer *path;
	/* buffer to print at Last-Modified: header */
	buffer *mtime;
	/* content-type */
	buffer *content_type;
	/* etag */
	buffer *etag;

	unsigned int hash;
}; 

static struct cache_entry *memcache;

static uint64_t usedmemory = 0; /* to support > 4G memory */

/* probation lru splaytree */
splay_tree *plru;
/* structure to store probation lru info */
struct probation {
	time_t startts;
	int count;
};

typedef struct {
	PLUGIN_DATA;
	
	plugin_config **config_storage;
	
	plugin_config conf; 
} plugin_data;

/* init cache_entry table */
static struct cache_entry *global_cache_entry_init(void) {
	struct cache_entry *c;
	c = (struct cache_entry *) calloc(MEMCACHED_SIZE+1, sizeof(struct cache_entry));
	return c;
}

/* free cache_entry */
static void free_cache_entry(struct cache_entry *cache) {
	if (cache == NULL) return;
	cachenumber --;
	if (usedmemory >= cache->size)
		usedmemory -= cache->size;
	else
		usedmemory = 0;
	if (!buffer_is_empty(cache->content_name))
		mc_delete(cache->mc, cache->content_name->ptr, cache->content_name->used, 0);
	buffer_free(cache->content_name);
	buffer_free(cache->content_type);
	buffer_free(cache->etag);
	buffer_free(cache->path);
	buffer_free(cache->mtime);
	cache->mtime = cache->etag = cache->path = cache->content_type = cache->content_name = NULL;
}

/* reset cache_entry to initial state */
static void init_cache_entry(struct cache_entry *cache, struct memcache *mc, buffer *namespace) {
	if (cache == NULL) return;
	if (cache->content_name == NULL) {
		char tmp[10];
		cache->content_name = buffer_init_buffer(namespace);
		sprintf(tmp, "_%08X", cachefile++);
		buffer_append_string(cache->content_name, tmp);
		mc_delete(mc, cache->content_name->ptr, cache->content_name->used, 0);
	} else {
		cachenumber --;
		usedmemory -= cache->size;
		cache->size = 0;
		cache->inuse = 0;
		mc_delete(mc, cache->content_name->ptr, cache->content_name->used, 0);
	}
	if (cache->content_type == NULL) cache->content_type = buffer_init();
	if (cache->etag == NULL) cache->etag = buffer_init();
	if (cache->path == NULL) cache->path = buffer_init();
	if (cache->mtime == NULL) cache->mtime = buffer_init();
	cache->mc = mc;
}

/* init the plugin data */
INIT_FUNC(mod_memcached_cache_init) {
	plugin_data *p;
	
#ifdef LIGHTTPD_V15
	UNUSED(srv);
#endif
	p = calloc(1, sizeof(*p));
	memcache = global_cache_entry_init();
	lruheader = lruend = cachenumber = 0;
	reqcount = reqhit = 0;
	usedmemory = 0;
	plru = NULL;
	
	return p;
}

void free_cache_entry_chain(struct cache_entry *p) {
	struct cache_entry *c1, *c2;

	c1 = p;
	while(c1) {
		c2 = c1->scnext;
		free_cache_entry(c1);
		if (c1 != p) free(c1);
		c1 = c2;
	}

}

/* detroy the plugin data */
FREE_FUNC(mod_memcached_cache_free) {
	plugin_data *p = p_d;
	size_t i;
	
	UNUSED(srv);

	if (!p) return HANDLER_GO_ON;
	
	for (i = 0; i<= MEMCACHED_SIZE; i++) {
		free_cache_entry_chain(memcache+i);
	}

	if (p->config_storage) {
		for (i = 0; i < srv->config_context->used; i++) {
			plugin_config *s = p->config_storage[i];
			
			if (!s) continue;
			array_free(s->filetypes);
			buffer_free(s->mc_namespace);
			array_free(s->mc_hosts);
			if (s->mc) mc_free(s->mc);
			free(s);
		}
		free(p->config_storage);
	}
	
	free(p);
	free(memcache);

	while(plru) {
		free(plru->data);
		plru = splaytree_delete(plru, plru->key);
	}

	return HANDLER_GO_ON;
}

/* handle plugin config and check values */

SETDEFAULTS_FUNC(mod_memcached_cache_set_defaults) {
	plugin_data *p = p_d;
	size_t i = 0;
	
	config_values_t cv[] = { 
		{ CONFIG_MEMCACHED_CACHE_MAX_MEM, NULL, T_CONFIG_SHORT, T_CONFIG_SCOPE_CONNECTION },       /* 0 */
		{ CONFIG_MEMCACHED_CACHE_MAX_FILE_SIZE, NULL, T_CONFIG_SHORT, T_CONFIG_SCOPE_CONNECTION },       /* 1 */
		{ CONFIG_MEMCACHED_CACHE_LRU_REMOVE_COUNT, NULL, T_CONFIG_SHORT, T_CONFIG_SCOPE_CONNECTION },       /* 2 */
		{ CONFIG_MEMCACHED_CACHE_ENABLE, NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION },       /* 3 */
		{ CONFIG_MEMCACHED_CACHE_EXPIRE_TIME, NULL, T_CONFIG_SHORT, T_CONFIG_SCOPE_CONNECTION },       /* 4 */
		{ CONFIG_MEMCACHED_CACHE_FILE_TYPES, NULL, T_CONFIG_ARRAY, T_CONFIG_SCOPE_CONNECTION },       /* 5 */
		{ CONFIG_MEMCACHED_CACHE_SLRU_THRESOLD, NULL, T_CONFIG_SHORT, T_CONFIG_SCOPE_CONNECTION },       /* 6 */
		{ CONFIG_MEMCACHED_CACHE_HOSTS,  NULL, T_CONFIG_ARRAY, T_CONFIG_SCOPE_CONNECTION },        /* 7 */
		{ CONFIG_MEMCACHED_CACHE_NAMESPACE, NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },    /* 8 */
		{ NULL,                         NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
	};
	
	if (!p) return HANDLER_ERROR;
	
	p->config_storage = calloc(1, srv->config_context->used * sizeof(specific_config *));
	
	for (i = 0; i < srv->config_context->used; i++) {
		plugin_config *s;
		
		s = calloc(1, sizeof(plugin_config));
		s->maxmemory_2 = 256; /* 256M default */
		s->maxfilesize = 512; /* maxium 512k */
		s->lru_remove_count = 10; /* default 10 */
		s->enable = 1; /* default to cache content into memory */
		s->expires = 0; /* default to check stat at every request */
		s->filetypes = array_init();
		s->thresold = 0; /* 0 just like normal LRU algorithm */
		s->mc_hosts = array_init();
		s->mc_namespace = buffer_init();

		
		cv[0].destination = &(s->maxmemory_2);
		cv[1].destination = &(s->maxfilesize);
		cv[2].destination = &(s->lru_remove_count);
		cv[3].destination = &(s->enable);
		cv[4].destination = &(s->expires);
		cv[5].destination = s->filetypes;
		cv[6].destination = &(s->thresold);
		cv[7].destination = s->mc_hosts;
		cv[8].destination = s->mc_namespace;
		
		p->config_storage[i] = s;
	
		if (0 != config_insert_values_global(srv, ((data_config *)srv->config_context->data[i])->value, cv)) {
			return HANDLER_ERROR;
		}
		s->expires *= 60;

		if (s->maxfilesize <= 0) s->maxfilesize = 512; /* 512K */
		s->maxfilesize *= 1024; /* KBytes */

		if (s->maxmemory_2 <= 0) s->maxmemory_2 = 256; /* 256M */
		s->maxmemory = s->maxmemory_2;
		s->maxmemory *= 1024*1024; /* MBytes */

		if (srv->srvconf.max_worker > 0)
			s->maxmemory /= srv->srvconf.max_worker;

		if (s->mc_hosts->used) {
			size_t k;
			s->mc = mc_new();

			for (k = 0; k < s->mc_hosts->used; k++) {
				data_string *ds = (data_string *)s->mc_hosts->data[k];

				if (0 != mc_server_add4(s->mc, ds->value->ptr)) {
					log_error_write(srv, __FILE__, __LINE__, "sb",
						"connection to host failed:",
						ds->value);
					return HANDLER_ERROR;
				}
			}
		}

		if (s->thresold < 0) s->thresold = 0;
		if (s->thresold > 0)
#ifdef LIGHTTPD_V14
			status_counter_set(srv, CONST_STR_LEN("memcached-cache.slru-thresold"), s->thresold);
#else
			status_counter_set(CONST_STR_LEN("memcached-cache.slru-thresold"), s->thresold);
#endif
	}
	
	return HANDLER_GO_ON;
}

#ifndef PATCH_OPTION
#define PATCH_OPTION(x) \
	p->conf.x = s->x
#endif

static int mod_memcached_cache_patch_connection(server *srv, connection *con, plugin_data *p) {
	size_t i, j;
	plugin_config *s = p->config_storage[0];
	
	PATCH_OPTION(maxmemory);
	PATCH_OPTION(maxfilesize);
	PATCH_OPTION(lru_remove_count);
	PATCH_OPTION(enable);
	PATCH_OPTION(expires);
	PATCH_OPTION(filetypes);
	PATCH_OPTION(thresold);
	PATCH_OPTION(mc_namespace);
	PATCH_OPTION(mc);
	
	/* skip the first, the global context */
	for (i = 1; i < srv->config_context->used; i++) {
		data_config *dc = (data_config *)srv->config_context->data[i];
		s = p->config_storage[i];
		
		/* condition didn't match */
		if (!config_check_cond(srv, con, dc)) continue;
		
		/* merge config */
		for (j = 0; j < dc->value->used; j++) {
			data_unset *du = dc->value->data[j];
			
			if (buffer_is_equal_string(du->key, CONST_STR_LEN(CONFIG_MEMCACHED_CACHE_ENABLE))) {
				PATCH_OPTION(enable);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN(CONFIG_MEMCACHED_CACHE_MAX_FILE_SIZE))) {
				PATCH_OPTION(maxfilesize);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN(CONFIG_MEMCACHED_CACHE_MAX_MEM))) {
				PATCH_OPTION(maxmemory);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN(CONFIG_MEMCACHED_CACHE_FILE_TYPES))) {
				PATCH_OPTION(filetypes);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN(CONFIG_MEMCACHED_CACHE_EXPIRE_TIME))) {
				PATCH_OPTION(expires);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN(CONFIG_MEMCACHED_CACHE_LRU_REMOVE_COUNT))) {
				PATCH_OPTION(lru_remove_count);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN(CONFIG_MEMCACHED_CACHE_SLRU_THRESOLD))) {
				PATCH_OPTION(thresold);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN(CONFIG_MEMCACHED_CACHE_NAMESPACE))) {
				PATCH_OPTION(mc_namespace);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN(CONFIG_MEMCACHED_CACHE_HOSTS))) {
				PATCH_OPTION(mc);
				
			}
		}
	}
	
	return 0;
}

#if LRUDEBUG
static void print_static_lru(server *srv) {
	int d1;
	struct cache_entry *g, *g2;

	if (lruheader == 0 || lruend == 0) return;
	d1 = lruheader;
	TRACE("total lru number = %d, total memory used = %ld", cachenumber, (long) usedmemory);
	while(d1) {
		g = memcache + d1;
		if(g->content) 
			TRACE("list %d: data_length %d, block size %d, path %s", d1, g->content->used, g->content->size, g->path->ptr);
		else
			TRACE("list %d: path %s", d1, g->path->ptr);
		g2 = g->scnext;
		while(g2) {
			if(g2->content) 
				TRACE("chain %d: data_length %d, block size %d, path %s", d1, g2->content->used, g2->content->size, g2->path->ptr);
			else
				TRACE("chain %d: path %s", d1, g2->path->ptr);
			g2 = g2->scnext;
		}
		d1 = memcache[d1].next;
	}
}
#endif

#undef PATCH_OPTION

/* free all cache-entry and init cache_entry */
static void free_all_cache_entry(server *srv) {
	int j;

	UNUSED(srv);
	for (j = 0; j <= MEMCACHED_SIZE; j++) {
		free_cache_entry_chain(memcache+j);
	}

	memset(memcache, 0, sizeof(struct cache_entry)*(MEMCACHED_SIZE+1));
	lruheader = lruend = cachenumber = usedmemory = 0;
	log_error_write(srv, __FILE__, __LINE__, "s", "free all state_cache data due to data inconsistence");
#ifdef LIGHTTPD_V14
	status_counter_set(srv, CONST_STR_LEN(MEMCACHED_CACHE_USED), usedmemory);
	status_counter_set(srv, CONST_STR_LEN(MEMCACHED_CACHE_NUMBER), cachenumber);
#else
	status_counter_set(CONST_STR_LEN(MEMCACHED_CACHE_USED_MB), ((long)usedmemory)>>20);
	status_counter_set(CONST_STR_LEN(MEMCACHED_CACHE_ITEMS), cachenumber);
#endif
}

static void free_cache_entry_by_lru(server *srv, const int num) {
	int i, d1;

	if (lruheader == 0 || lruend == 0) return;
	d1 = lruheader;
#if LRUDEBUG
	log_error_write(srv, __FILE__, __LINE__, "sdsd",
			"memory size before lru remove:", usedmemory, "cachenumber", cachenumber);
#endif
	for(i = 0; i < num; i++, d1=lruheader) {
		lruheader = memcache[d1].next;
		if (memcache[d1].inuse) {
			memcache[d1].next = memcache[d1].prev = 0;
			free_cache_entry_chain(memcache+d1);
			memcache[d1].inuse = 0;
			memset(memcache+d1, 0, sizeof(struct cache_entry));
		} else { 
			/* wrong lru data, free them all! */
			free_all_cache_entry(srv);
			break;
		}
		if (lruheader == 0) { lruheader = lruend = cachenumber = usedmemory = 0; break; }
	}
#ifdef LIGHTTPD_V14
	status_counter_set(srv, CONST_STR_LEN(MEMCACHED_CACHE_USED), usedmemory);
	status_counter_set(srv, CONST_STR_LEN(MEMCACHED_CACHE_NUMBER), cachenumber);
#else
	status_counter_set(CONST_STR_LEN(MEMCACHED_CACHE_USED_MB), ((long)usedmemory)>>20);
	status_counter_set(CONST_STR_LEN(MEMCACHED_CACHE_ITEMS), cachenumber);
#endif
#if LRUDEBUG
	log_error_write(srv, __FILE__, __LINE__, "sdsdsds",
			"memory size:", usedmemory, "after remove:", i, "items", cachenumber, "remained");
#endif
}

/* update LRU lists */
static void update_lru(server *srv, int i) {
	int d1, d2;

	if (i == 0 || memcache[i].inuse == 0) return;
	if (lruheader == 0 || lruend == 0) { 
		/* first item */
		memcache[i].prev = memcache[i].next = 0;
		lruheader = lruend = i;
	} else if (i != lruend && i != lruheader){ 
		/* re-order lru list */
		d1 = memcache[i].prev;
		d2 = memcache[i].next;
		if (d1 == 0 && d2 == 0) { 
			/* new item */
			memcache[i].prev = lruend;
			memcache[i].next = 0;
			memcache[lruend].next = i;
			lruend = i;
		} else if (d1 == 0 || d2 == 0) {
			/* wrong lru , free all cached data and reset lru */
			free_all_cache_entry(srv);
		} else {
			memcache[d1].next = d2;
			memcache[d2].prev = d1;
			/* append to end of list */
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


/* read file content into buffer dst 
 * return 1 if failed
 */
static int readfile_into_buffer(server *srv, connection *con, int filesize, buffer *dst) {
	int ifd;
	char *files;

	UNUSED(srv);

	if (dst == NULL) return 1;
	if (dst->size <= (size_t) filesize) return 1;
	if (-1 == (ifd = open(con->physical.path->ptr, O_RDONLY | O_BINARY))) {
		log_error_write(srv, __FILE__, __LINE__, "sbss", "opening plain-file", 
				con->physical.path, "failed", strerror(errno));
		return 1;
	}

	files = mmap(NULL, filesize, PROT_READ, MAP_PRIVATE, ifd, 0);
	if (files == NULL) {
		log_error_write(srv, __FILE__, __LINE__, "sbs", "mmap", con->physical.path, "failed");
		close(ifd);
		return 1;
	}

	memcpy(dst->ptr, files, filesize);
	dst->ptr[filesize] = '\0';
	dst->used = filesize + 1;
	munmap(files, filesize);
	close(ifd); 
	return 0; 
}


/* if HIT + not expire, set status = 1 and return ptr
 * else if HIT but expired, set status = 0 and return ptr
 * else if not HIT, set status = 0 and return NULL
 */
static struct cache_entry *check_memcached(server *srv, connection *con, int *status, const unsigned int hash) {
	struct cache_entry *c;
	int success = 0, i;

	i = (hash & MEMCACHE_MASK)+1;
	c = memcache+i;
	if (status) *status = 0;
	
	while (c) {
		if (c->path && c->hash == hash && buffer_is_equal(c->path, con->physical.path)) {
			success = 1;
			break;
		}
		c = c->scnext;
	}

	if (success) {
		if (c->inuse && (srv->cur_ts <= c->ct))
			if (status) *status = 1;
		return c;
	}

	return NULL;
}

static struct cache_entry *get_memcached_cache_entry(const uint32_t hash) {
	unsigned int i;
	struct cache_entry *c1, *c2;

	i = (hash & (MEMCACHED_SIZE-1))+1;
	c1 = c2 = memcache+i;
	
	/* try to find unused item first */
	while(c1 && c1->inuse) {
		c2 = c1;
		c1 = c1->scnext;
	}
	if (c1) return c1; /* use the first unused item */
	/* we need allocate new cache_entry */
	c1 = (struct cache_entry *)calloc(1, sizeof(struct cache_entry));
	if (c1 == NULL) return NULL;
	/* put new cache_entry into hash table */
	c2->scnext = c1;
	return c1;
}

/* return 0 when probation->count > p->conf.thresold in 24 hours or p->conf.thresold == 0
 * otherwise return 1
 */
static int check_probation_lru(server *srv, plugin_data *p, int hash) {
	struct probation *pr;
	int status = 1;

	if (p->conf.thresold == 0) return 0;
	plru = splaytree_splay(plru, hash);
	if (plru == NULL || plru->key != hash) { /* first splaytree node or new node*/
		pr = (struct probation *) calloc(1, sizeof(struct probation));
		if (pr == NULL) { /* out of memory */
			return 1;
		}
		pr->count = 1;
		pr->startts = srv->cur_ts;
		plru = splaytree_insert(plru, hash, (void *) pr);
	} else { /* matched */
		pr = (struct probation *) plru->data;
		if ((srv->cur_ts - pr->startts) > 86400) {
			/* keep track of last 24 hours only */
			pr->count = 0;
			pr->startts = srv->cur_ts;
		}
		pr->count ++;
		if (pr->count > p->conf.thresold) {
			free(pr);
			plru = splaytree_delete(plru, hash);
			status = 0;
		}
	}
	return status;
}

handler_t mod_memcached_cache_uri_handler(server *srv, connection *con, void *p_d) {
	plugin_data *p = p_d;
	unsigned int hash;
	int success = 0;
	size_t m;
	stat_cache_entry *sce = NULL;
	buffer *mtime;
	data_string *ds;
	struct cache_entry *cache = NULL;
	buffer *content;
	
	/* someone else has done a decision for us */
	if (con->http_status != 0) return HANDLER_GO_ON;
	if (con->uri.path->used == 0) return HANDLER_GO_ON;
	if (con->physical.path->used == 0) return HANDLER_GO_ON;
	
	/* someone else has handled this request */
	if (con->mode != DIRECT) return HANDLER_GO_ON;
#ifdef LIGHTTPD_V14
	if (con->file_finished) return HANDLER_GO_ON;
#else
	if (con->send->is_closed) return HANDLER_GO_ON;
#endif

	/* we only handle GET, POST and HEAD */
	switch(con->request.http_method) {
	case HTTP_METHOD_GET:
	case HTTP_METHOD_POST:
	case HTTP_METHOD_HEAD:
		break;
	default:
		return HANDLER_GO_ON;
	}
	
	if (con->conf.range_requests && NULL != array_get_element(con->request.headers, ("Range")))
		/* don't handle Range request */
		return HANDLER_GO_ON;

	mod_memcached_cache_patch_connection(srv, con, p);
	
	if (p->conf.enable == 0 || p->conf.maxfilesize == 0) return HANDLER_GO_ON;

	if (con->conf.log_request_handling) {
		log_error_write(srv, __FILE__, __LINE__, "s", "-- mod_memcached_cache_uri_handler called");
	}

	hash = hashme(con->physical.path);
	cache = check_memcached(srv, con, &success, hash);
	reqcount ++;
	content = buffer_init();

	if (success != 0 && cache != NULL && p->conf.mc) {
		void *r;
		size_t retlen;
		buffer_prepare_copy(content, cache->size);
		if (NULL == (r = mc_aget2(p->conf.mc, CONST_BUF_LEN(cache->content_name), &retlen))) {
			init_cache_entry(cache, p->conf.mc, p->conf.mc_namespace);
			buffer_reset(content);
		} else {
			buffer_copy_memory(content, r, retlen);
			free(r);
		}
	}

	if (buffer_is_empty(content)) {
		/* going to put content into cache */
		if (HANDLER_ERROR == stat_cache_get_entry(srv, con, con->physical.path, &sce)) {
			goto handler_go_on;
		}
		/* we only handline regular files */
#ifdef HAVE_LSTAT
		if ((sce->is_symlink == 1) && !con->conf.follow_symlink) {
			con->http_status = 403;
			buffer_reset(con->physical.path);
			goto handler_go_on;
		}
#endif

		if (!S_ISREG(sce->st.st_mode))
			goto handler_go_on;

		/* check filetypes */
		for (m = 0; m < p->conf.filetypes->used; m++) {
			ds = (data_string *)p->conf.filetypes->data[m];
			if (!ds) goto handler_go_on;
			if (sce->content_type->used &&
			    strncmp(ds->value->ptr, sce->content_type->ptr, ds->value->used-1)==0)
				break;
		}

		if (m && m == p->conf.filetypes->used) /* not found */
			goto handler_go_on;

		if (sce->st.st_size == 0 || (sce->st.st_size > p->conf.maxfilesize))  /* don't cache big file */
			goto handler_go_on;

		if (cache == NULL) {
			/* check probation lru now */
			if (check_probation_lru(srv, p, hash))
				goto handler_go_on;

			cache = get_memcached_cache_entry(hash);
			if (cache == NULL) {
				/* may be out of memory, just return GO_ON */
				goto handler_go_on;
			}
		}

		/* add ETag */
		etag_mutate(con->physical.etag, sce->etag);

		/* 1) new allocated, cache->inused = 0 
		 * 2) previous unused, cache->inused = 0 && cache->etag != con->physical.etag
		 * 3) the items just expired, cache->inused = 0 && cache->etag == con->physical.etag
		 */
		if (cache->inuse && buffer_is_equal(con->physical.etag, cache->etag)) {
			void *r;
			size_t retlen;
			buffer_prepare_copy(content, cache->size);
			if (NULL == (r = mc_aget2(p->conf.mc, CONST_BUF_LEN(cache->content_name), &retlen))) {
				buffer_reset(content);
			} else {
				buffer_copy_memory(content, r, retlen);
				free(r);
			}
		}

		if (buffer_is_empty(content)) {

			while ((usedmemory + sce->st.st_size) > p->conf.maxmemory) {
				/* free least used items */
				free_cache_entry_by_lru(srv, p->conf.lru_remove_count); 
			}

			/* initialze cache's buffer if needed */
			init_cache_entry(cache, p->conf.mc, p->conf.mc_namespace);
			buffer_prepare_copy(content, sce->st.st_size);
			if (readfile_into_buffer(srv, con, sce->st.st_size, content)) {
				goto handler_go_on;
			}

			if (p->conf.mc)
				mc_set(p->conf.mc, CONST_BUF_LEN(cache->content_name), content->ptr, sce->st.st_size, p->conf.expires, 0);

			cache->size = sce->st.st_size;
			usedmemory += cache->size;
			/* increase cachenumber if needed */
			if (cache->inuse == 0) {
				cachenumber ++;
				cache->inuse = 1;
			}


			if (sce->content_type->used == 0) {
				buffer_copy_string_len(cache->content_type, CONST_STR_LEN("application/octet-stream"));
			} else {
				buffer_copy_string_buffer(cache->content_type, sce->content_type);
			}
			buffer_copy_string_buffer(cache->etag, con->physical.etag);
			buffer_copy_string_buffer(cache->path, con->physical.path);
			buffer_copy_string_buffer(cache->mtime, strftime_cache_get(srv, sce->st.st_mtime));
			cache->ct = srv->cur_ts + p->conf.expires;
			cache->hash = hash;
//			response_header_overwrite(srv, con, CONST_STR_LEN("X-Cache"), CONST_STR_LEN("to memcache"));
		} else  {
			cache->ct = srv->cur_ts + p->conf.expires;
			reqhit ++;
//			response_header_overwrite(srv, con, CONST_STR_LEN("X-Cache"), CONST_STR_LEN("by memcache"));
		}
	} else {
		reqhit ++;
//		response_header_overwrite(srv, con, CONST_STR_LEN("X-Cache"), CONST_STR_LEN("by memcache"));
	}

	if (NULL == array_get_element(con->response.headers, ("Content-Type"))) {
		response_header_overwrite(srv, con, CONST_STR_LEN("Content-Type"), CONST_BUF_LEN(cache->content_type));
	}
	
	if (NULL == array_get_element(con->response.headers, ("ETag"))) {
		response_header_overwrite(srv, con, CONST_STR_LEN("ETag"), CONST_BUF_LEN(cache->etag));
	}

	/* prepare header */
	if (NULL == (ds = (data_string *)array_get_element(con->response.headers, ("Last-Modified")))) {
		mtime = cache->mtime;
		response_header_overwrite(srv, con, CONST_STR_LEN("Last-Modified"), CONST_BUF_LEN(mtime));
	} else mtime = ds->value;

	if (HANDLER_FINISHED == http_response_handle_cachable(srv, con, mtime /*, cache->etag */)) {
		buffer_free(content);
		return HANDLER_FINISHED;
	}

	/* update LRU here */
	update_lru(srv, (hash & MEMCACHE_MASK)+1);

	buffer_reset(con->physical.path);
#ifdef LIGHTTPD_V14
	status_counter_set(srv, CONST_STR_LEN(MEMCACHED_CACHE_HITPERCENT), (int) (((float)reqhit/(float)reqcount)*100));
	status_counter_set(srv, CONST_STR_LEN(MEMCACHED_CACHE_USED), usedmemory);
	status_counter_set(srv, CONST_STR_LEN(MEMCACHED_CACHE_NUMBER), cachenumber);
	chunkqueue_append_buffer(con->write_queue, content);
	con->file_finished = 1;
#else
	status_counter_set(CONST_STR_LEN(MEMCACHED_CACHE_HITRATE), (int) (((float)reqhit/(float)reqcount)*100));
	status_counter_set(CONST_STR_LEN(MEMCACHED_CACHE_USED_MB), usedmemory >> 20);
	status_counter_set(CONST_STR_LEN(MEMCACHED_CACHE_ITEMS), cachenumber);
	chunkqueue_append_buffer(con->send, content);
	con->send->is_closed = 1;
#endif
	buffer_free(content);
	
	return HANDLER_FINISHED;

handler_go_on:
	buffer_free(content); // we alloc later
	return HANDLER_GO_ON;
}

/* this function is called at dlopen() time and inits the callbacks */

int mod_memcached_cache_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = buffer_init_string("memcached_cache");
	
	p->init        = mod_memcached_cache_init;
#ifdef LIGHTTPD_V14
	p->handle_subrequest_start = mod_memcached_cache_uri_handler;
#else
	p->handle_response_header = mod_mem_cache_uri_handler;
#endif
	p->set_defaults  = mod_memcached_cache_set_defaults;
	p->cleanup     = mod_memcached_cache_free;
	
	p->data        = NULL;
	
	return 0;
}
