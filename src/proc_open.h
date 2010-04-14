
#include "buffer.h"

#ifdef _WIN32
#include <windows.h>
typedef HANDLE descriptor_t;
typedef HANDLE proc_pid_t;
#else
typedef int descriptor_t;
typedef pid_t proc_pid_t;
#endif

typedef struct {
	descriptor_t parent, child;
	int fd;
} pipe_t;

typedef struct {
	pipe_t in, out, err;
	proc_pid_t child;
} proc_handler_t;

LI_EXPORT int proc_close(proc_handler_t *ht);
LI_EXPORT int proc_open(proc_handler_t *ht, const char *command);
LI_EXPORT  int proc_open_buffer(const char *command, buffer *in, buffer *out, buffer *err);
