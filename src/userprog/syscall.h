#include "threads/interrupt.h"
#include <syscall-nr.h>

#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init(void);
void handle_exit(int status);

typedef struct handler {
    void (*fn)(struct intr_frame*, unsigned*);
    int arity;
} handler_t;

/* handler_t makeHandler(void (*)(struct intr_frame*, unsigned*), int); */

handler_t makeHandler(void (*fn)(struct intr_frame*, unsigned*), int arity) {
    handler_t h = {fn, arity};
    return h;
}

handler_t handler_table[SYS_LAST - SYS_FIRST + 1];

#define HREGISTER(sys_code, name, arity) handler_table[sys_code] = makeHandler(name, arity);

#define DEFINE_HANDLER(name) void name(struct intr_frame* f, unsigned* argv)

#endif /* userprog/syscall.h */
