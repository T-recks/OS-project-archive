#include "threads/interrupt.h"

#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init(void);
void handle_exit(int status);

typedef struct handler {
    void (*fn)(struct intr_frame*, unsigned*);
    int arity;
} handler_t;

handler_t makeHandler(void (*)(struct intr_frame*, unsigned*), int);

#endif /* userprog/syscall.h */
