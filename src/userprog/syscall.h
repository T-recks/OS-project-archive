#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init(void);
void handle_exit(int status);
void handle_sys_pthread_exit(void);
void release_all_locks(void);

#endif /* userprog/syscall.h */
