#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

struct inode;
struct dir;
struct dir_entry;

void syscall_init(void);
void handle_exit(int status);

#endif /* userprog/syscall.h */
