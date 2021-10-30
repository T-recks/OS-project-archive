#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include <stdint.h>

// At most 8MB can be allocated to the stack
// These defines will be used in Project 2: Multithreading
#define MAX_STACK_PAGES (1 << 11)
#define MAX_THREADS 127

/* PIDs and TIDs are the same type. PID should be
   the TID of the main thread of the process */
typedef tid_t pid_t;

/* Thread functions (Project 2: Multithreading) */
typedef void (*pthread_fun)(void*);
typedef void (*stub_fun)(pthread_fun, void*);

/* The process control block for a given process. Since
   there can be multiple threads per process, we need a separate
   PCB from the TCB. All TCBs in a process will have a pointer
   to the PCB, and the PCB will have a pointer to the main thread
   of the process, which is `special`. */
struct process {
  /* Owned by process.c. */
  uint32_t* pagedir;          /* Page directory. */
  char process_name[16];      /* Name of the main thread */
  struct thread* main_thread; /* Pointer to main thread */
  struct list* argv;
  struct wait_status* ws;  /* Wait status struct of the parent */
  struct list* waits;      /* List of children this process' children */
  struct list* open_files; /* All files opened by this process */
};

/*
Structure the file descriptors into a list. */
struct file_data {
  struct file* file; /* File pointer */
  char* filename;
  int fd;                /* File descriptor of this file */
  int ref_cnt;           /* How many processes have this file open */
  struct list_elem elem; /* List element for all files list */
};

/* Shared between a parent and a child, one for each newly created child
 * Need 2 semaphores because wait() waits for the process to exit, while
 * exec() waits for the process to load. */
struct wait_status {
  struct semaphore sema_wait; /* Semaphore to indicate the process has exited */
  struct semaphore sema_load; /* Semaphore to indicate the process has loaded */
  struct lock lock;           /* Lock to avoid race conditions with ref_cnt */
  int ref_cnt;                /* Number of active processes; initialize to 2 */
  int exit_code;              /* Exit code of child, if applicable */
  int pid;                    /* pid of the child */
  bool loaded;                /* Child should set this to true after loading*/
  struct list_elem elem;
};

/*
Structure the words extracted from the user command into a list. */
typedef struct word {
  char* val;
  int len;
  struct list_elem elem;
} word_t;

void userprog_init(void);

pid_t process_execute(const char* file_name, struct wait_status* ws);
int process_wait(pid_t);
void process_exit(void);
void process_activate(void);

bool is_main_thread(struct thread*, struct process*);
pid_t get_pid(struct process*);

struct file_data* find_file(int fd, struct list* fd_table);
void free_process(struct process* pcb);

#endif /* userprog/process.h */
