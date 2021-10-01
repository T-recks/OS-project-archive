#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"

static void syscall_handler(struct intr_frame*);

void syscall_init(void) {
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static int handle_practice(int val) {
  return val + 1;
}

static void handle_exit(int status) {
  struct process *pcb = thread_current()->pcb;
  printf("%s: exit(%d)\n", pcb->process_name, status);
  lock_acquire(&pcb->ws->lock);
  // Store the exit code into wait_status
  pcb->ws->exit_code = status;
  // Up both semaphores so the parent can read the shared data
  sema_up(&pcb->ws->sema_wait);
  sema_up(&pcb->ws->sema_load);
  // Decrement the ref count of this wait_status
  pcb->ws->ref_cnt -= 1;
  lock_release(&pcb->ws->lock);
  if (pcb->ws->ref_cnt == 0) {
    // TODO: not thread safe
    free(pcb->ws);
  }
  // Decrement the ref count of each of the child waiters
  struct list_elem *e;
  struct wait_status *w;
  for (e = list_begin(pcb->waits); e!= list_end(pcb->waits); e = list_next(e)) {
    w = list_entry(e, struct wait_status, elem);
    lock_acquire(&w->lock);
    w->ref_cnt -= 1;
    // TODO: not thread safe
    lock_release(&w->lock);
    if (w->ref_cnt == 0) {
      // Free each one whose ref count hits 0
      free(w);
    }
  }
  process_exit();
}

static int handle_exec(const char *cmd_line) {
  
  // Initialize the share wait status struct
  struct wait_status *ws = (struct wait_status*)malloc(sizeof(struct wait_status));
  sema_init(&ws->sema_load, 0);
  sema_init(&ws->sema_wait, 0);
  lock_init(&ws->lock);
  ws->loaded = false;
  ws->ref_cnt = 2;
  
  // TODO: validate the args, should that go in process.c?
  pid_t pid = process_execute(cmd_line, ws);
  // Wait for the child process to finish loading
  sema_down(&ws->sema_load); // Child calls sema_up in start_process
  if (pid == TID_ERROR || !ws->loaded) {
    // TODO: free the wait status and the command lines arg
    return -1;
  } else {
    // Add the child to the list of active children
    struct list_elem *e = (struct list_elem*)malloc(sizeof(struct list_elem));
    ws->elem = *e;
    ws->loaded = true;
    ws->pid = pid;
    list_push_back(thread_current()->pcb->waits, &ws->elem);
    
    return pid;
  }
}

static int handle_wait(pid_t pid) {
  int status = process_wait(pid);
  return status;
}

static int handle_write(uint32_t* args) {
  unsigned size = (unsigned)args[3];
  char* buf = (char*)args[2];
  int fd = (int)args[1];
  if (fd == 1) {
    putbuf(buf, size);
    return size;
  }
  return 0;
}

/* Validate ARGS by ensuring each address points to valid memory.
 * Valid pointers are not null, reference below PHYS_BASE/are not
 * in kernel memory.
 * When exec() is called, n = -1. Validate up until the null pointer
 * is encountered, since this is the end of the argument list.
 * If any arg is invalid, kills the process with exit code -1 and frees
 * memory allocated by process_start; being the thread and page directory.
 * */
static void validate_args(struct intr_frame* f, uint32_t* args, int n) {
  // TODO: How to tell if the pointer is to a buffer
  int i = 1;
  for (; i != n+1; i++) {
    if ((void*)args[i] == NULL && args[0] != SYS_EXIT) {
      // exit(0) is a successfull exit
      if (n == -1) {
        // exec() called and null pointer found
        return;
      }
      // Null pointer
      break;
    }
    // For checking if the pointer is to invalid memory, add 3 to the
    // address to account for the case some bytes of the address are
    // valid but the others are not (address lies on a page boundary).
    if (is_kernel_vaddr((void*)(args[i]+3))) {
      // Referencing kernel memory.
      break;
    }
  }
  if (i != n+1) {
    // Invalid memory access, terminate the process
    f->eax = -1;
    handle_exit(-1);
  }
}

static void syscall_handler(struct intr_frame* f UNUSED) {
  uint32_t* args = ((uint32_t*)f->esp);

  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

//  printf("System call number: %d\n", args[0]);

  //TODO: Validate args[0]

  switch (args[0]) {
    case SYS_PRACTICE:
      validate_args(f, args, 1);
      f->eax = handle_practice(args[1]);
      break;
    case SYS_HALT:
      shutdown_power_off();
      break;
    case SYS_EXIT:
      validate_args(f, args, 1);
      f->eax = args[1];
      handle_exit(args[1]);
      break;
    case SYS_EXEC:
      validate_args(f, args, 1);
      f->eax = handle_exec((char*)args[1]);
      break;
    case SYS_WAIT:
      validate_args(f, args, 1);
      f->eax = handle_wait((pid_t)args[1]);
      break;
    case SYS_CREATE:
      validate_args(f, args, 2);
      break;
    case SYS_REMOVE:
      validate_args(f, args, 1);
      break;
    case SYS_OPEN:
      validate_args(f, args, 1);
      break;
    case SYS_FILESIZE:
      validate_args(f, args, 1);
      break;
    case SYS_READ:
      validate_args(f, args, 3);
      break;
    case SYS_WRITE:
      validate_args(f, args, 3);
      f->eax = handle_write(args);
      break;
    case SYS_SEEK:
      validate_args(f, args, 2);
      break;
    case SYS_TELL:
      validate_args(f, args, 1);
      break;
    case SYS_CLOSE:
      validate_args(f, args, 1);
      break;
  }
}