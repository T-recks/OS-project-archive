#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "devices/shutdown.h"
#include "threads/synch.h"
#include "filesys/file.h"
#include <string.h>
#include "filesys/filesys.h"

static void syscall_handler(struct intr_frame*);

struct lock filesys_lock;

void syscall_init(void) {
  lock_init(&filesys_lock);
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static int handle_practice(int val) { return val + 1; }

void handle_exit(int status) {
  struct process* pcb = thread_current()->pcb;
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
  struct list_elem* e;
  struct wait_status* w;
  for (e = list_begin(pcb->waits); e != list_end(pcb->waits); e = list_next(e)) {
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

static int handle_exec(const char* cmd_line) {

  // Initialize the share wait status struct
  struct wait_status* ws = (struct wait_status*)malloc(sizeof(struct wait_status));
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
    struct list_elem* e = (struct list_elem*)malloc(sizeof(struct list_elem));
    ws->elem = *e;
    ws->loaded = true;
    ws->pid = pid;
    list_push_back(thread_current()->pcb->waits, &ws->elem);

    return pid;
  }
}

static int handle_open(char* filename) {
  struct list* fd_table = thread_current()->pcb->open_files;
  lock_acquire(&filesys_lock);
  // check the fd table to see if file already open
   struct list_elem* e;
  for (e = list_begin(fd_table); e != list_end(fd_table); e = list_next(e)) {
    struct file_data* f = list_entry(e, struct file_data, elem);

    if (strcmp(f->filename, filename) == 0) {
      // incrmt ref_cnt and return the fd
      f->ref_cnt++;
      lock_release(&filesys_lock);
      return f->fd;
    }
  }

  // call filesys_open, if get NULL then handle failed open
  struct file* new_file = filesys_open(filename);
  if (new_file == NULL) {
    lock_release(&filesys_lock);
    return -1;
  }

  // create a new fd table entry
  struct file_data* fd_entry = (struct file_data*)malloc(sizeof(struct file_data));
  fd_entry->file = new_file;
  fd_entry->filename = filename;
  fd_entry->ref_cnt = 1;
  if (!list_empty(fd_table)) {
    struct list_elem* e = list_back(fd_table);
    struct file_data* f = list_entry(e, struct file_data, elem);
    fd_entry->fd = f->fd + 1;
  } else {
    fd_entry->fd = 3;
  }
  list_push_back(fd_table, &fd_entry->elem);
  return fd_entry->fd;
  lock_release(&filesys_lock);
}

static bool handle_close(const int fd) {
  struct list* fd_table = thread_current()->pcb->open_files;
  lock_acquire(&filesys_lock);
  // check the fd table for the given fd, return false if not present
  struct list_elem* e;
  for (e = list_begin(fd_table); e != list_end(fd_table); e = list_next(e)) {
    struct file_data* f = list_entry(e, struct file_data, elem);
    if (f->fd == fd) {
      //close file & decrement ref_cnt in fd table
      file_close(f->file);
      f->ref_cnt--;
      if (f->ref_cnt == 0) {
        // if ref_cnt is 0, remove from table and free the file_data struct
        list_remove(e);
        free(f);
      }
  lock_release(&filesys_lock);
      return true;
    }
  }
  lock_release(&filesys_lock);
  return false;
}

static int handle_filesize(int fd) {
  struct list* fd_table = thread_current()->pcb->open_files;
  lock_acquire(&filesys_lock);
  // check the fd table for the given fd, return false if not present
  struct file_data *f = find_file(fd, fd_table);
  if (f != NULL) {
    int length = file_length(f->file);
    lock_release(&filesys_lock);
    return length;
  }
  lock_release(&filesys_lock);
  return -1;
}

static int handle_read(int fd, void* buffer, unsigned size) {
  struct list* fd_table = thread_current()->pcb->open_files;
  lock_acquire(&filesys_lock);
  // check the fd table for the given fd, return false if not present
  struct file_data *f = find_file(fd, fd_table);
  if (f != NULL) {
    int result = file_read(f->file, buffer, size);
    lock_release(&filesys_lock);
    return result;
  }
  lock_release(&filesys_lock);
  return -1;
}

static int handle_wait(pid_t pid) {
  int status = process_wait(pid);
  return status;
}

static bool handle_create(char* file, unsigned size) {
  lock_acquire(&filesys_lock);
  bool success = filesys_create(file, size);
  lock_release(&filesys_lock);
  return success;
}

static int handle_write(uint32_t* args) {
  unsigned size = (unsigned)args[3];
  char* buf = (char*)args[2];
  int fd = (int)args[1];
  lock_acquire(&filesys_lock);
  if (fd == 1) {
    putbuf(buf, size);
    return size;
  } else {
      struct list* fd_table = thread_current()->pcb->open_files;
      struct file_data *f = find_file(fd, fd_table);
      if (f != NULL) {
        int result = file_write(f->file, buf, size);
        lock_release(&filesys_lock);
        return result;
      }
      lock_release(&filesys_lock);
      return -1;
  }
}

static void handle_seek(int fd, unsigned position) {
  lock_acquire(&filesys_lock);
  struct list* fd_table = thread_current()->pcb->open_files;
  struct file_data *f = find_file(fd, fd_table);
  if (f != NULL) {
    file_seek(f->file, position);
  }
  lock_release(&filesys_lock);
}

static unsigned handle_tell(int fd) {
  lock_acquire(&filesys_lock);
  struct list* fd_table = thread_current()->pcb->open_files;
  struct file_data *f = find_file(fd, fd_table);
  if (f != NULL) {
    int position = file_tell(f->file, position);
    lock_release(&filesys_lock);
    return position;
  }
  lock_release(&filesys_lock);
  return -1;
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
  int i = 1;
  
  if (args[0] == SYS_EXEC) {
    // Argument is a pointer, make sure it's valid
    if (args[1] == NULL || pagedir_get_page(active_pd(), (void*)args[1]) == NULL) {
      f->eax = -1;
      handle_exit(-1);
    }
  }
  
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
    // For checking if the pointer is to invalid memory, add 1 byte to the
    // address to account for the case some bytes of the address are
    // valid but the others are not (address lies on a page boundary).
    if (is_kernel_vaddr((void*)(&args[i] + 1))) {
      // Referencing kernel memory.
      break;
    }
    if (pagedir_get_page(active_pd(), (void*)(&args[i] + 1)) == NULL) {
      // Referencing memory not in the page directory
      break;
    }
  }
  if (i != n + 1) {
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
  
  // Case where the stack is too large and all bytes of the esp are in invalid memory
  if (f->ebp - (uint32_t)f->esp > 4096 && pagedir_get_page(active_pd(), (void*)(f->esp)) == NULL) {
    handle_exit(-1);
  }

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
      f->eax = handle_create((char*)args[1], (unsigned)args[2]);
      break;
    case SYS_REMOVE:
      validate_args(f, args, 1);
      break;
    case SYS_OPEN:
      validate_args(f, args, 1);
      f->eax = handle_open((char*)args[1]);
      break;
    case SYS_FILESIZE:
      validate_args(f, args, 1);
      f->eax = handle_filesize((int)args[1]);
      break;
    case SYS_READ:
      validate_args(f, args, 3);
      f->eax = handle_read((int)args[1], (void*)args[2], (unsigned)args[3]);
      break;
    case SYS_WRITE:
      validate_args(f, args, 3);
      f->eax = handle_write(args);
      break;
    case SYS_SEEK:
      validate_args(f, args, 2);
      handle_seek((int)args[1], (unsigned)args[2]);
      break;
    case SYS_TELL:
      validate_args(f, args, 1);
      f->eax = handle_tell((int)args[1]);
      break;
    case SYS_CLOSE:
      validate_args(f, args, 1);
      handle_close((int)args[1]);
      break;
  }
}
