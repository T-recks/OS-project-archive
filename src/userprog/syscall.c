#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "devices/shutdown.h"
#include "lib/float.h"
#include "threads/synch.h"
#include "filesys/file.h"
#include <string.h>
#include "filesys/filesys.h"

static void syscall_handler(struct intr_frame*);
static bool handle_close(const int fd);
void close_all_files(void);
void clear_cmdline(void);
static void handle_practice(struct intr_frame*, unsigned*);
static void handle_compute_e(struct intr_frame*, unsigned*);
static void handle_write(struct intr_frame* f, unsigned* args);

struct lock filesys_lock;

handler_t handler_table[SYS_LAST - SYS_FIRST + 1];

handler_t makeHandler(void (*fn)(struct intr_frame*, unsigned*), int arity) {
    handler_t h = {fn, arity};
    return h;
}

void close_all_files(void) {
  struct list* fd_table = thread_current()->pcb->open_files;
  if (fd_table == NULL) {
    return;
  }
  lock_acquire(&filesys_lock);
  while (!list_empty(fd_table)) {
    struct list_elem *e = list_pop_front(fd_table);
    struct file_data* f = list_entry(e, struct file_data, elem);
    file_close(f->file);
    f->ref_cnt--;
    if (f->ref_cnt == 0) {
      list_remove(e);
      free(f);
    }
  }
  lock_release(&filesys_lock);
}

void clear_cmdline(void) {
  struct list* argv = thread_current()->pcb->argv;
  if (argv == NULL)
    return;
  while (!list_empty(argv)) {
    struct list_elem *e = list_pop_front(argv);
    struct word* w = list_entry(e, struct word, elem);
    list_remove(e);
    free(w);
  }
}

static void handle_practice(struct intr_frame* f, unsigned* argv) {
    f->eax = (int)argv[1] + 1;
}

void f_handle_exit(struct intr_frame* f, unsigned* argv) {
    int status = argv[1];
    f->eax = status;
    handle_exit(status);
}

void handle_exit(int status) {
  struct process *pcb = thread_current()->pcb;
  printf("%s: exit(%d)\n", pcb->process_name, status);
  if (pcb->ws == NULL) {
    goto done;
  }
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
    free(pcb->ws);
  }
  if (pcb->waits == NULL) {
    goto done;
  }
  // Decrement the ref count of each of the child waiters
  struct list_elem *e;
  struct wait_status *w;
  for (e = list_begin(pcb->waits); e!= list_end(pcb->waits); e = list_next(e)) {
    w = list_entry(e, struct wait_status, elem);
    lock_acquire(&w->lock);
    w->ref_cnt -= 1;
    lock_release(&w->lock);
    if (w->ref_cnt == 0) {
      // Free each one whose ref count hits 0
      free(w);
    }
  }
done:
  close_all_files();
  clear_cmdline();
  process_exit();
}

static void handle_exec(struct intr_frame* f, unsigned* argv) {
  // Initialize the share wait status struct
  struct wait_status *ws = (struct wait_status*)malloc(sizeof(struct wait_status));
  sema_init(&ws->sema_load, 0);
  sema_init(&ws->sema_wait, 0);
  lock_init(&ws->lock);
  ws->loaded = false;
  ws->ref_cnt = 2;

  const char *cmd_line = (char*)argv[1];
  pid_t pid = process_execute(cmd_line, ws);
  // Wait for the child process to finish loading
  sema_down(&ws->sema_load); // Child calls sema_up in start_process
  if (pid == TID_ERROR || !ws->loaded) {
    free(ws);
    f->eax = -1;
  } else {
    // Add the child to the list of active children
    struct list_elem *e = (struct list_elem*)malloc(sizeof(struct list_elem));
    ws->elem = *e;
    ws->loaded = true;
    ws->pid = pid;
    list_push_back(thread_current()->pcb->waits, &ws->elem);

    f->eax = pid;
  }
}

static int handle_open(char* filename) {
  struct list* fd_table = thread_current()->pcb->open_files;
  lock_acquire(&filesys_lock);
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
  lock_release(&filesys_lock);
  return fd_entry->fd;
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

static void handle_wait(struct intr_frame* f, unsigned* argv) {
  pid_t pid = argv[1];
  int status = process_wait(pid);
  f->eax = status;
}

static bool handle_create(char* file, unsigned size) {
  lock_acquire(&filesys_lock);
  bool success = filesys_create(file, size);
  lock_release(&filesys_lock);
  return success;
}

static bool handle_remove(char* file) {
  lock_acquire(&filesys_lock);
  bool success = filesys_remove(file);
  lock_release(&filesys_lock);
  return success;
}

static void handle_write(struct intr_frame* frame, unsigned* args) {
  unsigned size = (unsigned)args[3];
  char* buf = (char*)args[2];
  int fd = (int)args[1];
  lock_acquire(&filesys_lock);
  if (fd == 1) {
    putbuf(buf, size);
    lock_release(&filesys_lock);
    frame->eax = size;
    return;
  } else {
    struct list* fd_table = thread_current()->pcb->open_files;
    struct file_data *f = find_file(fd, fd_table);
    if (f != NULL) {
      int result = file_write(f->file, buf, size);
      lock_release(&filesys_lock);
      frame->eax = result;
      return;
    }
    lock_release(&filesys_lock);
    frame->eax = -1;
    return;
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
    int position = file_tell(f->file);
    lock_release(&filesys_lock);
    return position;
  }
  lock_release(&filesys_lock);
  return -1;
}

static void handle_compute_e(struct intr_frame* f, unsigned* argv) {
    f->eax = sys_sum_to_e((int)argv[1]);
}

static void handle_halt(struct intr_frame* f UNUSED, unsigned* argv UNUSED) {
    shutdown_power_off();
}

/* Validate ARGS by ensuring each address points to valid memory.
 * Valid pointers are not null, reference below PHYS_BASE/are not
 * in kernel memory.
*/
static void validate_args(struct intr_frame* f, uint32_t* args, int n) {
  int i = 1;
  
  int vldt_i = -1;
  if (args[0] == SYS_EXEC || args[0] == SYS_OPEN || args[0] == SYS_CREATE || args[0] == SYS_REMOVE) {
    vldt_i = 1;
  }
  if (args[0] == SYS_READ || args[0] == SYS_WRITE) {
    vldt_i = 2;
  }
  if (vldt_i != -1) {
    // Argument is a pointer, make sure it's valid
    if (is_kernel_vaddr((void*)(&args[vldt_i]+1)) || pagedir_get_page(active_pd(), (void*)&args[vldt_i]+1) == NULL || args[vldt_i] == (int)NULL) {
      f->eax = -1;
      handle_exit(-1);
    }
    if (is_kernel_vaddr((void*)(args[vldt_i]+1)) || pagedir_get_page(active_pd(), (void*)args[vldt_i]+1) == NULL || args[vldt_i] == (int)NULL) {
      f->eax = -1;
      handle_exit(-1);
    }
  }
  
  for (; i != n+1; i++) {
    if ((void*)args[i] == NULL && (args[0] != SYS_EXIT && args[0] != SYS_READ && args[0] != SYS_WRITE &&
                                   args[0] != SYS_SEEK && args[0] != SYS_TELL && args[0] != SYS_CREATE)) {
      // exit(0) is a successfull exit, reading/writing 0 bytes is valid
      break;
    }
    // For checking if the pointer is to invalid memory, add 1 byte to the
    // address to account for the case some bytes of the address are
    // valid but the others are not (address lies on a page boundary).
    if (is_kernel_vaddr((void*)(&args[i]+1))) {
      // Referencing kernel memory.
      break;
    }
    if (pagedir_get_page(active_pd(), (void*)(&args[i]+1)) == NULL) {
      // Referencing memory not in the page directory
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
  
  // Case where the stack is too large and all bytes of the esp are in invalid memory
  if (f->ebp - (uint32_t)f->esp > 4096 && pagedir_get_page(active_pd(), (void*)(f->esp+1)) == NULL) {
    handle_exit(-1);
  }

  handler_t h = handler_table[args[0]];
  if (args[0] == SYS_PRACTICE || args[0] == SYS_COMPUTE_E || args[0] == SYS_WRITE) {
      validate_args(f, args, h.arity);
      h.fn(f, args);
      return;
  }

  switch (args[0]) {
    case SYS_CREATE:
      validate_args(f, args, 2);
      f->eax = handle_create((char*)args[1], (unsigned)args[2]);
      break;
    case SYS_REMOVE:
      validate_args(f, args, 1);
      f->eax = handle_remove((char*)args[1]);
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

void syscall_init(void) {
  lock_init(&filesys_lock);
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
  handler_table[SYS_PRACTICE] = makeHandler(handle_practice, 1);
  handler_table[SYS_COMPUTE_E] = makeHandler(handle_compute_e, 1);
  handler_table[SYS_WRITE] = makeHandler(handle_write, 3);
  handler_table[SYS_HALT] = makeHandler(handle_halt, 0);
  handler_table[SYS_EXIT] = makeHandler(f_handle_exit, 1);
  handler_table[SYS_EXEC] = makeHandler(handle_exec, 1);
  handler_table[SYS_WAIT] = makeHandler(handle_wait, 1);
}
