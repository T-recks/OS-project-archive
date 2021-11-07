#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "threads/palloc.h"
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
void release_all_locks(void);
void up_all_semaphores(void);
void free_all_locks(void);
void free_all_semaphores(void);

struct lock filesys_lock;

void syscall_init(void) {
  lock_init(&filesys_lock);
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

void close_all_files(void) {
  struct process* pcb = thread_current()->pcb;
  struct list* fd_table = pcb->open_files;
  if (fd_table == NULL) {
    return;
  }

  while (!list_empty(fd_table)) {
    struct list_elem* e = list_pop_front(fd_table);
    struct file_data* f = list_entry(e, struct file_data, elem);
    file_close(f->file);
    f->ref_cnt--;
    if (f->ref_cnt == 0) {
      list_remove(e);
      free(f);
    }
  }
}

void clear_cmdline(void) {
  struct process* pcb = thread_current()->pcb;
  struct list* argv = pcb->argv;
  if (argv == NULL)
    return;

  while (!list_empty(argv)) {
    struct list_elem* e = list_pop_front(argv);
    struct word* w = list_entry(e, struct word, elem);
    list_remove(e);
    free(w);
  }
}

void free_all_locks(void) {
  struct process* pcb = thread_current()->pcb;
  struct list* locks = pcb->locks;
  if (locks == NULL)
    return;

  while (!list_empty(locks)) {
    struct list_elem* e = list_pop_front(locks);
    struct user_lock* w = list_entry(e, struct user_lock, elem);
    list_remove(e);
    free(w->lock_kernel);
    free(w);
  }
}

void free_all_semaphores(void) {
  struct process* pcb = thread_current()->pcb;
  struct list* semas = pcb->semaphores;
  if (semas == NULL)
    return;

  while (!list_empty(semas)) {
    struct list_elem* e = list_pop_front(semas);
    struct user_sema* w = list_entry(e, struct user_sema, elem);
    list_remove(e);
    free(w->sema_kernel);
    free(w);
  }
}

void release_all_locks(void) {
  struct process* pcb = thread_current()->pcb;
  struct list* locks = pcb->locks;
  if (locks == NULL)
    return;

  struct list_elem* e;
  for (e = list_begin(locks); e != list_end(locks); e = list_next(e)) {
    struct user_lock* ul = list_entry(e, struct user_lock, elem);
    struct thread* holder = ul->lock_kernel->holder;
    if (holder != NULL && holder->tid == thread_current()->tid) {
      lock_release(ul->lock_kernel);
    }
  }
}

static int handle_practice(int val) { return val + 1; }

void handle_exit(int status) {
  struct process* pcb = thread_current()->pcb;
  lock_acquire(&pcb->lock);
  if (pcb->exiting) {
    // Process already exiting
    lock_release(&pcb->lock);
    return;
  }
  pcb->exiting = true;
  
  // TODO: might only want the main thread to be getting past the conditional
  
  while (list_size(pcb->threads) > 1) {
    cond_wait(&pcb->cond, &pcb->lock);
  }
  
  // At this point, should only be 1 active thread; no more synchronization required
  lock_release(&pcb->lock);
  
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
  struct list_elem* e;
  struct wait_status* w;
  for (e = list_begin(pcb->waits); e != list_end(pcb->waits); e = list_next(e)) {
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
  //  release_all_locks();
  free_all_locks();
  free_all_semaphores();
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

  pid_t pid = process_execute(cmd_line, ws);
  // Wait for the child process to finish loading
  sema_down(&ws->sema_load); // Child calls sema_up in start_process
  if (pid == TID_ERROR || !ws->loaded) {
    free(ws);
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
  struct file_data* f = find_file(fd, fd_table);
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
  struct file_data* f = find_file(fd, fd_table);
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

static bool handle_remove(char* file) {
  lock_acquire(&filesys_lock);
  bool success = filesys_remove(file);
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
    lock_release(&filesys_lock);
    return size;
  } else {
    struct list* fd_table = thread_current()->pcb->open_files;
    struct file_data* f = find_file(fd, fd_table);
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
  struct file_data* f = find_file(fd, fd_table);
  if (f != NULL) {
    file_seek(f->file, position);
  }
  lock_release(&filesys_lock);
}

static unsigned handle_tell(int fd) {
  lock_acquire(&filesys_lock);
  struct list* fd_table = thread_current()->pcb->open_files;
  struct file_data* f = find_file(fd, fd_table);
  if (f != NULL) {
    int position = file_tell(f->file);
    lock_release(&filesys_lock);
    return position;
  }
  lock_release(&filesys_lock);
  return -1;
}

static int handle_compute_e(int n) { return sys_sum_to_e(n); }

static bool handle_lock_init(char lock) {
  // TODO: use process lock to lock these functions
  if (lock == NULL) {
    return false;
  }

  struct list* locks = thread_current()->pcb->locks;

  struct user_lock* lock_u = malloc(sizeof(struct user_lock));
  if (lock_u == NULL) {
    handle_exit(-1);
  }

  struct lock* lock_k = malloc(sizeof(struct lock));
  lock_init(lock_k);
  lock_u->lock_user = lock;
  lock_u->lock_kernel = lock_k;
  list_push_back(locks, &lock_u->elem);
  return true;
}

static bool handle_lock_acquire(char lock) {
  struct process* pcb = thread_current()->pcb;
  struct list* locks = pcb->locks;
  struct list_elem* e;

  lock_acquire(&pcb->lock);
  for (e = list_begin(locks); e != list_end(locks); e = list_next(e)) {
    struct user_lock* lock_u = list_entry(e, struct user_lock, elem);

    // Get the kernel lock mapped by the user lock
    if (lock_u->lock_user == lock) {
      struct thread* holder = lock_u->lock_kernel->holder;
      if (holder == NULL || holder->tid != thread_current()->tid) {
        lock_acquire(lock_u->lock_kernel);
        lock_release(&pcb->lock);
        return true;
      } else {
        // Process already holds this lock
        lock_release(&pcb->lock);
        return false;
      }
    }
  }

  // User lock not initialized by this process
  lock_release(&pcb->lock);
  return false;
}

static bool handle_lock_release(char lock) {
  struct process* pcb = thread_current()->pcb;
  struct list* locks = pcb->locks;
  struct list_elem* e;

  lock_acquire(&pcb->lock);
  for (e = list_begin(locks); e != list_end(locks); e = list_next(e)) {
    struct user_lock* lock_u = list_entry(e, struct user_lock, elem);

    // Get the kernel lock mapped by the user lock
    if (lock_u->lock_user == lock) {
      struct thread* holder = lock_u->lock_kernel->holder;
      if (holder != NULL && holder->tid == thread_current()->tid) {
        lock_release(lock_u->lock_kernel);
        lock_release(&pcb->lock);
        return true;
      } else {
        // Process does not hold this lock
        lock_release(&pcb->lock);
        return false;
      }
    }
  }

  // User lock not initialized by this process
  lock_release(&pcb->lock);
  return false;
}

static bool handle_sema_init(char sema, int val) {
  if (sema == NULL || val < 0) {
    return false;
  }

  struct list* semaphores = thread_current()->pcb->semaphores;
  struct user_sema* sema_u = malloc(sizeof(struct user_sema));
  if (sema_u == NULL) {
    handle_exit(-1);
  }

  struct semaphore* sema_k = malloc(sizeof(struct semaphore));
  sema_init(sema_k, val);
  sema_u->sema_user = sema;
  sema_u->sema_kernel = sema_k;
  list_push_back(semaphores, &sema_u->elem);
  return true;
}

static bool handle_sema_change(char sema, bool up) {
  struct process* pcb = thread_current()->pcb;
  struct list* semaphores = pcb->semaphores;
  struct list_elem* e;

  lock_acquire(&pcb->lock);
  for (e = list_begin(semaphores); e != list_end(semaphores); e = list_next(e)) {
    struct user_sema* sema_u = list_entry(e, struct user_sema, elem);

    // Get the semaphore lock mapped by the user lock
    if (sema_u->sema_user == sema) {
      if (up) {
        sema_up(sema_u->sema_kernel);
        lock_release(&pcb->lock);
        return true;
      } else {
        sema_down(sema_u->sema_kernel);
        lock_release(&pcb->lock);
        return true;
      }
    }
  }

  // User semaphore not initialized by this process
  lock_release(&pcb->lock);
  return false;
}

static tid_t handle_sys_pthread_create(stub_fun sfun, pthread_fun tfun, void* arg) {
  struct thread* t = thread_current();
  lock_acquire(&t->pcb->lock);
  tid_t tid = pthread_execute(sfun, tfun, arg);
  lock_release(&t->pcb->lock);
  return tid;
}

static tid_t handle_sys_pthread_join(tid_t tid) {
  struct thread *t = thread_current();
  if (t->pcb->main_thread->tid == tid) {
    sema_down(&t->js->sema);
    return tid;
  }
  struct list* joins = t->pcb->threads;
  struct list_elem *e;
  lock_acquire(&t->pcb->lock);
  for (e = list_begin(joins); e != list_end(joins); e = list_next(e)) {
    struct join_status *js = list_entry(e, struct join_status, elem);
    if (js->tid == tid) {
      lock_acquire(&js->lock); // Acquire before so only one thread can get into the conditional
      if (!js->joined) {
        // Set to true to avoid waiting on the same thread twice
        js->joined = true;
        lock_release(&js->lock);
        if (js->status == THREAD_DYING) {
          // Thread was part of the same process but has already terminated
          lock_release(&t->pcb->lock);
          return js->tid;
        } else {
          // Block on the thread (release locks to avoid deadlock)
          release_all_locks();
          lock_release(&t->pcb->lock);
          sema_down(&js->sema);
          
          // Free the join status and remove it from the list
          lock_acquire(&t->pcb->lock);
          list_remove(e);
          free(js);
          lock_release(&t->pcb->lock);
          return tid;
        }
      } else {
        // INVALID: Thread has already been joined on
        lock_release(&js->lock);
        lock_release(&t->pcb->lock);
        return TID_ERROR;
      }
    }
  }
  
  // INVALID: Thread is not a part of this process
  lock_release(&t->pcb->lock);
  return TID_ERROR;
}

static void handle_sys_pthread_exit_main(void) {
  struct thread *t = thread_current();
  
  lock_acquire(&t->pcb->lock);
  // Wake any waiters and signal
  sema_up(&t->js->sema);
  cond_signal(&t->pcb->cond, &t->pcb->lock);
  lock_release(&t->pcb->lock);
  
  
  // Join on all unjoined threads
  struct list* threads = t->pcb->threads;
  struct list_elem *e;
  for (e = list_begin(threads); e != list_end(threads); e = list_next(e)) {
    struct join_status *js = list_entry(e, struct join_status, elem);
    if (!js->joined) {
      handle_sys_pthread_join(js->tid);
    }
  }
  
  // Process exit
  handle_exit(0);
}

void handle_sys_pthread_exit(void) {
  struct thread *t = thread_current();
  if (t->pcb->main_thread->tid == t->tid) {
    // Exiting thread is main thread
    handle_sys_pthread_exit_main();
  } else {
    // Deallocate the user stack
    pagedir_clear_page(t->pcb->pagedir, t->thread_stack);
    void* page = pagedir_get_page(t->pcb->pagedir, t->thread_stack);
    palloc_free_page(page);
    
    lock_acquire(&t->pcb->lock);
    // Wake any waiters and signal
    sema_up(&t->js->sema);
    cond_signal(&t->pcb->cond, &t->pcb->lock);
    lock_release(&t->pcb->lock);
  
    // Kill the thread
    thread_exit();
  }
}

/* Validate ARGS by ensuring each address points to valid memory.
 * Valid pointers are not null, reference below PHYS_BASE/are not
 * in kernel memory.
*/
static void validate_args(struct intr_frame* f, uint32_t* args, int n) {
  int i = 1;

  int vldt_i = -1;
  if (args[0] == SYS_EXEC || args[0] == SYS_OPEN || args[0] == SYS_CREATE ||
      args[0] == SYS_REMOVE) {
    vldt_i = 1;
  }
  if (args[0] == SYS_READ || args[0] == SYS_WRITE) {
    vldt_i = 2;
  }
  if (vldt_i != -1) {
    // Argument is a pointer, make sure it's valid
    if (is_kernel_vaddr((void*)(&args[vldt_i] + 1)) ||
        pagedir_get_page(active_pd(), (void*)&args[vldt_i] + 1) == NULL ||
        args[vldt_i] == (int)NULL) {
      f->eax = -1;
      handle_exit(-1);
    }
    if (is_kernel_vaddr((void*)(args[vldt_i] + 1)) ||
        pagedir_get_page(active_pd(), (void*)args[vldt_i] + 1) == NULL ||
        args[vldt_i] == (int)NULL) {
      f->eax = -1;
      handle_exit(-1);
    }
  }

  for (; i != n + 1; i++) {
    if ((void*)args[i] == NULL &&
        (args[0] != SYS_EXIT && args[0] != SYS_READ && args[0] != SYS_WRITE &&
         args[0] != SYS_SEEK && args[0] != SYS_TELL && args[0] != SYS_CREATE)) {
      // exit(0) is a successfull exit, reading/writing 0 bytes is valid
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
  if (f->ebp - (uint32_t)f->esp > 4096 &&
      pagedir_get_page(active_pd(), (void*)(f->esp + 1)) == NULL) {
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
    case SYS_COMPUTE_E:
      f->eax = handle_compute_e(args[1]);
      break;
    case SYS_PT_CREATE:
      f->eax = handle_sys_pthread_create((stub_fun)args[1], (pthread_fun)args[2], (void*)args[3]);
      break;
    case SYS_PT_EXIT:
      handle_sys_pthread_exit();
      break;
    case SYS_PT_JOIN:
      f->eax = handle_sys_pthread_join((tid_t)args[1]);
      break;
    case SYS_LOCK_INIT:
      f->eax = handle_lock_init((char)args[1]);
      break;
    case SYS_LOCK_ACQUIRE:
      //      validate_args(f, args, 1);
      f->eax = handle_lock_acquire((char)args[1]);
      break;
    case SYS_LOCK_RELEASE:
      //      validate_args(f, args, 1);
      f->eax = handle_lock_release((char)args[1]);
      break;
    case SYS_SEMA_INIT:
      //      validate_args(f, args, 2);
      f->eax = handle_sema_init((char)args[1], (int)args[2]);
      break;
    case SYS_SEMA_DOWN:
      //      validate_args(f, args, 1);
      f->eax = handle_sema_change((char)args[1], false);
      break;
    case SYS_SEMA_UP:
      //      validate_args(f, args, 1);
      f->eax = handle_sema_change((char)args[1], true);
      break;
  }
}
