static int handle_open(char* filename) {
  struct list* fd_table = thread_current()->pcb->open_files;
  struct dir* location;
  struct file* opened_file = NULL;
  struct dir* opened_dir = NULL;
  char name[NAME_MAX + 1];
  lock_acquire(&filesys_lock); // TODO: remove global lock

  // check for dir vs. file
  bool is_dir = file_is_dir(filename, &location, name);
  if (false) {
    struct inode* inode;
    dir_lookup(location, name, &inode);
    opened_dir = dir_open(inode);
    if (opened_dir == NULL) { // directory does not exist
      lock_release(&filesys_lock);
      return -1;
    }
  } else {
    struct file* opened_file = filesys_open(filename);
    if (opened_file == NULL) {
      lock_release(&filesys_lock);
      return -1;
    }
  }

  // TODO: abstract this
  // create a new fd table entry
  struct file_data* fd_entry = (struct file_data*)malloc(sizeof(struct file_data));
  fd_entry->dir = opened_dir;
  fd_entry->file = opened_file;
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
