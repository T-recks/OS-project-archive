#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/thread.h"
#include "userprog/process.h"

/* Partition that contains the file system. */
struct block* fs_device;

static void do_format(void);

static struct dir* get_cwd(void) {
  struct dir* dir = thread_current()->pcb->cwd;
  if (dir == NULL)
    dir = dir_open_root();
  return dir;
}

bool is_absolute(const char* path) { return path[0] == '\\' || path[0] == '/'; }

bool parent_path(const char* path) { return strlen(path) >= 2 && path[0] == '.' && path[1] == '.'; }

/* Takes a relative PATH; return false if given absolute path.
 * Expands it to an absolute path and stores in DEST.
 * The caller is responsible for making sure DEST and S are large
 * enough to store the full path.
 */
bool expand_path(char* dst, const char* path, size_t size) {
    if (is_absolute(path)) {
        return false;
    } else {
        char* cwd = thread_current()->pcb->cwd_name;
        strlcpy(dst, cwd, strlen(cwd)); // copy cwd
        strlcat(dst, "/", 1); // append "/"
        strlcat(dst, path, size); // append path
        return true;
    }
}

/* Equivalent to parse_dir, except
 * 1. We return a bool indicating whether the path refers to a directory
 * 2. We modify dst so it points to the the second to last element of the path
 * Examples:
 * struct dir* dir; 
 * file_is_dir("/home/tim/somefile.c", &dir);
 * -> false
 * dir points to /home/tim directory
 * file_is_dir("/home/tim/somedirectory", &dir);
 * -> true
 * dir points to /home/tim
 */
bool file_is_dir(char* path, struct dir** dst, char name[NAME_MAX+1]) {
    struct dir* dir;
    
    if (is_absolute(path)) {
        dir = dir_open_root();
    } else {
        dir = get_cwd();
    }
    
    struct dir* parent;
    *dst = traverse(dir_get_inode(dir), path, &parent, name, true);

    struct inode* inode;
    dir_lookup(*dst, name, &inode);
    return inode_is_dir(inode);
}

/* Returns the directory the file is located in, storing the parsed
 * name of the file in NAME */
static struct dir* parse_dir(const char* path, char name[NAME_MAX + 1]) {
  struct dir* dir;
  if (is_absolute(path)) {
    dir = dir_open_root();
  } else {
    dir = get_cwd();
    if (parent_path(name)) {
      // TODO: get the dir struct of the parent
      // dir =
    }
  }

  struct dir* parent;
  dir = traverse(dir_get_inode(dir), path, &parent, name, false);
  return dir;
}

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void filesys_init(bool format) {
  fs_device = block_get_role(BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC("No file system device found, can't initialize file system.");

  cache_init();
  inode_init();
  free_map_init();

  if (format)
    do_format();

  free_map_open();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void filesys_done(void) {
  cleanup_cache();
  free_map_close();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool filesys_create(const char* name, off_t initial_size) {
  block_sector_t inode_sector = 0;
  char relative_name[NAME_MAX + 1];
  struct dir* dir = parse_dir(name, relative_name);
  bool success = (dir != NULL && free_map_allocate(1, &inode_sector) &&
                  inode_create(inode_sector, initial_size, false) &&
                  dir_add(dir, relative_name, inode_sector));
  if (!success && inode_sector != 0)
    free_map_release(inode_sector, 1);

  if (dir_get_inode(dir) != dir_get_inode(get_cwd())) {
    // Don't want to close the process' CWD
    dir_close(dir);
  }

  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file* filesys_open(const char* name) {
  char relative_name[NAME_MAX + 1];
  struct dir* dir = parse_dir(name, relative_name);
  struct inode* inode = NULL;

  if (dir != NULL)
    dir_lookup(dir, relative_name, &inode);

  if (dir_get_inode(dir) != dir_get_inode(get_cwd())) {
    // Don't want to close the process' CWD
    dir_close(dir);
  }
  return file_open(inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool filesys_remove(const char* name) {
  char relative_name[NAME_MAX + 1];
  struct dir* dir = parse_dir(name, relative_name);
  bool success = dir != NULL && dir_remove(dir, relative_name);

  if (dir_get_inode(dir) != dir_get_inode(get_cwd())) {
    // Don't want to close the process' CWD
    dir_close(dir);
  }

  return success;
}

/* Formats the file system. */
static void do_format(void) {
  printf("Formatting file system...");
  free_map_create();
  if (!dir_create(ROOT_DIR_SECTOR, 16))
    PANIC("root directory creation failed");
  free_map_close();
  printf("done.\n");
}
