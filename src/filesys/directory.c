#include "filesys/directory.h"
#include <stdio.h>
#include <string.h>
#include <list.h>
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "userprog/process.h"

/* A directory. */
struct dir {
  struct inode* inode; /* Backing store. */
  off_t pos;           /* Current position. */
};

/* A single directory entry. */
struct dir_entry {
  block_sector_t inode_sector; /* Sector number of header. */
  char name[NAME_MAX + 1];     /* Null terminated file name. */
  bool in_use;                 /* In use or free? */
  struct dir_entry* loc;       /* Pointer to "." directory */
  struct dir_entry* parent;    /* Pointer to ".." directory */
};

/* Creates a directory with space for ENTRY_CNT entries in the
   given SECTOR.  Returns true if successful, false on failure. */
bool dir_create(block_sector_t sector, size_t entry_cnt) {
  return inode_create(sector, entry_cnt * sizeof(struct dir_entry), true);
}

/* Opens and returns the directory for the given INODE, of which
   it takes ownership.  Returns a null pointer on failure. */
struct dir* dir_open(struct inode* inode) {
  struct dir* dir = calloc(1, sizeof *dir);
  if (inode != NULL && dir != NULL) {
    dir->inode = inode;
    dir->pos = 0;
    return dir;
  } else {
    inode_close(inode);
    free(dir);
    return NULL;
  }
}

/* Opens the root directory and returns a directory for it.
   Return true if successful, false on failure. */
struct dir* dir_open_root(void) {
  return dir_open(inode_open(ROOT_DIR_SECTOR));
}

/* Opens and returns a new directory for the same inode as DIR.
   Returns a null pointer on failure. */
struct dir* dir_reopen(struct dir* dir) {
  return dir_open(inode_reopen(dir->inode));
}

/* Destroys DIR and frees associated resources. */
void dir_close(struct dir* dir) {
  if (dir != NULL) {
    inode_close(dir->inode);
    free(dir);
  }
}

/* Returns the inode encapsulated by DIR. */
struct inode* dir_get_inode(struct dir* dir) {
  return dir->inode;
}

block_sector_t dir_get_sector(struct dir* dir) { return inode_get_inumber(dir->inode); }

struct dir_entry* dir_get_parent(struct dir* dir) {
  struct dir_entry e;
  size_t ofs;

  for (ofs = 0; inode_read_at(dir->inode, &e, sizeof e, ofs) == sizeof e; ofs += sizeof e)
    if (e.in_use && e.parent != NULL && e.parent->parent != NULL) {
      return e.parent->parent;
    }
  return NULL;
}

/* Searches DIR for a file with the given NAME.
   If successful, returns true, sets *EP to the directory entry
   if EP is non-null, and sets *OFSP to the byte offset of the
   directory entry if OFSP is non-null.
   otherwise, returns false and ignores EP and OFSP. */
static bool lookup(const struct dir* dir, const char* name, struct dir_entry* ep, off_t* ofsp) {
  struct dir_entry e;
  size_t ofs;

  ASSERT(dir != NULL);
  ASSERT(name != NULL);

  for (ofs = 0; inode_read_at(dir->inode, &e, sizeof e, ofs) == sizeof e; ofs += sizeof e)
    if (e.in_use && !strcmp(name, e.name)) {
      if (ep != NULL)
        *ep = e;
      if (ofsp != NULL)
        *ofsp = ofs;
      return true;
    }
  return false;
}

/* Searches DIR for a file with the given NAME
   and returns true if one exists, false otherwise.
   On success, sets *INODE to an inode for the file, otherwise to
   a null pointer.  The caller must close *INODE. */
bool dir_lookup(const struct dir* dir, const char* name, struct inode** inode) {
  struct dir_entry e;
  off_t ofs = 0;
  bool success = false;

  ASSERT(dir != NULL);
  ASSERT(name != NULL);

  if (lookup(dir, name, &e, &ofs)) {
    *inode = inode_open(e.inode_sector);
    if (*inode == NULL) {
      e.in_use = false;
      success = inode_write_at(dir->inode, &e, sizeof e, ofs) == sizeof e;
    }
  } else
    *inode = NULL;

  return *inode != NULL;
}

/* Adds a file named NAME to DIR, which must not already contain a
   file by that name.  The file's inode is in sector
   INODE_SECTOR.
   Returns true if successful, false on failure.
   Fails if NAME is invalid (i.e. too long) or a disk or memory
   error occurs. */
bool dir_add(struct dir* dir, const char* name, block_sector_t inode_sector) {
  struct dir_entry e;
  off_t ofs;
  bool success = false;

  ASSERT(dir != NULL);
  ASSERT(name != NULL);

  /* Check NAME for validity. */
  if (*name == '\0' || strlen(name) > NAME_MAX)
    return false;

  /* Check that NAME is not in use. */
  if (lookup(dir, name, NULL, NULL))
    goto done;

  /* Set OFS to offset of free slot.
     If there are no free slots, then it will be set to the
     current end-of-file.

     inode_read_at() will only return a short read at end of file.
     Otherwise, we'd need to verify that we didn't get a short
     read due to something intermittent such as low memory. */
  for (ofs = 0; inode_read_at(dir->inode, &e, sizeof e, ofs) == sizeof e; ofs += sizeof e)
    if (!e.in_use)
      break;

  // Initialize "." and ".." pointers
  //  struct dir_entry parent;
  //  lookup(dir, ".", parent, NULL);
  //  e.loc = &e;
  //  e.parent = &parent;

  /* Write slot. */
  e.in_use = true;
  strlcpy(e.name, name, sizeof e.name);
  e.inode_sector = inode_sector;
  success = inode_write_at(dir->inode, &e, sizeof e, ofs) == sizeof e;

done:
  return success;
}

bool dir_init(struct dir* parent, struct dir* dir) {
  return dir_add(dir, ".", inode_get_inumber(dir->inode)) &&
         dir_add(dir, "..", inode_get_inumber(parent->inode));
}

/* Removes any entry for NAME in DIR.
   Returns true if successful, false on failure,
   which occurs only if there is no file with the given NAME. */
bool dir_remove(struct dir* dir, const char* name) {
  struct dir_entry e;
  struct inode* inode = NULL;
  bool success = false;
  off_t ofs;

  ASSERT(dir != NULL);
  ASSERT(name != NULL);

  /* Find directory entry. */
  if (!lookup(dir, name, &e, &ofs))
    goto done;

  /* Open inode. */
  inode = inode_open(e.inode_sector);
  if (inode == NULL || inode == thread_current()->pcb->cwd->inode || inode_open_cnt(inode) > 4)
    goto done;

  if (inode_is_dir(inode) && !dir_is_empty(inode))
    goto done;
  /* Erase directory entry. */
  e.in_use = false;
  if (inode_write_at(dir->inode, &e, sizeof e, ofs) != sizeof e)
    goto done;

  /* Remove inode. */
  inode_remove(inode);
  success = true;

done:
  inode_close(inode);
  return success;
}

/* Reads the next directory entry in DIR and stores the name in
   NAME.  Returns true if successful, false if the directory
   contains no more entries. */
bool dir_readdir(struct dir* dir, char name[NAME_MAX + 1]) {
  struct dir_entry e;

  while (inode_read_at(dir->inode, &e, sizeof e, dir->pos) == sizeof e) {
    dir->pos += sizeof e;
    if (e.in_use && strcmp(e.name, ".") != 0 && strcmp(e.name, "..") != 0) {
      strlcpy(name, e.name, NAME_MAX + 1);
      return true;
    }
  }
  return false;
}

/* Extracts a file name part from *SRCP into PART, and updates *SRCP so that the
next call will return the next file name part. Returns 1 if successful, 0 at
end of string, -1 for a too-long file name part. */
static int get_next_part(char part[NAME_MAX + 1], const char** srcp) {
  const char* src = *srcp;
  char* dst = part;
  /* Skip leading slashes. If it's all slashes, we're done. */
  while (*src == '/')
    src++;
  if (*src == '\0')
    return 0;
  /* Copy up to NAME_MAX character from SRC to DST. Add null terminator. */
  while (*src != '/' && *src != '\0') {
    if (dst < part + NAME_MAX)
      *dst++ = *src;
    else
      return -1;
    src++;
  }
  *dst = '\0';
  /* Advance source pointer. */
  *srcp = src;
  return 1;
}

struct dir* traverse(struct inode* inode, const char* path, struct dir* parent,
                     char name[NAME_MAX + 1], bool get_s2l) {
  struct dir* d = malloc(sizeof(struct dir));
  struct inode* next_inode;
  char next_part[NAME_MAX + 1];
  if (name != NULL) {
    strlcpy(name, path, strlen(path) + 1);
  }
  bool success;

  d->inode = inode;
  d->pos = 0;

  get_next_part(next_part, &path);
  while ((success = dir_lookup(d, next_part, &next_inode))) {
    if (get_s2l && strlen(path) == 0) {
      strlcpy(name, next_part, strlen(next_part) + 1);
      return d;
    }
    get_next_part(next_part, &path);
    if (name != NULL) {
      strlcpy(name, next_part, strlen(next_part) + 1);
    }
    if (inode_is_dir(next_inode)) {
      if (!get_s2l)
        parent->inode = d->inode;
      d->inode = next_inode;
      d->pos = 0;
    } else {
      return d;
    }
    if (get_s2l && strlen(path) == 0) {
      return d;
    }
    if (strcmp(next_part, "..") == 0 && strlen(path) == 0)
      return d;
  }

  if (get_s2l && strlen(path) == 0) {
    strlcpy(name, next_part, strlen(next_part) + 1);
  }

  return d;
}

/* Return true if dir contains no active entries.
 */
bool dir_is_empty(const struct inode* inode) {
  struct dir_entry e;
  size_t ofs;

  // Search dir for an active entry and return false only if we find one
  for (ofs = 0; inode_read_at(inode, &e, sizeof e, ofs) == sizeof e; ofs += sizeof e) {
    if (e.in_use && strcmp(e.name, ".") != 0 && strcmp(e.name, "..") != 0) {
      return false;
    }
  }
  return true;
}