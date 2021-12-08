#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include <stdio.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "threads/synch.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

#define NUM_DIR_PTR 123

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk {
  off_t length;   /* File size in bytes. */
  unsigned magic; /* Magic number. */
  bool isdir;     /* True if a directory, otherwise it's a file */
  block_sector_t direct_ptr[NUM_DIR_PTR];
  block_sector_t ind_ptr;     /* points to 128 data blocks */
  block_sector_t dbl_ind_ptr; /* points to 16384 data blocks */
};

file_buffer_t* f_buffer;

bool clock_algorithm(block_sector_t sector_addr, file_cache_block_t** block);
void advance_hand(void);

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t bytes_to_sectors(off_t size) { return DIV_ROUND_UP(size, BLOCK_SECTOR_SIZE); }

/* In-memory inode. */
struct inode {
  struct list_elem elem;  /* Element in inode list. */
  block_sector_t sector;  /* Sector number of disk location. */
  int open_cnt;           /* Number of openers. */
  bool removed;           /* True if deleted, false otherwise. */
  int deny_write_cnt;     /* 0: writes ok, >0: deny writes. */
  struct inode_disk data; /* Inode content. */
};

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t byte_to_sector(const struct inode* inode, off_t pos) {
  ASSERT(inode != NULL);
  off_t index = 0;
  // TODO: Get the inode_disk from the cache
  struct inode_disk data = inode->data;

  while (pos >= BLOCK_SECTOR_SIZE && index < NUM_DIR_PTR - 1) {
    // Start counting how many blocks above the first block the offset it
    pos -= BLOCK_SECTOR_SIZE;
    index += 1;
  }

  if (pos < BLOCK_SECTOR_SIZE) {
    return data.direct_ptr[index];
  } else if (data.ind_ptr == 0) {
    // Offset is past end of file
    return -1;
  }

  // Look through indirect pointers
  if (pos <= 128 * BLOCK_SECTOR_SIZE) {
    pos -= BLOCK_SECTOR_SIZE;
    block_sector_t buffer[128];
    memset(buffer, 0, 512);
    block_read(fs_device, data.ind_ptr, buffer);
    index = 0;
    while (pos >= BLOCK_SECTOR_SIZE && index < 127) {
      pos -= BLOCK_SECTOR_SIZE;
      index += 1;
    }

    if (pos < BLOCK_SECTOR_SIZE) {
      return buffer[index];
    } else if (data.dbl_ind_ptr == 0) {
      // Offset is past end of file
      return -1;
    }
  }

  // TODO: has not been tested
  // Look through doubly direct pointers
  pos -= 128 * BLOCK_SECTOR_SIZE;
  block_sector_t ind_buffer[128];
  memset(ind_buffer, 0, 512);
  block_read(fs_device, data.ind_ptr, ind_buffer);
  for (int i = 0; i < 128; i++) {
    block_sector_t buffer[128];
    memset(buffer, 0, 512);
    block_sector_t ind_block = ind_buffer[i];
    block_read(fs_device, ind_block, buffer);
    block_sector_t block = ind_block;
    index = 0;
    while (pos >= BLOCK_SECTOR_SIZE && index < 127) {
      pos -= BLOCK_SECTOR_SIZE;
      index += 1;
    }

    if (pos < BLOCK_SECTOR_SIZE) {
      return buffer[index];
    } else if (data.dbl_ind_ptr == 0) {
      // Offset is past end of file
      return -1;
    }
  }

  //  if (pos < inode->data.length)
  ////    return inode->data.start + pos / BLOCK_SECTOR_SIZE;
  //    return inode->data.direct_ptr[0] + pos / BLOCK_SECTOR_SIZE;
  //  else
  //    return -1;
}

static bool inode_resize(struct inode_disk* id, off_t size) {
  static char zeros[BLOCK_SECTOR_SIZE];

  // Try direct pointers
  for (int i = 0; i < NUM_DIR_PTR; i++) {
    if (size <= 512 * i && id->direct_ptr[i] != 0) {
      // Shrink inode
      free_map_release(id->direct_ptr[i], 1);
      id->direct_ptr[i] = 0;
    }
    if (size > 512 * i && id->direct_ptr[i] == 0) {
      if (!free_map_allocate(1, &id->direct_ptr[i])) {
        // Allocation failed; rollback
        inode_resize(id, id->length);
        return false;
      }
      block_write(fs_device, id->direct_ptr[i], zeros);
    }
  }

  // Try indirect
  if (id->ind_ptr == 0 && size <= 512 * NUM_DIR_PTR) {
    // Can fit with just direct pointers, and no need to shrink since inode has not idps
    id->length = size;
    return true;
  }

  block_sector_t buffer[128];
  if (id->ind_ptr == 0) {
    memset(buffer, 0, 512);
    // Allocate indirect page
    if (!free_map_allocate(1, &id->ind_ptr)) {
      inode_resize(id, id->length);
      return false;
    }
  } else {
    block_read(fs_device, id->ind_ptr, buffer);
  }
  for (int i = 0; i < 128; i++) {
    if (size <= (NUM_DIR_PTR + i) * 512 && buffer[i] != 0) {
      free_map_release(buffer[i], 1);
      buffer[i] = 0;
    }
    if (size > (NUM_DIR_PTR + i) * 512 && buffer[i] == 0) {
      if (!free_map_allocate(1, &buffer[i])) {
        inode_resize(id, id->length);
        return false;
      }
      block_write(fs_device, buffer[i], zeros);
    }
  }
  if (id->ind_ptr != 0 && size <= 512 * NUM_DIR_PTR) {
    // Needed to shrink the inode, and deleted all the indirect blocks; now delete the idp
    free_map_release(id->ind_ptr, 1);
    id->ind_ptr = 0;
  } else {
    block_write(fs_device, id->ind_ptr, buffer);
  }

  // Try doubly indirect
  if (id->dbl_ind_ptr == 0 && size <= 512 * NUM_DIR_PTR + 128 * 512) {
    // Fits without doubly indirect, and no doubly indirect pointer present
    id->length = size;
    return true;
  }

  if (id->dbl_ind_ptr == 0) {
    // Allocate doubly indirect page
    if (!free_map_allocate(1, &id->dbl_ind_ptr)) {
      inode_resize(id, id->length);
      return false;
    }
  } else {
    // Each element in buffer is now an indirect pointer
    block_read(fs_device, id->dbl_ind_ptr, buffer);
  }
  for (int i = 0; i < 128; i++) {
    // For storing the indirect pointers of the doubly indirect pointer
    block_sector_t ind_buffer[128];
    block_read(fs_device, buffer[i], ind_buffer);
    for (int k = 0; k < 128; k++) {
      if (size <= (NUM_DIR_PTR + i) * 128 * 512 && ind_buffer[i] != 0) {
        free_map_release(ind_buffer[i], 1);
        ind_buffer[i] = 0;
      }
      if (size > (NUM_DIR_PTR + i) * 128 * 512 && ind_buffer[i] == 0) {
        if (!free_map_allocate(1, &ind_buffer[i])) {
          inode_resize(id, id->length);
          return false;
        }
        block_write(fs_device, ind_buffer[i], zeros);
      }
    }
  }
  if (id->ind_ptr != 0 && size <= 512 * NUM_DIR_PTR + 128 * 512) {
    free_map_release(id->dbl_ind_ptr, 1);
    id->dbl_ind_ptr = 0;
  } else {
    block_write(fs_device, id->ind_ptr, buffer);
  }

  id->length = size;
  return true;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

struct list inode_get_list(void) {
  return open_inodes;
}

/* Initializes the inode module. */
void inode_init(void) { list_init(&open_inodes); }

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool inode_create(block_sector_t sector, off_t length, bool isdir) {
  struct inode_disk* disk_inode = NULL;
  bool success = false;

  ASSERT(length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT(sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc(1, sizeof *disk_inode);
  if (disk_inode != NULL) {
    size_t sectors = bytes_to_sectors(length);
    disk_inode->length = length;
    disk_inode->magic = INODE_MAGIC;

    disk_inode->isdir = isdir;
    if (inode_resize(disk_inode, length)) {
      //    if (free_map_allocate(sectors, &disk_inode->start)) {
      cache_write(sector, disk_inode);
      if (sectors > 0) {
        static char zeros[BLOCK_SECTOR_SIZE];
        size_t i;

        //        for (i = 0; i < sectors; i++)
        //          block_write(fs_device, disk_inode->start + i, zeros);
      }
      success = true;
    }
    free(disk_inode);
  }
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode* inode_open(block_sector_t sector) {
  struct list_elem* e;
  struct inode* inode;

  /* Check whether this inode is already open. */
  for (e = list_begin(&open_inodes); e != list_end(&open_inodes); e = list_next(e)) {
    inode = list_entry(e, struct inode, elem);
    if (inode->sector == sector) {
      inode_reopen(inode);
      return inode;
    }
  }

  /* Allocate memory. */
  inode = malloc(sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front(&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  cache_read(inode->sector, &inode->data);
  // block_read(fs_device, inode->sector, &inode->data);
  return inode;
}

/* Reopens and returns INODE. */
struct inode* inode_reopen(struct inode* inode) {
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t inode_get_inumber(const struct inode* inode) { return inode->sector; }

bool inode_is_dir(struct inode* inode) {
  // TODO: get this from cache
  return inode->data.isdir;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void inode_close(struct inode* inode) {
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0) {
    /* Remove from inode list and release lock. */
    list_remove(&inode->elem);

    /* Deallocate blocks if removed. */
    if (inode->removed) {
      free_map_release(inode->sector, 1);
      // TODO: Get data from cache
      inode_resize(&inode->data, 0);
      //      free_map_release(inode->data.start, bytes_to_sectors(inode->data.length));
    }

    free(inode);
  }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void inode_remove(struct inode* inode) {
  ASSERT(inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t inode_read_at(struct inode* inode, void* buffer_, off_t size, off_t offset) {
  uint8_t* buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t* bounce = NULL;

  while (size > 0) {
    /* Disk sector to read, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector(inode, offset);
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length(inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually copy out of this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
      break;

    if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
      /* Read full sector directly into caller's buffer. */
      cache_read(sector_idx, buffer + bytes_read);
    } else {
      /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
      if (bounce == NULL) {
        bounce = malloc(BLOCK_SECTOR_SIZE);
        if (bounce == NULL)
          break;
      }
      cache_read(sector_idx, bounce);
      memcpy(buffer + bytes_read, bounce + sector_ofs, chunk_size);
    }

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_read += chunk_size;
  }
  free(bounce);

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t inode_write_at(struct inode* inode, const void* buffer_, off_t size, off_t offset) {
  const uint8_t* buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t* bounce = NULL;

  if (inode->deny_write_cnt)
    return 0;

  // TODO: Get the data from the cache
  if (offset + size > inode->data.length) {
    inode_resize(&inode->data, size + inode->data.length);
  }

  while (size > 0) {
    /* Sector to write, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector(inode, offset);
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length(inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually write into this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
      break;

    if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
      /* Write full sector directly to disk. */
      cache_write(sector_idx, buffer + bytes_written);
    } else {
      /* We need a bounce buffer. */
      if (bounce == NULL) {
        bounce = malloc(BLOCK_SECTOR_SIZE);
        if (bounce == NULL)
          break;
      }

      /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
      if (sector_ofs > 0 || chunk_size < sector_left)
        cache_read(sector_idx, bounce);
      else
        memset(bounce, 0, BLOCK_SECTOR_SIZE);
      memcpy(bounce + sector_ofs, buffer + bytes_written, chunk_size);
      cache_write(sector_idx, bounce);
    }

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_written += chunk_size;
  }
  free(bounce);

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void inode_deny_write(struct inode* inode) {
  inode->deny_write_cnt++;
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void inode_allow_write(struct inode* inode) {
  ASSERT(inode->deny_write_cnt > 0);
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t inode_length(const struct inode* inode) { return inode->data.length; }

void cache_init() {

  f_buffer = (file_buffer_t*)malloc(sizeof(file_buffer_t));

  f_buffer->clock_hand = 0;
  f_buffer->replacement_lock = (struct lock*)malloc(sizeof(struct lock));
  lock_init(f_buffer->replacement_lock);

  for (int i = 0; i < BUFFER_LEN; i++) {
    file_cache_block_t* entry = &f_buffer->buffer[i];

    entry->sector = 0;
    entry->contents = malloc(BLOCK_SECTOR_SIZE);
    entry->dirty = false;
    entry->in_use = false;
    entry->evicting = false;
    entry->free = true;
    entry->write_lock = (struct rw_lock*)malloc(sizeof(struct rw_lock));
    rw_lock_init(entry->write_lock);
  }
}

void cleanup_cache() {

  for (int i = 0; i < BUFFER_LEN; i++) {
    file_cache_block_t entry = f_buffer->buffer[i];
    if (entry.dirty && !entry.free) {
      block_write(fs_device, entry.sector, entry.contents);
    }
    free(entry.write_lock);
    free(entry.contents);
  }
  free(f_buffer->replacement_lock);
  free(f_buffer);
}

void cache_read(block_sector_t sector, void* buffer) {
  file_cache_block_t* block;

  if (!clock_algorithm(sector, &block)) {
    // cache miss
    block_read(fs_device, sector, block->contents);
    block->dirty = false;
  }

  rw_lock_acquire(block->write_lock, true);

  memcpy(buffer, block->contents, BLOCK_SECTOR_SIZE);

  rw_lock_release(block->write_lock, true);
}

void cache_write(block_sector_t sector, const void* buffer) {
  file_cache_block_t* block;

  if (!clock_algorithm(sector, &block)) {
    // cache miss
    block_read(fs_device, sector, block->contents);
  }

  rw_lock_acquire(block->write_lock, false);

  memcpy(block->contents, buffer, BLOCK_SECTOR_SIZE);

  block->dirty = true;

  rw_lock_release(block->write_lock, false);
}

bool clock_algorithm(block_sector_t sector_addr, file_cache_block_t** block) {
  file_cache_block_t* entry;

  // - acquire `replacement_lock`
  lock_acquire(f_buffer->replacement_lock);

  // - If `sector_addr` in `file_buffer` and not `evicting`:
  for (int i = 0; i < BUFFER_LEN; i++) {
    entry = &f_buffer->buffer[i];
    if (sector_addr == entry->sector && !entry->evicting) {
      //     - set appropriate `file_cache_block→in_use` to true
      //     - *block = &file_cache_block
      //     - release `replacement_lock`
      //     - Return `true`
      entry->in_use = true;
      *block = entry;
      lock_release(f_buffer->replacement_lock);

      return true;
    }
  }

  // - Else: cache miss

  //     - `advance_hand`
  advance_hand();
  entry = &f_buffer->buffer[f_buffer->clock_hand];

  //     - While `in_use` and not `free` and not `active` or `evicting`:
  while (entry->in_use && !entry->free && !entry->evicting) {
    //         - set `in_use` to 0 and advance_hand
    entry->in_use = false;
    advance_hand();
    entry = &f_buffer->buffer[f_buffer->clock_hand];
  }

  //     - If not `free`: evict the page
  if (!entry->free) {
    //         - rw_lock_acquire(file_cache_block→write_lock, false)`
    rw_lock_acquire(entry->write_lock, false);

    entry->evicting = true;
    //         - release `replacement_lock`
    lock_release(f_buffer->replacement_lock);

    //         - write back to disk if `dirty` via `block_write`.
    block_write(fs_device, entry->sector, entry->contents);
    entry->dirty = false;

    //         - acquire `replacement_lock`
    lock_acquire(f_buffer->replacement_lock);

    entry->evicting = false;

    //         - `rw_lock_``releas``e``(file_cache_block→write_lock, false)`
    rw_lock_release(entry->write_lock, false);
  }

  //     - set `free` to 0, `in_use` to 1
  entry->free = false;
  entry->in_use = true;

  //     - set `file_cache_block→sector` to `sector_addr`
  entry->sector = sector_addr;

  //     - *block = &file_cache_block
  *block = entry;

  //     - release `replacement_lock`
  lock_release(f_buffer->replacement_lock);

  //     - Return `false`
  return false;
}

void advance_hand() {
  f_buffer->clock_hand += 1;
  if (f_buffer->clock_hand >= BUFFER_LEN) {
    f_buffer->clock_hand = 0;
  }
}
