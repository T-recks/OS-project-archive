#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "threads/synch.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

#define NUM_DIR_PTR 124

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk {
  off_t length;   /* File size in bytes. */
  unsigned magic; /* Magic number. */
  block_sector_t direct_ptr[NUM_DIR_PTR];
  block_sector_t ind_ptr;     /* points to 128 data blocks */
  block_sector_t dbl_ind_ptr; /* points to 16384 data blocks */
};

typedef struct file_cache_block {
  block_sector_t sector;
  struct inode_disk inode_disk; // contents at this sector (BLOCK_SECTOR_SIZE bytes)
  bool dirty;                   // tracks whether a write-back is required
  bool in_use; // track if block has been used since last considered for replacement
  bool free;   // if this block is empty
  bool active;
  bool evicting;
  struct rw_lock write_lock; // prevents any other threads from accessing while one is writing
} file_cache_block_t;

typedef struct file_buffer {
  file_cache_block_t buffer[64]; // buffer cache representation
  uint8_t clock_hand;            // where the clock hand currently points to
  struct lock replacement_lock;  // prevents race conditions when cache replacement is needed
} file_buffer_t;

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

void cache_read(struct block* block, block_sector_t sector, void* buffer) {}
void cache_write(struct block* block, block_sector_t sector, const void* buffer) {}

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t byte_to_sector(const struct inode* inode, off_t pos) {
  ASSERT(inode != NULL);
  off_t index = 0;
  // TODO: Get the inode_disk from the cache
  struct inode_disk data = inode->data;

  while (pos >= BLOCK_SECTOR_SIZE && index < NUM_DIR_PTR) {
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
    block_sector_t ind_block = data.ind_ptr;
    for (int i = 0; i < 128; i++) {
      block_sector_t block = ind_block;
      if (index * BLOCK_SECTOR_SIZE >= pos) {
        return block;
      }
      pos -= BLOCK_SECTOR_SIZE;
      index += 1;
      ind_block++;
    }
  }

  // Look through doubly direct pointers
  pos -= 128 * BLOCK_SECTOR_SIZE;
  block_sector_t dbl_ind_block = data.dbl_ind_ptr;
  for (int i = 0; i < 128; i++) {
    block_sector_t ind_block = dbl_ind_block;
    block_sector_t block = ind_block;
    for (int k = 0; k < 128; k++) {
      if (index * BLOCK_SECTOR_SIZE >= pos) {
        return block;
      }
      pos -= BLOCK_SECTOR_SIZE;
      index += 1;
      ind_block++;
    }
    dbl_ind_block++;
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

/* Initializes the inode module. */
void inode_init(void) { list_init(&open_inodes); }

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool inode_create(block_sector_t sector, off_t length) {
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
    if (inode_resize(disk_inode, length)) {
      //    if (free_map_allocate(sectors, &disk_inode->start)) {
      block_write(fs_device, sector, disk_inode);
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
  block_read(fs_device, inode->sector, &inode->data);
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
      block_read(fs_device, sector_idx, buffer + bytes_read);
    } else {
      /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
      if (bounce == NULL) {
        bounce = malloc(BLOCK_SECTOR_SIZE);
        if (bounce == NULL)
          break;
      }
      block_read(fs_device, sector_idx, bounce);
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
    inode_resize(&inode->data, size);
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
      block_write(fs_device, sector_idx, buffer + bytes_written);
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
        block_read(fs_device, sector_idx, bounce);
      else
        memset(bounce, 0, BLOCK_SECTOR_SIZE);
      memcpy(bounce + sector_ofs, buffer + bytes_written, chunk_size);
      block_write(fs_device, sector_idx, bounce);
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
