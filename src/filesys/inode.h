#ifndef FILESYS_INODE_H
#define FILESYS_INODE_H

#include <stdbool.h>
#include "filesys/off_t.h"
#include "devices/block.h"

#define BUFFER_LEN 64

struct bitmap;

typedef struct file_cache_block {
  block_sector_t sector;      // disk sector address cached by this block, 512B
  void* contents;             // contents at this sector (BLOCK_SECTOR_SIZE bytes)
  bool dirty;                 // tracks whether a write-back is required
  bool in_use;                // track if block has been used since last considered for replacement
  bool evicting;              // track if block is being evicted
  bool free;                  // if this block is empty
  struct rw_lock* write_lock; // prevents any other threads from accessing while one is writing
} file_cache_block_t;

typedef struct file_buffer {
  file_cache_block_t buffer[BUFFER_LEN]; // buffer cache representation
  uint8_t clock_hand;                    // where the clock hand currently points to
  struct lock* replacement_lock; // prevents race conditions when cache replacement is needed
} file_buffer_t;

void inode_init(void);
bool inode_create(block_sector_t, off_t, bool);
struct inode* inode_open(block_sector_t);
struct inode* inode_reopen(struct inode*);
block_sector_t inode_get_inumber(const struct inode*);

block_sector_t inode_open_cnt(const struct inode*);
bool inode_is_dir(struct inode*);
void inode_close(struct inode*);
void inode_remove(struct inode*);
off_t inode_read_at(struct inode*, void*, off_t size, off_t offset);
off_t inode_write_at(struct inode*, const void*, off_t size, off_t offset);
void inode_deny_write(struct inode*);
void inode_allow_write(struct inode*);
off_t inode_length(const struct inode*);
struct list inode_get_list(void);

void cache_init(void);
void cleanup_cache(void);
void cache_read(block_sector_t sector, void* buffer);
void cache_write(block_sector_t sector, const void* buffer);

#endif /* filesys/inode.h */
