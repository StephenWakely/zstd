#include<sys/mman.h>
#include<stdlib.h>
#include<stdio.h>
#include<stdatomic.h>
#include<unistd.h>
#include<pthread.h>
#include<string.h>
#include "zalloc.h"

//#define INDEBUG

#ifdef INDEBUG

#define DEBUG(msg, ...)           \
  do {                            \
    printf("zalloc: ");           \
    printf(msg, ##__VA_ARGS__);   \
    fflush(stdout);               \
  } while(0)

#else

#define DEBUG(msg, ...)           

#endif

// This is a fairly large assumption that we won't have more that 128 allocations
// using zstd. Initial tests show around 13.
#define MAX_ARENAS 128

// The header for each arena 
#define HEADER_OWNED(h, idx) (h[idx * 3])
#define HEADER_SIZE(h, idx) (h[idx * 3 + 1])
#define HEADER_ADDR(h, idx) (h[idx * 3 + 2])

static long* header = NULL; 
static pthread_mutex_t header_mutex = PTHREAD_MUTEX_INITIALIZER;

// Round up to nearest power of two
// https://graphics.stanford.edu/%7Eseander/bithacks.html#RoundUpPowerOf2
size_t roundsize(size_t v) {
  v--;
  v |= v >> 1;
  v |= v >> 2;
  v |= v >> 4;
  v |= v >> 8;
  v |= v >> 16;
  v++;
  return v;
}

// Create a new arena with 1gb of space allocated.
void* new_arena(size_t size) {
  void* buffer = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (buffer == MAP_FAILED) {
    perror("mmap");
    exit(EXIT_FAILURE);
  }

  return buffer;
}

// Gets the header block.
// If it hasn't been initialised, we create one 
void* get_header() {
  long* ret = __atomic_load_n(&header, __ATOMIC_RELAXED);
  if ( ret != NULL) {
    return (void*)ret;
  }

  pthread_mutex_lock(&header_mutex);

  // Check someone hasn't sneaked in before us to create the arena.
  ret = __atomic_load_n(&header, __ATOMIC_RELAXED);
  if ( ret != NULL) {
    return (void*)ret;
  }

  // Mmap our arena
  void* h = new_arena(MAX_ARENAS * 3);

  // Clear enough space for 128 arenas.
  memset(h, 0, MAX_ARENAS * 3);
  __atomic_store(&header, &h, __ATOMIC_RELAXED);

  pthread_mutex_unlock(&header_mutex);

  DEBUG("Made header\n");

  return h;
}

// Allocate memory with the given size.
void* zalloc(size_t size) {
  long* h = get_header();

  DEBUG("Header %p\n", h);

  // Round the size up to the nearest power of 2
  size_t upper_size = roundsize(size);

  // Find a free arena
  for (size_t arena_idx = 0; arena_idx < MAX_ARENAS; arena_idx++) {
    // Is this arena the size we want? If it is zero it hopefully means it hasn't been alloced
    // and we can claim it.
    long allocedsize = __atomic_load_n(&HEADER_SIZE(h, arena_idx), __ATOMIC_RELAXED);
    if (allocedsize == (long)upper_size || allocedsize == 0) {
      // Try to claim this arena.
      long expected = 0;
      if (__atomic_compare_exchange_n(&HEADER_OWNED(h, arena_idx), &expected, 1,
				      1, __ATOMIC_RELAXED,
				      __ATOMIC_RELAXED) != 0) {
	DEBUG("The arena %zu is ours!\n", arena_idx);
	// This arena is ours.
	long pointer =
	    __atomic_load_n(&HEADER_ADDR(h, arena_idx), __ATOMIC_RELAXED);
	if (pointer == 0) {
	  // Allocate some space
	  long arena = (long)new_arena(upper_size);
	  __atomic_store(&HEADER_ADDR(h, arena_idx), &arena, __ATOMIC_RELAXED);
	  __atomic_store(&HEADER_SIZE(h, arena_idx), (long*)&upper_size, __ATOMIC_RELAXED);
	  pointer = (long)arena;
	  DEBUG("arena needs allocating : %p %zu(rounded to %zu)\n", (void *)arena, size, upper_size);
	}

        DEBUG("alloced : %p\n", (void *)pointer);

	#if defined INDEBUG
	dumparenas();
	#endif

        return (void *)pointer;
      }
    } else {
      DEBUG("Wrong size for idx %zu wanted %zu got %ld\n", arena_idx, size, allocedsize);
    }
  }

  // No free arenas. :-(
  perror("no more arenas");
  return NULL;
}

// Free the memory at the given address.
void zfree(void* addr) {
  long* h = get_header();
  DEBUG("Need to free %p\n", addr);

  for (size_t arena_idx=0; arena_idx < MAX_ARENAS; arena_idx++) {
    DEBUG("Check arena to free %zu\n", arena_idx);
    long arena = __atomic_load_n(&HEADER_ADDR(h, arena_idx), __ATOMIC_RELAXED);
    DEBUG("Got arena %zu\n", arena);
    if (arena == (long)addr) {
      // Unset the flag so it can be reused
      __atomic_store_n(&HEADER_OWNED(h, arena_idx), 0, __ATOMIC_RELAXED);
      DEBUG("Freed\n");
      return;
    }
  }

  perror("couldn't find arena to free");
}

// Dump all the info about the arenas we have alloced.
void dumparenas() {
  long* h = get_header();
  for (size_t arena_idx = 0; arena_idx < MAX_ARENAS; arena_idx++) {
    long owned = __atomic_load_n(&HEADER_OWNED(h, arena_idx), __ATOMIC_RELAXED);
    long arena = __atomic_load_n(&HEADER_ADDR(h, arena_idx), __ATOMIC_RELAXED);
    long size = __atomic_load_n(&HEADER_SIZE(h, arena_idx), __ATOMIC_RELAXED);

    if (arena != 0) {
      printf("zalloc: Arena %zu: %ld %p %ld\n", arena_idx, owned, (void *)arena,
             size);
    }

  }
  printf("----------------\n");
  fflush(stdout);
}
