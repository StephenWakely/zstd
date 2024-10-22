#include<sys/mman.h>
#include<stdlib.h>
#include<stdio.h>
#include<stdatomic.h>
#include<unistd.h>
#include<pthread.h>
#include<string.h>

#define INDEBUG

#ifdef INDEBUG

#define DEBUG(msg, ...)           \
  do {                            \
    printf("zalloc: ");           \
    printf(msg, ##__VA_ARGS__);   \
    fflush(stdout);               \
  } while(0);

#else

#define DEBUG(msg, ...)           

#endif

#define MAX_ARENAS 128

//static _Atomic long* header = NULL;
static long* header = NULL; //ATOMIC_VAR_INIT(NULL);
static pthread_mutex_t header_mutex = PTHREAD_MUTEX_INITIALIZER;

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
  void* h = new_arena(MAX_ARENAS * 2);

  // Clear enough space for 128 arenas.
  memset(h, 0, 256);
  __atomic_store(&header, &h, __ATOMIC_RELAXED);

  pthread_mutex_unlock(&header_mutex);

  DEBUG("Made header\n");

  return h;
}

void* zalloc(size_t size) {
  (void)size;
  long* h = get_header();

  DEBUG("Header %p\n", h);

  // Find a free arena
  for (size_t arena_idx = 0; arena_idx < MAX_ARENAS; arena_idx++) {
    // Try to claim this arena.
    long expected = 0;
    if (__atomic_compare_exchange_n(&h[arena_idx * 2], &expected, 1, 1,
				    __ATOMIC_RELAXED, __ATOMIC_RELAXED) != 0) {
      DEBUG("The arena %zu is ours!\n", arena_idx);
      // This arena is ours, we don't need to do an atomic load here.
      long pointer = __atomic_load_n(&h[arena_idx * 2 + 1], __ATOMIC_RELAXED);
      if (pointer == 0) {
	// Giz a gig.
	long arena = (long)new_arena(1 << 30);
	__atomic_store(&h[arena_idx * 2 + 1], &arena, __ATOMIC_RELAXED);
	pointer = (long)arena;
	DEBUG("arena needs allocating : %p\n", (void *)arena);
      }

      DEBUG("alloced : %p\n", (void *)pointer);

      return (void *)pointer;
    }
  }

  // No free arenas. :-(
  return NULL;
}

// Free the memory at the given address.
void zfree(void* addr) {
  long* h = get_header();
  DEBUG("Need to free %p\n", addr);

  for (size_t arena_idx=0; arena_idx < MAX_ARENAS; arena_idx++) {
    DEBUG("Check arena to free %zu\n", arena_idx);
    long arena = __atomic_load_n(&h[arena_idx * 2 + 1], __ATOMIC_RELAXED);
    DEBUG("Got arena %zu\n", arena);
    if (arena == (long)addr) {
      // Unset the flag so it can be reused
      __atomic_store_n(&h[arena_idx * 2], 0, __ATOMIC_RELAXED);
      DEBUG("Freed\n");
      return;
    }
  }
}

