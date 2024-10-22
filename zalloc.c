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
#define MAX_BUCKETS 128

// The header for each bucket 
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

// Create a new bucket with 1gb of space allocated.
void* new_bucket(size_t size) {
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

  // Check someone hasn't sneaked in before us to create the bucket.
  ret = __atomic_load_n(&header, __ATOMIC_RELAXED);
  if ( ret != NULL) {
    return (void*)ret;
  }

  // Mmap our bucket
  void* h = new_bucket(MAX_BUCKETS * 3);

  // Clear enough space for 128 buckets.
  memset(h, 0, MAX_BUCKETS * 3);
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

  // Find a free bucket
  for (size_t bucket_idx = 0; bucket_idx < MAX_BUCKETS; bucket_idx++) {
    // Is this bucket the size we want? If it is zero it hopefully means it hasn't been alloced
    // and we can claim it.
    long allocedsize = __atomic_load_n(&HEADER_SIZE(h, bucket_idx), __ATOMIC_RELAXED);
    if (allocedsize == (long)upper_size || allocedsize == 0) {
      // Try to claim this bucket.
      long expected = 0;
      if (__atomic_compare_exchange_n(&HEADER_OWNED(h, bucket_idx), &expected, 1,
				      1, __ATOMIC_RELAXED,
				      __ATOMIC_RELAXED) != 0) {
	DEBUG("The bucket %zu is ours!\n", bucket_idx);
	// This bucket is ours.
	long pointer =
	    __atomic_load_n(&HEADER_ADDR(h, bucket_idx), __ATOMIC_RELAXED);
	if (pointer == 0) {
	  // Allocate some space
	  long bucket = (long)new_bucket(upper_size);
	  __atomic_store(&HEADER_ADDR(h, bucket_idx), &bucket, __ATOMIC_RELAXED);
	  __atomic_store(&HEADER_SIZE(h, bucket_idx), (long*)&upper_size, __ATOMIC_RELAXED);
	  pointer = (long)bucket;
	  DEBUG("bucket needs allocating : %p %zu(rounded to %zu)\n", (void *)bucket, size, upper_size);
	}

        DEBUG("alloced : %p\n", (void *)pointer);

	#if defined INDEBUG
	dumpbuckets();
	#endif

        return (void *)pointer;
      }
    } else {
      DEBUG("Wrong size for idx %zu wanted %zu got %ld\n", bucket_idx, size, allocedsize);
    }
  }

  // No free buckets. :-(
  perror("no more buckets");
  return NULL;
}

// Free the memory at the given address.
void zfree(void* addr) {
  long* h = get_header();
  DEBUG("Need to free %p\n", addr);

  for (size_t bucket_idx=0; bucket_idx < MAX_BUCKETS; bucket_idx++) {
    DEBUG("Check bucket to free %zu\n", bucket_idx);
    long bucket = __atomic_load_n(&HEADER_ADDR(h, bucket_idx), __ATOMIC_RELAXED);
    DEBUG("Got bucket %zu\n", bucket);
    if (bucket == (long)addr) {
      // Unset the flag so it can be reused
      __atomic_store_n(&HEADER_OWNED(h, bucket_idx), 0, __ATOMIC_RELAXED);
      DEBUG("Freed\n");
      return;
    }
  }

  perror("couldn't find bucket to free");
}

// Dump all the info about the buckets we have alloced.
void dumpbuckets() {
  long* h = get_header();
  for (size_t bucket_idx = 0; bucket_idx < MAX_BUCKETS; bucket_idx++) {
    long owned = __atomic_load_n(&HEADER_OWNED(h, bucket_idx), __ATOMIC_RELAXED);
    long bucket = __atomic_load_n(&HEADER_ADDR(h, bucket_idx), __ATOMIC_RELAXED);
    long size = __atomic_load_n(&HEADER_SIZE(h, bucket_idx), __ATOMIC_RELAXED);

    if (bucket != 0) {
      printf("zalloc: Bucket %zu: %ld %p %ld\n", bucket_idx, owned, (void *)bucket,
             size);
    }

  }
  printf("----------------\n");
  fflush(stdout);
}
