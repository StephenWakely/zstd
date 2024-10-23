#ifndef ZALLOC_H
#define ZALLOC_H

#include<stdlib.h>

void* zalloc(size_t size);
void zfree(void* addr); 
void dumpbuckets();

#endif
