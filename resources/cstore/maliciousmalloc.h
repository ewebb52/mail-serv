#include <time.h>

#define realmalloc(x) malloc(x)
void *_my_malloc(size_t size, char *filename, int line)
{
	srand(time(0));
	int domalloc = (rand() % 100) < 85;

	if (domalloc)
		return realmalloc(size);

	fprintf(stderr, "Malicious Malloc Inserted at %s %d\n", filename, line);
	return NULL;
}

#define malloc(x) _my_malloc(x, __FILE__, __LINE__)
