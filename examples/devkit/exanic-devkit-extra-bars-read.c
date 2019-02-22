/**
 * Simple utility for reading from registers/memory in the devkit extra BAR spaces.
 *
 * Works with the extra_bars_example.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>

int main(int argc, char *argv[])
{
	int fd;
	uint32_t offset, value;
	void *base;
	struct stat st;
	char *end;
	
	if (argc < 3)
	{
		fprintf(stderr, "usage: %s file offset\n", argv[0]);
		return 1;
	}

	fd = open(argv[1], O_RDONLY);
	if (fd == -1)
	{
		perror("open");
		return 1;
	}

	if (fstat(fd, &st) == -1)
	{
		perror("fstat");
		close(fd);
		return 1;
	}

	offset = strtol(argv[2], &end, 0);
	if (*end || (offset & 3) || (offset >= st.st_size))
	{
		fprintf(stderr, "bad offset %u\n", offset);
		return 1;
	}

	base = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	close(fd);
	if (base == MAP_FAILED)
	{
		perror("mmap");
		return 1;
	}

	value = *(uint32_t *)(base + offset);
	printf("%08x : %08x\n", offset, value);
	munmap(base, st.st_size);
	return 0;
}

