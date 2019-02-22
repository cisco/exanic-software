/**
 * Simple utility for writing to registers/memory in the devkit extra BAR spaces.
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
	
	if (argc < 4)
	{
		fprintf(stderr, "usage: %s file offset value\n", argv[0]);
		return 1;
	}

	fd = open(argv[1], O_RDWR);
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

	value = strtol(argv[3], &end, 0);
	if (*end)
	{
		fprintf(stderr, "bad value\n");
		return 1;
	}

	base = mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	close(fd);
	if (base == MAP_FAILED)
	{
		perror("mmap");
		return 1;
	}

	*(uint32_t *)(base + offset) = value;
	printf("%08x = %08x\n", offset, value);
	value  = *(uint32_t *)(base + offset);
	printf("%08x : %08x\n", offset, value);
	munmap(base, st.st_size);
	return 0;
}

