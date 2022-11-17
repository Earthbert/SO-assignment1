/*
 * Loader Implementation
 *
 * 2022, Operating Systems
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h> 
#include <inttypes.h>
#include <sys/mman.h>
#include <fcntl.h>

#define DEBUG

#include "debug.h"
#include "exec_parser.h"


static so_exec_t *exec;

// Executable file descriptor.
static int exec_fd;

// Number of bits needed to represent an offset in a page(12 for 4KB pages).
static uint8_t pagesz_bits;

// Page size.
static uint32_t pagesize;

static struct sigaction oldhandler;


static void segv_handler(int signum, siginfo_t *info, void *context)
{
	int seg_nr = 0;
	// Move through segments and see if address is in one of them.
	while (seg_nr < exec->segments_no) {
		if ((exec->segments[seg_nr].vaddr + exec->segments[seg_nr].mem_size) >= info->si_addr && 
			exec->segments[seg_nr].vaddr <= info->si_addr) {
			break;
		}
		seg_nr++;
	}

	// Virtual address is not in any segment. Call def handler.
	if (seg_nr == exec->segments_no) {
		oldhandler.sa_sigaction(signum, info, context);
	}

	struct so_seg seg = exec->segments[seg_nr];

	uint32_t page_in_seg = (int32_t)(info->si_addr - seg.vaddr) >> pagesz_bits;

	// Address is already mapped. Call def handler.
	if (((uint8_t *)(seg.data))[page_in_seg] == 1) {
		oldhandler.sa_sigaction(signum, info, context);
	}

	// Map address with write access to be able to read from file is needed.
	void *mapped_addr = mmap(seg.vaddr + page_in_seg * pagesize, pagesize, PROT_WRITE, MAP_ANONYMOUS | MAP_FIXED | MAP_SHARED, -1, 0);
	((uint8_t *)(seg.data))[page_in_seg] = 1;

	uint32_t pos_in_seg = mapped_addr - seg.vaddr;

	// In case it is needed to put data from exec to the mapped page.
	if (pos_in_seg < seg.file_size) {
		// If the whole page is in segment.
		if (pos_in_seg + pagesize < seg.file_size) {
			lseek(exec_fd, seg.offset + pos_in_seg, SEEK_SET);
			read(exec_fd, mapped_addr, pagesize);
		} else { // If just a part of the page is in segment.
			lseek(exec_fd, seg.offset + pos_in_seg, SEEK_SET);
			read(exec_fd, mapped_addr, seg.file_size - pos_in_seg);
		}
	}
	// Now set permisons.
	mprotect(mapped_addr, pagesize, seg.perm);
}

int so_init_loader(void)
{
	int rc;
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = segv_handler;
	sa.sa_flags = SA_SIGINFO;
	sigaction(SIGSEGV, &sa, &oldhandler);
	rc = sigaction(SIGSEGV, &sa, NULL);
	if (rc < 0) {
		perror("sigaction");
		return -1;
	}
	return 0;
}

int so_execute(char *path, char *argv[])
{
	exec = so_parse_exec(path);
	if (!exec)
		return -1;

	// Prepare global variables used for signal handling.
	exec_fd = open(path, O_RDONLY);

	uint32_t pagesz = getpagesize();
	pagesize = pagesz;
	pagesz_bits = 0;
	while (pagesz != 1) {
		pagesz = pagesz >> 1;
		pagesz_bits++;
	}

	/**
	 * Alloc an array of size nr of pages for every segment.
	 * It is done here so that we don't waste time allocating memory
	 * when handling SIGSEGV.
	*/
	for (int i = 0; i < exec->segments_no; i++) {
		int nrpages = exec->segments[i].mem_size >> pagesz_bits;
		exec->segments[i].data = calloc(nrpages, 1);
	}

	so_start_exec(exec, argv);

	close(exec_fd);

	return -1;
}
