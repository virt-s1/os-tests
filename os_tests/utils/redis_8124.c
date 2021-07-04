#include <assert.h>
#include <stdio.h>
#include <sys/fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

#define SIZE1 (500*1024*1024)
#define SIZE2 (500*1024*1024)

int main()
{
	int ret, i;
	volatile char *p, *p2;

	p = mmap(NULL, SIZE1, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	assert(p != MAP_FAILED);

	for (i = 0; i < SIZE1; i += 4096)
		p[i] = 42;

	/*
	 * madvise(MADV_FREE) marks the page for lazy reclamation. This means
	 * that *p can be:
	 *   - 42: the userspace should not rely on that value. It means that
	 *         Linux did not reclaim the page yet.
	 *   - 0:  Linux has reclaimed the original page and replaced it with
	 *         the zero page.
	 */
	ret = madvise((void *) p, SIZE1, MADV_FREE);
	assert(!ret);
	/*
	 * Writing a value to a MADV_FREE page, cancels the effects of it.
	 * Linux will not try to reclaim this page.
	 */
	*p = 43;
	/*
	 * The bug happens in fork(). The PTE of p is hw_dirty=1, sw_dirty=0.
	 * fork() calls copy_one_pte() which calls pte_wrprotect() which
	 * changes the PTE for the child to hw_dirty=0, sw_dirty=0. 1 of the 2
	 * PTEs that point to p has lost track of the fact that the page has
	 * been modified and should not be reclaimed.
	 */
	if (fork()) {
		/*
		 * Luckily, copy_one_pte() uses ptep_set_wrprotect() for the
		 * PTE of the parent which makes the PTE hw_dirty=0,
		 * sw_dirty=1. The following madvise changes the PTE to
		 * hw_dirty=0, sw_dirty=0. The page can now be reclaimed.
		 */
		ret = madvise((void *) p, SIZE1, MADV_FREE);
		assert(!ret);

		p2 = mmap(NULL, SIZE2, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
		assert(p2 != MAP_FAILED);
		/*
		 * Try to force page reclamation. If this step fails, then the
		 * results of the PoC are wrong.
		 */
		for (i = 0; i < SIZE2; i += 4096)
			p2[i] = 44;
		if (*p)
			printf("PoC failed to reclaim pages. ignore results.\n");
		sleep(2);
	} else {
		sleep(2);
		if (!*p)
			printf("Your kernel has a bug.\n");
		else
			printf("Your kernel looks fine.\n");
	}

	return 0;
}
