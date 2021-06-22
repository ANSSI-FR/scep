// SPDX-License-Identifier: GPL-2.0-only
/*
 * VServer Linux security module.
 *
 * Author: Philippe Trebuchet <philippe.trebuchet@ssi.gouv.fr>
 *
 * Copyright (C) 2021 ANSSI
 */

#define _GNU_SOURCE #include "../kselftest_harness.h"
#include <sys/capability.h>
#include<linux/types.h>
#include<errno.h>
#include<sys/ptrace.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<fcntl.h>
#include<sys/wait.h>
#include<unistd.h>
#include<stdio.h>

FIXTURE(hierarchy) { };

FIXTURE_VARIANT(hierarchy) {
	const bool same_context;
};

FIXTURE_VARIANT_ADD(hierarchy, same_context_test) {
	.same_context = true,
};

FIXTURE_VARIANT_ADD(hierarchy, different_context_test) {
	.same_context = false,
};

FIXTURE_SETUP(hierarchy)
{ }

FIXTURE_TEARDOWN(hierarchy)
{ }


TEST_F(hierarchy, ptrace)
{

	pid_t child, parent;
	int status;
	int pipe_parent[2];
	long ret;

	parent = getpid();
	ASSERT_EQ(0, pipe2(pipe_parent, O_CLOEXEC));

	child = fork();
	ASSERT_LE(0, child);
	if (child == 0) {
		char buf_child;

		ASSERT_EQ(0, close(pipe_parent[1]));

		/*  Synchronization for letting the parent go to the desired context*/
		ASSERT_EQ(1, read(pipe_parent[0], &buf_child, 1));

		/* Tests PTRACE_ATTACH on the parent. */
		ret = ptrace(PTRACE_ATTACH, parent, NULL, 0);
		if (variant->same_context == true)
			EXPECT_EQ(0, ret);
		else
			EXPECT_EQ(-EPERM, ret);
		if (ret == 0) {
			ASSERT_EQ(parent, waitpid(parent, &status, 0));
			ASSERT_EQ(1, WIFSTOPPED(status));
			ASSERT_EQ(0, ptrace(PTRACE_DETACH, parent, NULL, 0));
		}

		/* Tests PTRACE_TRACEME.  Should Work in all cases*/
		ret = ptrace(PTRACE_TRACEME);
		EXPECT_EQ(0, ret);

		/*
		 * Signals that the PTRACE_ATTACH test is done and the
		 * PTRACE_TRACEME test is ongoing.
		 */
		_exit(_metadata->passed ? EXIT_SUCCESS : EXIT_FAILURE);
	} else { /* Parent process */
		ASSERT_EQ(0, close(pipe_parent[0]));
		if (variant->same_context == false) {
			char cgbuf[1024], cgmountpt[1024];
			int fd, pathlen, cglen;
			FILE *pfd;

			pfd = popen("sed -n 's/cgroup.* \\([^ ]*\\) cgroup2.*/\\1/p' /proc/self/mounts", "r");
			pathlen = fscanf(pfd, "%1024s", cgmountpt);
			fd = open("/proc/self/cgroup", O_RDONLY);
			cglen = read(fd, cgbuf, 1024);
			write(0, cgbuf, pathlen);
			strncpy(cgmountpt, cgbuf+3, cglen);
			strncpy(cgmountpt+pathlen+cglen-3, "/plop", 6);
			mkdir(cgmountpt, 0700);
		}

		/* Signals to the child that the parent is ok to proceed */
		ASSERT_EQ(1, write(pipe_parent[1], ".", 1));

		/*
		 * Waits for the child to test PTRACE_ATTACH on the parent and start
		 * testing PTRACE_TRACEME.
		 */

		/* Wait for the child to end. */
		ASSERT_EQ(child, waitpid(child, &status, 0));
		if (WIFSIGNALED(status) || !WIFEXITED(status) ||
				WEXITSTATUS(status) != EXIT_SUCCESS)
			_metadata->passed = 0;
	}
}

TEST_HARNESS_MAIN
