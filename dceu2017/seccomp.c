#include <unistd.h>
#include <stdbool.h>
#include <stdio.h>
#include <signal.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <linux/limits.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <linux/seccomp.h>
#include <linux/filter.h>

static int filter_syscall(int syscall_nr)
{
	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, syscall_nr, 0, 1),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
	};

	struct sock_fprog bpf_prog = {
		.len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
		.filter = filter,
	};

	if (syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &bpf_prog) < 0) {
		perror("prctl failed");
		return -1;
	}

	return 0;
}

int main(int argc, char ** argv)
{
	pid_t pid;
	int mode, status;
	int sk_pair[2], sk, ret;
	char c = 'K';

	if (socketpair(PF_LOCAL, SOCK_SEQPACKET, 0, sk_pair)) {
		perror("socketpair");
		return 1;
	}

	pid = fork();
	if (pid < 0) {
		perror("fork");
		return 1;
	}

	if (pid == 0) {

		sk = sk_pair[1];
		close(sk_pair[0]);

		/*
		 * Let's install a few filters separately to make sure the
		 * chaining actually works.
		 */
		if (filter_syscall(__NR_ptrace) < 0)
			_exit(1);

		printf("SECCOMP_MODE_FILTER is enabled\n");

		if (write(sk, &c, 1) != 1) {
			perror("write");
			_exit(1);
		}

		/* We expect to be killed by our policy above. */
		ptrace(PTRACE_TRACEME);

		syscall(__NR_exit, 0);
	}

	sk = sk_pair[0];
	close(sk_pair[1]);

	if ((ret = read(sk, &c, 1)) != 1) {
		perror("read");
		goto err;
	}

	if (waitpid(pid, &status, 0) != pid) {
		perror("waitpid");
		goto err;
	}

	if (WTERMSIG(status) != SIGSYS) {
		printf("expected SIGSYS, got %d", WTERMSIG(status));
		return 1;
	}

	return 0;
err:
	kill(pid, SIGKILL);
	return 1;
}
