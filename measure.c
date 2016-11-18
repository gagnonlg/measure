#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <time.h>
#include <unistd.h>

int main(int argc, char * const * argv)
{
	/* parse argv */
	if (argc < 2) {
		fprintf(stderr, "usage: measure <command line>\n");
		return(EXIT_FAILURE);
	}

	const char *cmd = argv[1];
	char * const * cmd_argv = &argv[2];

	/* launch the command to profile */
	pid_t child_pid = fork();
	if (child_pid == 0) {
		/* inside child process */
		long ptrace_rc = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
		if (ptrace_rc < 0) {
			fprintf(stderr, "error: PTRACE_TRACEME: %s\n", strerror(errno));
			return EXIT_FAILURE;
		}
		int exec_rc = execvp(cmd, cmd_argv);
		if (exec_rc < 0) {
			fprintf(stderr, "error: execvp: %s\n", strerror(errno));
			return EXIT_FAILURE;
		}
	}
		
	/* back in the parent. When the chidl calls PTRACE_TRACEME, it
	 * traps at any exec* call. We must observe this trap before
	 * configuring and beginning to trace the process 
	 */
	siginfo_t infop;
	int wait_rc = waitid(P_PID, child_pid, &infop, WSTOPPED);
	if (wait_rc < 0) {
		fprintf(stderr, "error: waitid: %s\n", strerror(errno));
		return EXIT_FAILURE;
	}

	/* kill the tracee when we exit */
	ptrace(PTRACE_SETOPTIONS, child_pid, NULL, PTRACE_O_EXITKILL);
	
	/* restart the tracee right now to simplify the tracing logic
	 * below 
	 */
	ptrace(PTRACE_CONT, child_pid, NULL, NULL);

	struct user_regs_struct regs;
	
	bool tracee_alive = true;
	while (tracee_alive) {
		kill(child_pid, SIGSTOP);
		waitid(P_PID, child_pid, &infop, WSTOPPED | WEXITED);
		
		switch (infop.si_code) {
		case CLD_EXITED:
			fprintf(stderr, "info: traced process has exited with status=%d\n", infop.si_status);
			tracee_alive = false;
			break;
		case CLD_KILLED:
		case CLD_DUMPED:
			fprintf(stderr, "info: traced process has crashed\n");
			tracee_alive = false;
			break;
		case CLD_STOPPED:
		case CLD_TRAPPED:
			/* sample the instruction pointer */
			ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
			fprintf(stdout, "%llx\n", regs.rip);

			/* restard the tracee and let it work for a short interval */
			ptrace(PTRACE_CONT, child_pid, NULL, NULL);
			sleep(0.0001);
			break;
		default:
			/* unreachable */
			fprintf(stderr, "critical: reached unreachable code\n");
			return EXIT_FAILURE;
		}
	}

	return EXIT_SUCCESS;
}
