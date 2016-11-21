#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>

/* define logging macros to print diagnostics at different levels to
 * stderr. Accepts printf-style format strings via the 'string'
 * function defined below
 */
#define LOG(lvl, ...) \
	do { \
		fprintf(stderr, "%ld measure " lvl " %s\n", time(NULL),	\
			string(__VA_ARGS__));				\
	} while (0)

/* INFO is for informational messages under normal operation */
#define INFO(...) LOG("INFO", __VA_ARGS__)
/* WARNING is used to signal anormal events which are non-fatal */
#define WARNING(...) LOG("ERROR",__VA_ARGS__)
/* ERROR is used to signal fatal anormal events. Exiting the program
 * is handled outside of this macro
 */
#define ERROR(...) LOG("ERROR", __VA_ARGS__)

/* CRITICAL is for fatal errors where the program must abort
 * immediately (e.g.: out of memory). It accepts a normal string
 * buffer (i.e. not a format string). This macro handles the exit.
 */
#define CRITICAL(msg) \
	do { \
		fprintf(stderr, "%ld measure CRITICAL %s\n", time(NULL), msg); \
		exit(EXIT_FAILURE);					\
	} while (0)


/* kill the program via CRITICAL if malloc fails */
void* xmalloc(size_t nbytes)
{
	void *ptr = malloc(nbytes);

	/* malloc can return NULL if 0 bytes were requested, so check
	 * for this edge case also
	 */
	if (nbytes > 0 && !ptr) {
		CRITICAL("out of memory");
	}
	return ptr;
}

char* string(const char *fmt, ...)
{
	/* First, count the required buffer length.
	 * vsnprintf(char *str, size_t size, ...) doesn't write more
	 * than `size` characters in `str` and returns the number of
	 * characters that the final string would contain after
	 * printing, even if it gets truncated. So, calling it with a
	 * size of 0 will return the required buffer length.
	 */
	va_list fmtargs;
	va_start(fmtargs, fmt);
	size_t len = vsnprintf(NULL, 0, fmt, fmtargs);
	va_end(fmtargs);
	
	/* increment len to account for terminating byte */
	char * str = xmalloc(++len);

	/* Then print into the output string */
	va_start(fmtargs, fmt);
	vsnprintf(str, len, fmt, fmtargs);
	va_end(fmtargs);

	return str;
}


/* Redirect stdin, stdout, stderr to /dev/null */
void quiet()
{
	const char *msg = NULL;

	int devnull = open("/dev/null", O_RDWR);
	if (devnull < 0) {
		msg = "open(\"/dev/null\")";
		goto _error;
	}
	
	if (dup2(devnull, STDIN_FILENO) < 0) {
		msg = "dup2(STDIN)";
		goto _error;
	}
	if (dup2(devnull, STDOUT_FILENO) < 0) {
		msg = "dup2(STDOUT)";
		goto _error;
	}
	if (dup2(devnull, STDERR_FILENO) < 0) {
		msg = "dup2(STDERR)";
		goto _error;
	}
	if (close(devnull) < 0) {
		/* something went terribly wrong as the open and dup2
		 * calls succeeded. We also don't have stdout or
		 * stderr to send diagnostics. For now, just kill the
		 * process and let a waitid call in the parent catch
		 * the failure.
		 *
		 * TODO: find better strategy
		 */
		CRITICAL("");
	}

	return;
	
_error:
	ERROR("%s: %s", msg, strerror(errno));
	exit(EXIT_FAILURE);
}


int main(int argc, char * const * argv)
{
 	/* parse argv */
	if (argc < 2) {
		ERROR("too few arguments (usage: measure <command line>)");
		return(EXIT_FAILURE);
	}

	const char *cmd = argv[1];
	char * const * cmd_argv = &argv[1];

	/* launch the command to profile */
	pid_t child_pid = fork();
	if (child_pid == 0) {
		/* inside child process */
		long ptrace_rc = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
		if (ptrace_rc < 0) {
			ERROR("PTRACE_TRACEME: %s", strerror(errno));
			return EXIT_FAILURE;
		}
		
		/* Suppress input/output */
		quiet();
			
		/* launch the command */
		int exec_rc = execvp(cmd, cmd_argv);
		if (exec_rc < 0) {
			ERROR("execvp: %s", strerror(errno));
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
		ERROR("waitid: %s", strerror(errno));
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
			INFO("traced process has exited with status=%d", infop.si_status);
			tracee_alive = false;
			break;
		case CLD_KILLED:
		case CLD_DUMPED:
			WARNING("traced process has crashed");
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
		        CRITICAL("reached unreachable code\n");
		}
	}

	return EXIT_SUCCESS;
}
