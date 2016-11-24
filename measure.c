#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>

/* TODO: change the name */
struct KeyValue {
	unsigned long long int key;
	unsigned long long int key_max;
	char *value;
};

struct SymbolTable {
	size_t size;
	struct KeyValue *table;
};

struct SymbolCount {
	char *name;
	size_t count;
};

int compar_sym_count(const void * ptr1, const void * ptr2)
{
	/* For use with qsort */
	
	struct SymbolCount *sym1 = (struct SymbolCount *) ptr1;
	struct SymbolCount *sym2 = (struct SymbolCount *) ptr2;

        /* We want reverse sorting */
	return sym2->count - sym1->count;
}
	
struct CountTable {
	size_t size;
	size_t capacity;
	struct SymbolCount *data;
};

struct CountTable count_table(void)
{
	struct CountTable tbl;
	tbl.size = 0;
	tbl.capacity = 0;
	tbl.data = NULL;
	return tbl;
}

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
#define WARNING(...) LOG("WARNING",__VA_ARGS__)
/* ERROR is used to signal fatal anormal events. Exiting the program
 * is handled by this macro
 */
#define ERROR(...) do { LOG("ERROR", __VA_ARGS__); exit(EXIT_FAILURE); } while (0)

/* CRITICAL is for fatal errors where the program must abort
 * immediately (e.g.: out of memory). It accepts a normal string
 * buffer (i.e. not a format string). This macro handles the exit.
 */
#define CRITICAL(msg) \
	do { \
		fprintf(stderr, "%ld measure CRITICAL %s\n", time(NULL), msg); \
		exit(EXIT_FAILURE);					\
	} while (0)



/* kill the program via CRITICAL if allocation fails */
void* xalloc(void *ptr, size_t nbytes)
{
	ptr = realloc(ptr, nbytes);

	/* realloc can return NULL if 0 bytes were requested, so check
	 * for this edge case also
	 */
	if (nbytes > 0 && !ptr) {
		CRITICAL("out of memory");
	}
	return ptr;
}


void *xmalloc(size_t nbytes)
{
	return xalloc(NULL, nbytes);
}


/* Basic safeguard against null pointer free */
#define FREE(ptr) do { if (ptr) { free(ptr); ptr = NULL; } } while (0)


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

struct Config {
	const char *output_path;
	double sampling_period;
        const char *cmd;
	char * const * cmd_argv;
};

/* TODO add -h option */
struct Config get_config(int argc, char * const * argv)
{
	struct Config cfg;
	cfg.output_path = "/dev/stdout";
	cfg.sampling_period = 0.001;

	/* Turn off the getopt error messages */
	opterr = 0;

	/* Parse the argv */
	int opt;
	while ((opt = 	getopt(argc, argv, "+:p:o:")) != -1) {
		switch (opt) {
		case 'p':
			/* Only way to check parsing failure here is to set errno to 0
			   and check it after the strtod call */
			errno = 0;
			cfg.sampling_period = strtod(optarg, NULL);
			if (errno != 0 || cfg.sampling_period <= 0) {
				/* reject null and negative periods */
				ERROR("Invalid argument for -p: %s\n", optarg);
			}
			break;
		case 'o':
			cfg.output_path = optarg;
			break;
		case '?':
			ERROR("unrecognized option: -%c", optopt);
		case ':':
			ERROR("missing argument for -%c", optopt);
		default:
			/* unreachable */
			CRITICAL("reached unreachable code in get_config");
		}
	}

	/* Check if a command was specified */
	if (!argv[optind]) {
		ERROR("too few arguments (usage: measure [-p <sampling period] [-o <output path>] <command line>)");
	}
	
	/* Found a command */
	cfg.cmd = argv[optind];
	cfg.cmd_argv = &argv[optind];

	return cfg;
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
		 */
		CRITICAL("");
	}

	return;
	
_error:
	ERROR("%s: %s", msg, strerror(errno));
}


void count_symbol(struct CountTable *tbl, char *name)
{
	for (size_t i = 0; i < tbl->size; i++) {
		if (strcmp(tbl->data[i].name, name) == 0) {
			/* found it!  */
			tbl->data[i].count += 1;
			return;
		}
	}

	/* If we get here, the symbol wasn't found in the table so it
	 * has to be appended. First, make sure there is enough room */
	while (tbl->size >= tbl->capacity) {
		tbl->capacity = (tbl->capacity == 0)? 256 : tbl->capacity * 2;
		tbl->data = xalloc(tbl->data, tbl->capacity * sizeof(struct SymbolCount));
	}

	/* Then append the symbol with a count of 1. Since the name
	 *  buffer may be reused outside, copy it in the table.
	 */
	tbl->data[tbl->size].name = xmalloc(strlen(name) + 1);
	strcpy(tbl->data[tbl->size].name, name);
	tbl->data[tbl->size].count = 1;
	tbl->size += 1;
}		


struct SymbolTable get_symbol_table(const char *path)
{
	FILE *stream = NULL;
	char *line = NULL;
	size_t len = 0;
	ssize_t read;

	struct SymbolTable table;
	table.size = 256;
	table.table = xmalloc(sizeof(struct KeyValue) * table.size);

	/* TODO: quiet this stream, provide own diagnostic in case of error */
	stream = popen(string("nm --numeric-sort %s", path), "r");
	if (stream == NULL) {
		exit(EXIT_FAILURE);
	}
	
	size_t count = 0;
	while ((read = getline(&line, &len, stream)) != -1) {

		/* lines are expected to be in the format:
		 * <address> <type> <symbol>
		 */
		char *addr_str = strtok(line, " \n");
		char *type_str = strtok(NULL, " \n");
		char *symbol_str = strtok(NULL, " \n");
		if (!addr_str || !type_str || !symbol_str) {
			WARNING("malformed line in `nm` output: %s", line);
			continue;
		}

		/* make sure the table is big enough */
		while (count >= table.size) {
			table.size *= 2;
			table.table = xalloc(table.table, sizeof(struct KeyValue) * table.size);
		}

		/* The only reliable way to check for failure here is
		 * to set errno to 0 before and checking it after
		 */
		errno = 0;
		unsigned long long int addr = strtoull(addr_str, NULL, 16);
		if (errno != 0) {
			exit(EXIT_FAILURE);
		}
		
		/* The line pointer gets reused so the symbol string
		 * must be copied 
		 */
		table.table[count].value = xmalloc(strlen(symbol_str) + 1);
		strcpy(table.table[count].value, symbol_str);
		/* The address has already been parsed */
		table.table[count].key = addr;
		
		count += 1;
	}

	/* Shrink the table to exact size */
	table.size = count;
	xalloc(table.table, table.size);

	/* fill key_max fields */
	for (size_t i = 0; i < table.size; i++) {
		table.table[i].key_max =
			(i == table.size - 1)?
			UINT64_MAX :
			table.table[i + 1].key;
	}

	/* cleanup */
	FREE(line);
	if (pclose(stream) < 0) {
		ERROR("pclose: %s", strerror(errno));
	}

	return table;
}

char * get_symbol(struct SymbolTable *table, unsigned long long address)
{
	/* Use binary search to get the symbol name */
	
	size_t imin = 0;
	size_t imax = table->size;
	char *symbol = NULL;
	
	while (!symbol) {

		if (imax < imin) {
			/* found no symbols. This should not
			 * happen. If it does, this is a bug, so treat
			 * it as a failure 
			 */
			CRITICAL(string("no symbols found for address %llx", address));
			exit(EXIT_FAILURE);
		}

		size_t i = (imax + imin) / 2;

		if (address < table->table[i].key) {
			/* address is lower. Upper bound is excluded so 
                         * no need to decrement i 
			 */ 
			imax = i;
		} else if (address >= table->table[i].key_max) {
			/* address is higher. Lower bound is included so 
                         * increment i by 1
			 */ 
			imin = i + 1;
		} else {
			/* got it */
			symbol = table->table[i].value;
		}
	}

	return symbol;
}

	      


int main(int argc, char * const * argv)
{
	int rc = EXIT_SUCCESS;

 	/* parse argv */
	struct Config cfg = get_config(argc, argv);

	/* get the symbol table */
	struct SymbolTable symbols = get_symbol_table(cfg.cmd);
	if (symbols.size > 0) {
		INFO("found %d symbols", symbols.size);
	} else {
		ERROR("no symbols found");
	}

	/* launch the command to profile */
	pid_t child_pid = fork();
	if (child_pid == 0) {
		/* inside child process */
		long ptrace_rc = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
		if (ptrace_rc < 0) {
			ERROR("PTRACE_TRACEME: %s", strerror(errno));
		}
		
		/* Suppress input/output */
		quiet();
			
		/* launch the command */
		int exec_rc = execvp(cfg.cmd, cfg.cmd_argv);
		if (exec_rc < 0) {
			ERROR("execvp: %s", strerror(errno));
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
	}

	/* kill the tracee when we exit */
	ptrace(PTRACE_SETOPTIONS, child_pid, NULL, PTRACE_O_EXITKILL);
	
	/* restart the tracee right now to simplify the tracing logic
	 * below 
	 */
	INFO("Beginning tracing");
	ptrace(PTRACE_CONT, child_pid, NULL, NULL);

	struct user_regs_struct regs;
	struct CountTable counts = count_table();
	
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
			char *symbol = get_symbol(&symbols, regs.rip);
			count_symbol(&counts, symbol);

			/* restard the tracee and let it work for a short interval */
			ptrace(PTRACE_CONT, child_pid, NULL, NULL);
			sleep(cfg.sampling_period);
			break;
		default:
			/* unreachable */
		        CRITICAL("reached unreachable code\n");
		}
	}

	/* Tracing is finished! Now sort the counts from high to low */
	INFO("Tracing finished");
	qsort(counts.data, counts.size, sizeof(struct SymbolCount), compar_sym_count);
	/* and print them to output file */
	INFO("Dumping the symbol counts to %s", cfg.output_path);
	FILE *out = fopen(cfg.output_path, "w");
	if (!out) {
		WARNING("unable to open output file %s: %s", cfg.output_path, strerror(errno));
		WARNING("Falling back to stdout");
		rc = EXIT_FAILURE;
		out = stdout;
	}
	for (size_t i = 0; i < counts.size; i++)
		fprintf(out, "%010lu\t%s\n", counts.data[i].count, counts.data[i].name);
	fclose(out);

	return rc;
}
