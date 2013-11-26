#include "nm_util.h"
#include <sys/wait.h>

#define MAX_VARS 100

char *variables[MAX_VARS];
int curr_var;

#define VAR_FAILED ((void*)1)

char *firstarg(char *buf)
{
	int v;
	char *arg = strtok(buf, " \t\n");
	char *ret;
	if (!arg)
		return NULL;
	if (arg[0] != '$' && arg[0] != '?')
		return arg;
	v = atoi(arg+1);
	if (v < 0 || v >= MAX_VARS)
		return "";
	ret = variables[v];
	if (ret == NULL)
		return "NULL";
	if (ret == VAR_FAILED) {
		printf("reading failed var, exit\n");
		exit(1);
	}
	if (arg[0] == '?')
		return ret;
	ret = rindex(ret, '=') + 1;
	return ret;
}

char *nextarg()
{
	return firstarg(NULL);
}

char *restofline()
{
	return strtok(NULL, "\n");
}

void resetvar(int v, char *b)
{
	if (variables[v] != VAR_FAILED)
		free(variables[v]);
	variables[v] = b;
}

#define outecho(format, args...) \
	do {\
		printf("%u:%lu: " format "\n", getpid(), (unsigned long) pthread_self(), ##args);\
		fflush(stdout);\
	} while (0)

#define output(format, args...) \
	do {\
		resetvar(curr_var, (char*)malloc(1024));\
		snprintf(variables[curr_var], 1024, format, ##args);\
		outecho(format, ##args);\
	} while (0)		

#define output_err(ret, format, args...)\
	do {\
		if (ret < 0) {\
			resetvar(curr_var, VAR_FAILED);\
			outecho(format, ##args);\
			outecho("error: %s", strerror(errno));\
		} else {\
			output(format, ##args);\
		}\
	} while (0)
	
struct chan {
	FILE *out;
	pid_t pid;
	pthread_t tid;
};

int chan_search_free(struct chan* c[], int max)
{
	int i;

	for (i = 0; i < max && c[i]; i++)
		;

	return i;
}

void chan_clear_all(struct chan *c[], int max)
{
	int i;

	for (i = 0; i < max; i++) {
		if (c[i]) {
			fclose(c[i]->out);
			free(c[i]);
			c[i] = NULL;
		}
	}
}

int last_fd = -1;
size_t last_memsize = 0;
void* last_mmap_addr = NULL;
char* last_access_addr = NULL;


void do_open()
{
	last_fd = open("/dev/netmap", O_RDWR);
	output_err(last_fd, "open(\"/dev/netmap\", O_RDWR)=%d", last_fd);
}

void do_close()
{
	int ret, fd;
	char *arg = nextarg();
	fd = arg ? atoi(arg) : last_fd;
	ret = close(fd);
	output_err(ret, "close(%d)=%d", fd, ret);
}

void parse_nmr_config(char* w, struct nmreq *nmr)
{
	char *tok;
	int i, v;

	nmr->nr_tx_rings = nmr->nr_rx_rings = 0;
	nmr->nr_tx_slots = nmr->nr_rx_slots = 0;
	if (w == NULL || ! *w)
		return;
	for (i = 0, tok = strtok(w, ","); tok; i++, tok = strtok(NULL, ",")) {
		v = atoi(tok);
		switch (i) {
		case 0:
			nmr->nr_tx_slots = nmr->nr_rx_slots = v;
			break;
		case 1:
			nmr->nr_rx_slots = v;
			break;
		case 2:
			nmr->nr_tx_rings = nmr->nr_rx_rings = v;
			break;
		case 3:
			nmr->nr_rx_rings = v;
			break;
		default:
			break;
		}
	}
}

void do_getinfo()
{
	struct nmreq nmr;
	int ret;
	char *arg, *name;
	int fd;

	bzero(&nmr, sizeof(nmr));
	nmr.nr_version = NETMAP_API;

	name = nextarg();
	if (name) {
		strncpy(nmr.nr_name, name, sizeof(nmr.nr_name));
	} else {
		name = "any";
	}

	arg = nextarg();
	if (!arg) {
		fd = last_fd;
		goto doit;
	}
	fd = atoi(arg);

	arg = nextarg();
	parse_nmr_config(arg, &nmr);

doit:
	ret = ioctl(fd, NIOCGINFO, &nmr);
	last_memsize = nmr.nr_memsize;
	output_err(ret, "ioctl(%d, NIOCGINFO) for %s: %s memsize=%zu",
		fd, name, (nmr.nr_ringid & NETMAP_PRIV_MEM ? "PRIVATE" : "GLOBAL"), last_memsize);
}


void do_regif()
{
	struct nmreq nmr;
	int ret;
	char *arg, *name;
	int fd;

	bzero(&nmr, sizeof(nmr));
	nmr.nr_version = NETMAP_API;

	name = nextarg();
	if (!name) {
		output("missing ifname");
		return;
	}
	strncpy(nmr.nr_name, name, sizeof(nmr.nr_name));

	arg = nextarg();
	if (!arg) {
		fd = last_fd;
		goto doit;
	}
	fd = atoi(arg);

	arg = nextarg();
	parse_nmr_config(arg, &nmr);

doit:
	ret = ioctl(fd, NIOCREGIF, &nmr);
	last_memsize = nmr.nr_memsize;
	output_err(ret, "ioctl(%d, NIOCREGIF) for %s: %s memsize=%zu",
		fd, name, (nmr.nr_ringid & NETMAP_PRIV_MEM ? "PRIVATE" : "GLOBAL"), last_memsize);
}


volatile char tmp1;
void do_access()
{
	char *arg = nextarg();
	char *p;
	if (!arg) {
		if (!last_access_addr) {
			output("missing address");
			return;
		}
		p = last_access_addr;
	} else {
		p = (char *)strtoul((void *)arg, NULL, 0);
	}
	last_access_addr = p + 4096;
	tmp1 = *p;
}

void do_mmap()
{
	size_t memsize;
	off_t off = 0;
	int fd;
	char *arg;

	arg = nextarg();
	if (!arg) {
		memsize = last_memsize;
		fd = last_fd;
		goto doit;
	}
	memsize = atoi(arg);
	arg = nextarg();
	if (!arg) {
		fd = last_fd;
		goto doit;
	}
	fd = atoi(arg);
	arg = nextarg();
	if (arg) {
		off = (off_t)atol(arg);
	}
doit:
	last_mmap_addr = mmap(0, memsize,
			PROT_WRITE | PROT_READ,
			MAP_SHARED, fd, off);
	if (last_access_addr == NULL)
		last_access_addr = last_mmap_addr;
	output_err(last_mmap_addr == MAP_FAILED ? -1 : 0,
		"mmap(0, %zu, PROT_WRITE|PROT_READ, MAP_SHARED, %d, %jd)=%p",
		memsize, fd, (intmax_t)off, last_mmap_addr);

}

void do_munmap()
{
	void *mmap_addr;
	size_t memsize;
	char *arg;
	int ret;

	arg = nextarg();
	if (!arg) {
		mmap_addr = last_mmap_addr;
		memsize = last_memsize;
		goto doit;
	}
	mmap_addr = (void*)strtoul(arg, NULL, 0);
	arg = nextarg();
	if (!arg) {
		memsize = last_memsize;
		goto doit;
	}
	memsize = (size_t)strtoul(arg, NULL, 0);
doit:
	ret = munmap(mmap_addr, memsize);
	output_err(ret, "munmap(%p, %zu)=%d", mmap_addr, memsize, ret);
}

void do_poll()
{
	/* timeout fd fd... */
	nfds_t nfds = 0, allocated_fds = 10, i;
	struct pollfd *fds;
	int timeout = 500; /* 1/2 second */
	char *arg;
	int ret;

	arg = nextarg();
	if (arg)
		timeout = atoi(arg);
	fds = malloc(allocated_fds * sizeof(struct pollfd));
	if (fds == NULL) {
		output_err(-1, "out of memory");
		return;
	}
	while ( (arg = nextarg()) ) {
		if (nfds >= allocated_fds) {
			allocated_fds *= 2;
			fds = realloc(fds, allocated_fds * sizeof(struct pollfd));
			if (fds == NULL) {
				output_err(-1, "out of memory");
				return;
			}
		}
		fds[nfds].fd = atoi(arg);
		fds[nfds].events = POLLIN;
		nfds++;
	}
	ret = poll(fds, nfds, timeout);
	for (i = 0; i < nfds; i++) {
		output("poll(%d)=%s%s%s%s%s", fds[i].fd, 
			(fds[i].revents & POLLIN) ? "IN  " : "-   ",
			(fds[i].revents & POLLOUT)? "OUT " : "-   ",
			(fds[i].revents & POLLERR)? "ERR " : "-   ",
			(fds[i].revents & POLLHUP)? "HUP " : "-   ",
			(fds[i].revents & POLLNVAL)?"NVAL" : "-");

	}
	output_err(ret, "poll(...)=%d", ret);
	free(fds);
}

void
do_txsync()
{
	char *arg = nextarg();
	int fd = arg ? atoi(arg) : last_fd;
	int ret = ioctl(fd, NIOCTXSYNC, NULL);
	output_err(ret, "ioctl(%d, NIOCTXSYNC)=%d", fd, ret);
}

void
do_rxsync()
{
	char *arg = nextarg();
	int fd = arg ? atoi(arg) : last_fd;
	int ret = ioctl(fd, NIOCRXSYNC, NULL);
	output_err(ret, "ioctl(%d, NIOCRXSYNC)=%d", fd, ret);
}

void
do_expr()
{
	unsigned long stack[11];
	int top = 10;
	char *arg;
	int err = 0;

	stack[10] = ULONG_MAX;
	while ( (arg = nextarg()) ) {
		errno = 0;
		char *rest;
		unsigned long n = strtoul(arg, &rest, 0);
		if (!errno && rest != arg) {
			if (top <= 0) {
				err = -1;
				break;
			}
			stack[--top] = n;
			continue;
		}
		if (top <= 8) {
			unsigned long n1 = stack[top++];
			unsigned long n2 = stack[top++];
			unsigned long r = 0;
			switch (arg[0]) {
			case '+':
				r = n1 + n2;
				break;
			case '-':
				r = n1 - n2;
				break;
			case '*':
				r = n1 * n2;
				break;
			case '/':
				if (n2)
					r = n1 / n2;
				else {
					errno = EDOM;
					err = -1;
				}
				break;
			default:
				err = -1;
				break;
			}
			stack[--top] = r;
			continue;
		}
		err = -1;
		break;
	}
	output_err(err, "expr=%lu", stack[top]);
}
				
			

void
do_echo()
{
	char *arg;
	for (arg = nextarg(); arg; arg = nextarg()) {
		printf("%s\n", arg);
	}
}

void
do_vars()
{
	int i;
	for (i = 0; i < MAX_VARS; i++) {
		const char *v = variables[i];
		if (v == NULL)
			continue;
		printf("?%d\t%s\n", i, v == VAR_FAILED ?  "FAILED" : v);
	}
}

struct cmd_def {
	const char *name;
	void (*f)(void);
};


struct cmd_def commands[] = {
	{
		.name = "open",
		.f    = do_open,
	},
	{
		.name = "close",
		.f    = do_close,
	},
	{
		.name = "getinfo",
		.f    = do_getinfo,
	},
	{
		.name = "regif",
		.f    = do_regif,
	},
	{
		.name = "mmap",
		.f    = do_mmap,
	},
	{	.name = "access", .f = do_access, },
	{
		.name = "munmap",
		.f    = do_munmap,
	},
	{
		.name = "poll",
		.f    = do_poll,
	},
	{
		.name = "txsync",
		.f    = do_txsync,
	},
	{
		.name = "rxsync",
		.f    = do_rxsync,
	},
	{
		.name = "expr",
		.f    = do_expr,
	},
	{
		.name = "echo",
		.f    = do_echo,
	},
	{
		.name = "vars",
		.f    = do_vars,
	}
};

const int N_CMDS = sizeof(commands) / sizeof(struct cmd_def);

int find_command(const char* cmd)
{
	int i;
	for (i = 0; i < N_CMDS; i++) {
		if (strcmp(commands[i].name, cmd) == 0)
			break;
	}
	return i;
}

#define MAX_CHAN 10

void prompt()
{
	if (isatty(STDIN_FILENO)) {
		printf("> ");
	}
}

struct chan *channels[MAX_CHAN];

void*
thread_cmd_loop(void *arg)
{
	char buf[1024];
	FILE *in = (FILE*)arg;

	while (fgets(buf, 1024, in)) {
		char *cmd; 
		int i;

		cmd = firstarg(buf);
		i = find_command(cmd);
		if (i < N_CMDS) {
			commands[i].f();
			continue;
		}
		output("unknown cmd %s", cmd);
	}
	fclose(in);
	return NULL;
}

void do_exit()
{
	output("quit");
}

void
cmd_loop()
{
	char buf[1024];
	int i;
	struct chan *c;

	bzero(channels, sizeof(*channels) * MAX_CHAN);

	atexit(do_exit);

	for (prompt(); fgets(buf, 1024, stdin); prompt()) {
		char *cmd;
		int slot;

		cmd = firstarg(buf);
		if (!cmd)
			continue;
		if (cmd[0] == '@') {
			curr_var = atoi(cmd + 1);
			if (curr_var < 0 || curr_var >= MAX_VARS)
				curr_var = 0;
			cmd = nextarg();
			if (!cmd)
				continue;
		} else {
			curr_var = 0;
		}
		
		if (strcmp(cmd, "fork") == 0) {
			int slot = chan_search_free(channels, MAX_CHAN);
			struct chan *c = NULL;
			pid_t pid;
			int p1[2] = { -1, -1};

			if (slot == MAX_CHAN) {
				output("too many channels");
				continue;
			}
			c = channels[slot] = (struct chan*)malloc(sizeof(struct chan));
			if (c == NULL) {
				output_err(-1, "malloc");
				continue;
			}
			bzero(c, sizeof(*c));
			if (pipe(p1) < 0) {
				output_err(-1, "pipe");
				goto clean1;
			}
			c->out = fdopen(p1[1], "w");
			if (c->out == NULL) {
				output_err(-1, "fdopen");
				goto clean1;
			}
			pid = fork();
			switch (pid) {
			case -1:
				output_err(-1, "fork");
				goto clean1;
			case 0:
				fclose(stdin);
				if (dup(p1[0]) < 0) {
					output_err(-1, "dup");
					exit(1);
				}
				close(p1[1]);
				stdin = fdopen(0, "r");
				chan_clear_all(channels, MAX_CHAN);
				goto out;
			default:
				break;
			}
			c->pid = pid;
			close(p1[0]);
			output("fork()=%d slot=%d", pid, slot);
			continue;
		clean1:
			if (c) {
				fclose(c->out);
			}
			close(p1[0]);
			close(p1[1]);
			free(c);
		out:
			continue;
		}
		if (strcmp(cmd, "kill") == 0) {
			int ret;

			cmd = nextarg();
			if (!cmd) {
				output("missing slot");
				continue;
			}
			slot = atoi(cmd);
			if (slot < 0 || slot >= MAX_CHAN || !channels[slot]) {
				output("invalid slot: %s", cmd);
				continue;
			}
			c = channels[slot];
			ret = kill(c->pid, SIGTERM);
			output_err(ret, "kill(%d, SIGTERM)=%d", c->pid, ret);
			if (ret != -1) {
				wait(NULL);
				fclose(c->out);
				free(c);
				channels[slot] = NULL;
			}
			continue;
		}
		if (strcmp(cmd, "thread") == 0) {
			int slot = chan_search_free(channels, MAX_CHAN);
			struct chan *c = NULL;
			pthread_t tid;
			int p1[2] = { -1, -1};
			int ret;
			FILE *in = NULL;
			
			if (slot == MAX_CHAN) {
				output("too many channels");
				continue;
			}
			c = channels[slot] = (struct chan*)malloc(sizeof(struct chan));
			bzero(c, sizeof(*c));
			if (pipe(p1) < 0) {
				output_err(-1, "pipe");
				goto clean2;
			}
			c->out = fdopen(p1[1], "w");
			if (c->out == NULL) {
				output_err(-1, "fdopen");
				goto clean2;
			}
			in = fdopen(p1[0], "r");
			if (in == NULL) {
				output_err(-1, "fdopen");
				goto clean2;
			}
			ret = pthread_create(&tid, NULL, thread_cmd_loop, in);
			output_err(ret, "pthread_create() tid=%lu slot=%d", 
				(unsigned long) tid, slot);
			if (ret < 0)
				goto clean2;
			c->pid = getpid();
			c->tid = tid;
			continue;
		clean2:
			fclose(in);
			fclose(c->out);
			close(p1[0]);
			close(p1[1]);
			free(c);
			continue;
		}
		if (strcmp(cmd, "cancel") == 0) {
			int ret;

			cmd = nextarg();
			if (!cmd) {
				output("missing slot");
				continue;
			}
			slot = atoi(cmd);
			if (slot < 0 || slot >= MAX_CHAN || !channels[slot]) {
				output("invalid slot: %s", cmd);
				continue;
			}
			c = channels[slot];
			fclose(c->out);
			ret = pthread_join(c->tid, NULL);
			output_err(ret, "pthread_join(%lu)=%d", 
				(unsigned long) c->tid, ret);
			if (ret > 0) {
				free(c);
				channels[slot] = NULL;
			}
			continue;
		}
		i = find_command(cmd);
		if (i < N_CMDS) {
			commands[i].f();
			continue;
		}
		slot = atoi(cmd);
		if (slot < 0 || slot > MAX_CHAN || !channels[slot]) {
			output("invalid cmd/slot: %s", cmd);
			continue;
		}
		cmd = restofline();
		if (!cmd) {
			output("missing command");
			continue;
		}
		fprintf(channels[slot]->out, "%s\n", cmd);
		fflush(channels[slot]->out);
		sleep(1);
	}
}

int
main(int argc, char **argv)
{
	(void) argc;
	(void) argv;
	cmd_loop();
	return 0;
}
