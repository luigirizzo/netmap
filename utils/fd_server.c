#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <syslog.h>
#include <unistd.h>

#include <libnetmap.h>

#include "fd_server.h"

struct nmd_entry {
	char if_name[NETMAP_REQ_IFNAMSIZ];
	struct nmport_d *nmd;
	uint8_t is_in_use;
	uint8_t is_open;
};

int foreground = 0;

#define msg(format, ...) do {					\
	if (foreground) {					\
		printf(format, ##__VA_ARGS__);			\
	} else {						\
		syslog(LOG_NOTICE, format, ##__VA_ARGS__);	\
	}							\
} while(0)

#define MAX_OPEN_IF 128
struct nmd_entry entries[MAX_OPEN_IF];
int num_entries = 0;

static void
print_request(struct fd_request *req)
{

	msg("action: %s, if_name: '%s'\n",
	       req->action == FD_GET
	               ? "FD_GET"
	               : req->action == FD_RELEASE
	                         ? "FD_RELEASE"
	                         : req->action == FD_CLOSE ? "FD_CLOSE"
	                                                   : "FD_STOP",
	       req->if_name);
}

struct nmd_entry *
search_des(const char *if_name)
{
	int i;

	// msg("searching %s\n", if_name);
	for (i = 0; i < num_entries; ++i) {
		struct nmd_entry *entry = &entries[i];

		// msg("i=%d, is_open=%d, is_in_use=%d, if_name=%s\n",
		// 	i, entry->is_open, entry->is_in_use, entry->if_name);

		if (entry->is_open == 0) {
			continue;
		}

		if (strncmp(entry->if_name, if_name, IFNAMSIZ) == 0) {
			// msg("finished searching with a match\n");
			return entry;
		}
	}

	// msg("finished searching without a match\n");
	return NULL;
}

struct nmd_entry *
get_free_des(void)
{
	if (num_entries == MAX_OPEN_IF) {
		return NULL;
	}

	return &entries[num_entries++];
}

int
marshal(struct fd_response *res, struct nmd_entry *entry)
{
	if (entry->nmd->hdr.nr_options) {
		msg("options are not supported\n");
		res->result = EOPNOTSUPP;
		return -1;
	}

	// copy the header
	res->hdr = entry->nmd->hdr;
	res->hdr.nr_options = 0;
	res->hdr.nr_body = 0;
	// copy the body
	res->reg = entry->nmd->reg;
	return 0;
}

int
get_fd(const char *if_name, struct fd_response *res)
{
	struct nmd_entry *entry;

	entry = search_des(if_name);
	if (entry != NULL) {
		if (entry->is_in_use == 1) {
			msg("if_name %s is in use\n", if_name);
			res->result = EBUSY;
			return -1;
		}
		if (marshal(res, entry) < 0)
			return -1;
		return entry->nmd->fd;
	}

	entry = get_free_des();
	if (entry == NULL) {
		msg("Out of memory\n");
		res->result = ENOMEM;
		return -1;
	}

	entry->nmd = nmport_open(if_name);
	if (entry->nmd == NULL) {
		msg("Failed to nm_open(%s) with error %d\n", if_name, errno);
		res->result = errno;
		return -1;
	}
	strncpy(entry->if_name, if_name, sizeof(entry->if_name));
	entry->if_name[sizeof(entry->if_name) - 1] = '\0';

	if (marshal(res, entry) < 0)
		return -1;
	res->result = 0;
	entry->is_in_use = 1;
	entry->is_open   = 1;
	return entry->nmd->fd;
}

void
release_fd(const char *if_name, struct fd_response *res)
{
	struct nmd_entry *entry;

	entry = search_des(if_name);
	if (entry == NULL) {
		msg("if_name %s isn't open\n", if_name);
		res->result = ENOENT;
		return;
	}

	entry->is_in_use = 0;
}

void
close_fd(const char *if_name, struct fd_response *res)
{
	struct nmd_entry *entry;

	if (if_name == NULL || strnlen(if_name, NETMAP_REQ_IFNAMSIZ) == 0) {
		res->result = EINVAL;
		return;
	}

	entry = search_des(if_name);
	if (entry == NULL) {
		res->result = ENOENT;
		msg("if_name %s hasn't been opened\n", if_name);
		return;
	}

	nmport_close(entry->nmd);
	res->result = 0;
	entry->is_in_use = 0;
	entry->is_open   = 0;
}

int
send_fd(int socket, int fd, void *buf, size_t buf_size)
{
	union {
		char buf[CMSG_SPACE(sizeof(int))];
		struct cmsghdr align;
	} ancillary;
	struct cmsghdr *cmsg;
	struct iovec iov[1];
	struct msghdr msg;
	int ret;

	iov[0].iov_base = buf;
	iov[0].iov_len  = buf_size;
	memset(&msg, 0, sizeof(struct msghdr));
	msg.msg_iov    = iov;
	msg.msg_iovlen = 1;

	if (fd >= 0) {
		/* We need the ancillary data only when we're sending a file
		 * descriptor, and a file descriptor cannot be negative.
		 */
		msg("sending a file descriptor\n");
		msg.msg_control         = ancillary.buf;
		msg.msg_controllen      = sizeof(ancillary.buf);
		cmsg                    = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level        = SOL_SOCKET;
		cmsg->cmsg_type         = SCM_RIGHTS;
		cmsg->cmsg_len          = CMSG_LEN(sizeof(int));
		memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));
	}

	ret = sendmsg(socket, &msg, 0);
	return ret;
}

int
handle_request(int accept_socket, int listen_socket)
{
	struct fd_response res;
	struct fd_request req;
	int fd = -1;
	int amount;
	int ret;

	memset(&req, 0, sizeof(req));
	amount = recv(accept_socket, &req, sizeof(struct fd_request), 0);
	if (amount == -1) {
		msg("error while receiving the request\n");
		return -1;
	}

	print_request(&req);
	switch (req.action) {
	case FD_GET:
		fd = get_fd(req.if_name, &res);
		break;
	case FD_RELEASE:
		release_fd(req.if_name, &res);
		return 0;
	case FD_CLOSE:
		close_fd(req.if_name, &res);
		return 0;
	case FD_STOP:
		msg("shutting down\n");
		close(listen_socket);
		close(accept_socket);
		exit(EXIT_SUCCESS);
		break;
	default:
		res.result = EOPNOTSUPP;
	}

	ret = send_fd(accept_socket, fd, &res, sizeof(res));
	if (ret == -1) {
		msg("error while sending the response\n");
	}
	return ret;
}

void
main_loop(void)
{
	struct sockaddr_un name;
	int socket_fd;
	int ret;

	msg("starting up.\n");
	if (unlink(SOCKET_NAME) == -1 && errno != ENOENT) {
		msg("error %d during unlink()", errno);
		exit(EXIT_FAILURE);
	}
	socket_fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (socket_fd == -1) {
		msg("error during socket()\n");
		exit(EXIT_FAILURE);
	}

	memset(&name, 0, sizeof(struct sockaddr_un));
	name.sun_family = AF_UNIX;
	strncpy(name.sun_path, SOCKET_NAME, sizeof(name.sun_path) - 1);
	ret = bind(socket_fd, (const struct sockaddr *)&name,
	           sizeof(struct sockaddr_un));
	if (ret == -1) {
		msg("error during bind()\n");
		exit(EXIT_FAILURE);
	}

	ret = listen(socket_fd, 2);
	if (ret == -1) {
		msg("error during listen()");
		exit(EXIT_FAILURE);
	}

	msg("listening\n");
	for (;;) {
		int conn_fd;
		int ret;

		conn_fd = accept(socket_fd, NULL, NULL);
		if (conn_fd == -1) {
			msg("error during accept(), shutting down\n");
			exit(EXIT_FAILURE);
		}

		ret = handle_request(conn_fd, socket_fd);
		if (ret == -1) {
			msg("error while handling a request\n");
		}
		(void)ret;
		close(conn_fd);
	}
}

void
daemonize(void)
{
	pid_t pid;
	int i;

	pid = fork();
	if (pid < 0) {
		exit(EXIT_FAILURE);
	}
	if (pid > 0) {
		exit(EXIT_SUCCESS);
	}

	if (setsid() == -1) {
		exit(EXIT_FAILURE);
	}

	signal(SIGCHLD, SIG_IGN);
	signal(SIGHUP, SIG_IGN);

	pid = fork();
	if (pid < 0) {
		exit(EXIT_FAILURE);
	}
	if (pid > 0) {
		exit(EXIT_SUCCESS);
	}

	umask(0);

	if (chdir("/") == -1) {
		exit(EXIT_FAILURE);
	}

	for (i = sysconf(_SC_OPEN_MAX); i >= 0; i--) {
		close(i);
	}

	openlog("nm_fd_server", LOG_PID, LOG_DAEMON);
}

int
main(int argc, char *argv[])
{
	int opt;

	while ( (opt = getopt(argc, argv, "f")) != -1) {
		switch (opt) {
		case 'f':
			foreground = 1;
			break;
		default:
			fprintf(stderr, "Unknown option: %c\n", opt);
			exit(EXIT_FAILURE);
			break;
		}
	}
	if (!foreground)
		daemonize();
	main_loop();
	return 0;
}
