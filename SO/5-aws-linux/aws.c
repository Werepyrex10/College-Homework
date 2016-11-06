/* Dimitriu Dragos-Cosmin 331CA */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <libaio.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/eventfd.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include "aws.h"
#include "util.h"
#include "http_parser.h"
#include "sock_util.h"
#include "w_epoll.h"

#define BUFSIZE (BUFSIZ * 8)

static int listenfd;
static int epollfd;

enum sock_state {
	IDLE,
	RECEIVED,
	HEADER,
	STATIC_FILE,
	PREP_AIO_READ,
	READ_DYNAMIC_CHUNK,
	PREP_AIO_SEND,
	SEND_DYNAMIC_CHUNK
};

enum fd_type {
	STATIC,
	DYNAMIC
};

typedef struct {
	int sockfd;

	struct iocb io;
	io_context_t ctx;
	int efd;


	char filename[100];
	int fd;
	enum fd_type type;

	char req[BUFSIZE];
	unsigned int total;

	char in_buf[BUFSIZE];
	unsigned int in_total;

	char out_buf[BUFSIZE];
	unsigned int out_total;
	unsigned int sent_total;

	enum sock_state state;
} conn_state;

/* Setting a file descriptor as nonblocking */
static void set_nonblock(int fd)
{
	int rc;
	int flags;
	/* preiau vechile flag-uri pentru file descriptor */
	rc = fcntl(fd, F_GETFL, 0);
	DIE(rc == -1, "FCNTL F_GETFL");

	flags = rc | O_NONBLOCK;

	rc = fcntl(fd, F_SETFL, flags);
	DIE(rc == -1, "FCNTL F_SETFL");
}

/* Setting resources for a new connection */
static void new_connection(void)
{
	int sockfd;
	socklen_t addrlen = sizeof(struct sockaddr_in);
	struct sockaddr_in addr;
	int rc;
	conn_state *conn;

	sockfd = accept(listenfd, (SSA *) &addr, &addrlen);
	DIE(sockfd < 0, "ACCEPT");
	set_nonblock(sockfd);

	conn = calloc(1, sizeof(conn_state));
	conn->sockfd = sockfd;
	conn->state = IDLE;

	rc = w_epoll_add_ptr_in(epollfd, sockfd, conn);
	DIE(rc == -1, "W_EPOLL_ADD_PTR_IN SOCKFD");
}

/* Closing connection, free the resources */
static void close_connection(conn_state *conn)
{
	int rc;

	rc = w_epoll_remove_ptr(epollfd, conn->sockfd, conn);
	DIE(rc == -1, "W_EPOLL_REMOVE_PTR SOCKFD");

	close(conn->sockfd);
	free(conn);
}

/* Finished reading a file chunk through aio */
static void read_dynamic_chunk(conn_state *conn)
{
	int rc;
	struct io_event event;

	rc = io_getevents(conn->ctx, 1, 1, &event, NULL);
	DIE(rc != 1, "IO_GETEVENTS\n");
	DIE(event.res != conn->in_total, "IO_GETEVENTS_RES");

	conn->state = PREP_AIO_SEND;

	io_destroy(conn->ctx);

	rc = w_epoll_remove_ptr(epollfd, conn->efd, conn);
	DIE(rc == -1, "W_EPOLL_REMOVE_PTR EFD");

	close(conn->efd);
}

/* Sending a chunk of a file by nonblocking send */
static void send_dynamic_chunk(conn_state *conn)
{
	int snt;

	snt = send(conn->sockfd, conn->in_buf + conn->total,
		conn->in_total - conn->total, 0);

	conn->total += snt;
	conn->sent_total += snt;

	if (conn->sent_total == conn->out_total) {
		close(conn->fd);
		close_connection(conn);
		return;
	} else if (conn->total == conn->in_total)
		conn->state = PREP_AIO_READ;
}

/* Prepairing for aio read or send */
static void prep_aio(conn_state *conn)
{
	int rc;
	struct iocb *piocb;

	conn->ctx = 0;

	if (conn->state == PREP_AIO_READ) {

		memset(conn->in_buf, 0, BUFSIZE);

		conn->in_total =
			(conn->sent_total + BUFSIZE > conn->out_total) ?
			(conn->out_total - conn->sent_total) : BUFSIZE;

		/* prepairing the read */
		io_prep_pread(&conn->io, conn->fd, conn->in_buf,
			conn->in_total, conn->sent_total);

		piocb = &conn->io;

		conn->efd = eventfd(0, 0);
		DIE(conn->efd == -1, "EVENTFD");

		/* setting the events in the iocb */
		io_set_eventfd(&conn->io, conn->efd);

		rc = w_epoll_add_ptr_in(epollfd, conn->efd, conn);
		DIE(rc == -1, "W_EPOLL_ADD_PTR_INOUT");

		/* setting the context and submiting the action */
		io_setup(1, &conn->ctx);
		io_submit(conn->ctx, 1, &piocb);

		conn->state = READ_DYNAMIC_CHUNK;
	} else {
		conn->total = 0;

		conn->state = SEND_DYNAMIC_CHUNK;
	}
}

/* Parsing input events */
static void parse_input(conn_state *conn)
{
	int rc, rcv;
	char aux[BUFSIZE];
	struct http_parser_url *url;

	rc = get_peer_address(conn->sockfd, aux, 64);

	if (rc == -1) {
		close_connection(conn);
		return;
	}
	/* reading a chunk of a dynamic file */
	if (conn->state == READ_DYNAMIC_CHUNK)
		read_dynamic_chunk(conn);

	/* prepairing for to send */
	if (conn->state == PREP_AIO_SEND)
		prep_aio(conn);

	/* starting to send a chunk of a file */
	if (conn->state == SEND_DYNAMIC_CHUNK)
		send_dynamic_chunk(conn);
	else { /* received a new connection */
		rcv = recv(conn->sockfd, conn->req + conn->total, BUFSIZE, 0);
		conn->total += rcv;

		if (rcv < 0 || (rcv == 0 && conn->total == 0))
				close_connection(conn);
		else if (strstr(conn->req, "\r\n\r\n") != NULL) {
			url = malloc(sizeof(struct http_parser_url));

			memcpy(conn->in_buf, conn->req, conn->total);
			conn->in_total = conn->total;

			memset(conn->req, 0, conn->total);
			conn->total = 0;

			conn->state = RECEIVED;

			http_parser_parse_url(conn->in_buf,
				conn->in_total, 0, url);

			strcpy(aux, conn->in_buf);

			/* field_data[0].len has the length
			 * up to which the filename starts
			 */
			strcpy(conn->filename, AWS_DOCUMENT_ROOT);
			strcat(conn->filename,
				strtok(aux + url->field_data[0].len,
					"\n ") + 1);

			if (strstr(conn->filename, "static") != NULL)
				conn->type = STATIC;
			else if (strstr(conn->filename, "dynamic") != NULL)
				conn->type = DYNAMIC;

			free(url);

			rc =
				w_epoll_update_ptr_inout(
					epollfd,
					conn->sockfd,
					conn);
			DIE(rc == -1, "W_EPOLL_UPDATE_PTR_INOUT SOCKFD");
		}
	}
}

/* Creating the http reply */
static void format_header(conn_state *conn)
{
	struct stat st;
	char aux[64];

	memset(aux, 0, 64);
	memset(conn->out_buf, 0, BUFSIZE);

	/* checking if file exists */
	if (access(conn->filename, F_OK) == -1) {
		/* looking for http type */
		if (strstr(conn->in_buf, "HTTP/1.0") != NULL)
			strcpy(conn->out_buf, "HTTP/1.0 ");
		else if (strstr(conn->in_buf, "HTTP/1.1") != NULL)
			strcpy(conn->out_buf, "HTTP/1.1 ");

		strcat(conn->out_buf, "404 Not Found\n"
			"Connection: close\r\n\r\n");

		conn->out_total = strlen(conn->out_buf);
		conn->sent_total = 0;
	} else {
		/* looking for http type */
		if (strstr(conn->in_buf, "HTTP/1.0") != NULL)
			strcpy(conn->out_buf, "HTTP/1.0 ");
		else if (strstr(conn->in_buf, "HTTP/1.1") != NULL)
			strcpy(conn->out_buf, "HTTP/1.1 ");

		strcat(conn->out_buf, "200 OK\n"
			"Connection: close\n"
			"Content-Length: ");

		conn->fd = open(conn->filename, O_RDONLY | O_NONBLOCK, 0644);
		DIE(conn->fd == -1, "OPEN FILENAME");

		stat(conn->filename, &st);
		conn->out_total = st.st_size;

		sprintf(aux, "%d\r\n\r\n", conn->out_total);
		strcat(conn->out_buf, aux);

		conn->out_total = strlen(conn->out_buf);
		conn->sent_total = 0;
	}

	conn->state = HEADER;
}

static void send_header(conn_state *conn)
{
	int snt;
	struct stat st;

	snt = send(conn->sockfd, conn->out_buf + conn->sent_total,
		conn->out_total - conn->sent_total, 0);

	if (snt < 0) {
		close_connection(conn);
		return;
	}
	/* counting how much I've send to know if I'm done */
	conn->sent_total += snt;

	if (conn->sent_total == conn->out_total) {
		if (conn->fd == -1) {
			close_connection(conn);
			return;
		}

		stat(conn->filename, &st);
		conn->out_total = st.st_size;

		conn->state = (
			conn->type == STATIC ?
			STATIC_FILE :
			PREP_AIO_READ);
		conn->sent_total = 0;
		memset(conn->out_buf, 0, BUFSIZE);
	}
}

/* Sending a file by zero-copy */
static void send_static_chunk(conn_state *conn)
{
	int snt = sendfile(conn->sockfd, conn->fd,
		NULL, conn->out_total - conn->sent_total);
	/* counting how much I've send to know how much I have left */
	conn->sent_total += snt;

	if (conn->sent_total == conn->out_total) {
		close(conn->fd);
		close_connection(conn);
	}
}

/* Parsing output events */
static void parse_output(conn_state *conn)
{
	int rc;
	char aux[64];

	memset(aux, 0, 64);
	rc = get_peer_address(conn->sockfd, aux, 64);

	if (rc < 0)
		close_connection(conn);

	if (conn->state == IDLE)
		return;

	/* received the request and building header */
	if (conn->state == RECEIVED)
		format_header(conn);

	/* ready to send header piece by piece */
	if (conn->state == HEADER)
		send_header(conn);

	/* ready to send static file piece by piece */
	if (conn->state == STATIC_FILE) {
		send_static_chunk(conn);
		return;
	}

	/* prepairing for aio read */
	if (conn->state == PREP_AIO_READ)
		prep_aio(conn);

	/* sending a chunk of file piece by piece */
	if (conn->state == SEND_DYNAMIC_CHUNK)
		send_dynamic_chunk(conn);
}

int main(int argc, char **argv)
{
	int rc;
	struct epoll_event ev;

	epollfd = w_epoll_create();
	DIE(epollfd < 0, "W_EPOLL_CREATE");

	listenfd = tcp_create_listener(AWS_LISTEN_PORT, DEFAULT_LISTEN_BACKLOG);
	DIE(listenfd < 0, "TCP_CREATE_LISTENER");

	set_nonblock(listenfd);

	rc = w_epoll_add_fd_in(epollfd, listenfd);
	DIE(rc == -1, "W_EPOLL_ADD_FD_IN LISTENFD");

	while (1) {
		rc = w_epoll_wait_infinite(epollfd, &ev);
		DIE(rc == -1, "EPOLL_WAIT");

		if (ev.data.fd == listenfd)
			new_connection();	/* new connection */
		else if ((ev.events & EPOLLIN) != 0)
			parse_input(ev.data.ptr);	/* input event */
		else if ((ev.events & EPOLLOUT) != 0)
			parse_output(ev.data.ptr);	/* output event */
	}

	rc = w_epoll_remove_fd(epollfd, listenfd);
	DIE(rc == -1, "W_EPOLL_REMOVE LISTENFD");

	close(listenfd);
	close(epollfd);

	return 0;
}
