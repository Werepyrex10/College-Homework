/* Dimitriu Dragos-Cosmin 331CA */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <mswsock.h>
#include <Windows.h>

#include "aws.h"
#include "util.h"
#include "sock_util.h"
#include "debug.h"
#include "w_iocp.h"

#define BUFSIZE (BUFSIZ * 32)

static SOCKET listenH;
static HANDLE iocpHandle;

enum sock_state {
	IDLE,
	HEADER,
	STATIC_FILE,
	READ_DYNAMIC_CHUNK,
	SEND_DYNAMIC_CHUNK
};

enum fd_type {
	STATIC,
	DYNAMIC
};

typedef struct {
	SOCKET sockfd;

	WSAOVERLAPPED in_ov;
	WSAOVERLAPPED out_ov;
	int efd;


	char filename[100];
	HANDLE hFile;
	enum fd_type type;

	DWORD total;

	WSABUF in_buf[1];
	DWORD in_total;

	WSABUF out_buf[1];
	DWORD out_total;
	DWORD sent_total;

	DWORD sent;
	DWORD recv;

	enum sock_state state;
} conn_state;

static struct {
	SOCKET sockfd;
	char buffer[BUFSIZ];
	size_t len;
	OVERLAPPED ov;
} ac;

/* Buffer an future possible connection */
static void create_iocp_accept(void)
{
	BOOL bRet;

	memset(&ac, 0, sizeof(ac));

	/* Create simple socket for acceptance */
	ac.sockfd = socket(PF_INET, SOCK_STREAM, 0);
	DIE(ac.sockfd == INVALID_SOCKET, "socket");

	/* Launch overlapped connection accept through AcceptEx. */
	bRet = AcceptEx(
			listenH,
			ac.sockfd,
			ac.buffer,
			0,
			128,
			128,
			&ac.len,
			&ac.ov);
	DIE(bRet == FALSE &&
		WSAGetLastError() != ERROR_IO_PENDING, "AcceptEx");
}

/* Schedule a receive from an existing connection */
static void connection_schedule_socket_receive(conn_state *conn)
{
	DWORD flags;
	int rc;

	memset(&conn->in_ov, 0, sizeof(conn->in_ov));
	conn->in_buf->len = BUFSIZE;

	flags = 0;
	rc = WSARecv(
			conn->sockfd,
			conn->in_buf,
			1,
			NULL,
			&flags,
			&conn->in_ov,
			NULL);
	if (rc && (rc != SOCKET_ERROR || WSAGetLastError() != WSA_IO_PENDING))
		exit(EXIT_FAILURE);
}

/* Accept a new connection */
static void new_connection(OVERLAPPED *ov)
{
	HANDLE hRet;
	int rc;
	char aux[64];
	conn_state *conn;

	/* assigning an existing dummy socket the actual new one */
	rc = setsockopt(ac.sockfd, SOL_SOCKET,
		SO_UPDATE_ACCEPT_CONTEXT, (char *)&listenH,
		sizeof(listenH)
		);
	DIE(rc < 0, "SETSOCKOPT");

	rc = get_peer_address(ac.sockfd, aux, 64);
	if (rc < 0) {
		ERR("get_peer_address");
		return;
	}

	conn = (conn_state *)calloc(1, sizeof(conn_state));
	conn->sockfd = ac.sockfd;
	conn->state = IDLE;
	conn->in_buf->buf = calloc(sizeof(CHAR), BUFSIZE);
	DIE(conn->in_buf->buf == NULL, "MALLOC INBUF");

	conn->out_buf->buf = calloc(sizeof(CHAR), BUFSIZE);
	DIE(conn->out_buf->buf == NULL, "MALLOC OUTBUF");

	hRet = w_iocp_add_key(
		iocpHandle,
		(HANDLE)conn->sockfd,
		(ULONG_PTR)conn);
	DIE(hRet != iocpHandle, "W_IOCP_ADD_KEY SOCKFD");

	/* schedule a possible receive from the new connection */
	connection_schedule_socket_receive(conn);

	/* schedule a new accept on the listen handle */
	create_iocp_accept();
}

/* Close a connection and free it's resources */
static void close_connection(conn_state *conn)
{
	closesocket(conn->sockfd);
	free(conn->in_buf->buf);
	free(conn->out_buf->buf);
	free(conn);
}

/* Send the header of the http reply */
static void send_header(conn_state *conn)
{
	DWORD flags;
	int rc;

	memset(&conn->out_ov, 0, sizeof(conn->out_ov));
	flags = 0;

	rc = WSASend(
		conn->sockfd,
		conn->out_buf,
		1,
		NULL,
		flags,
		&conn->out_ov,
		NULL);

	DIE(rc && (rc != SOCKET_ERROR ||
		WSAGetLastError() != WSA_IO_PENDING), "WSASEND HEADER");
}

/* Parse the message and format the reply header */
static void format_header(conn_state *conn)
{
	char aux[64];
	HANDLE hRet;
	WIN32_FIND_DATA FindFileData;

	memset(aux, 0, 64);

	/* checking if the file exists */
	hRet = FindFirstFile(conn->filename, &FindFileData);

	if (hRet == INVALID_HANDLE_VALUE) {
		if (strstr(conn->in_buf->buf, "HTTP/1.0") != NULL)
			strcpy(conn->out_buf->buf, "HTTP/1.0 ");
		else if (strstr(conn->in_buf->buf, "HTTP/1.1") != NULL)
			strcpy(conn->out_buf->buf, "HTTP/1.1 ");

		strcat(conn->out_buf->buf, "404 Not Found\n"
			"Connection: close\r\n\r\n");

		conn->hFile = INVALID_HANDLE_VALUE;
		conn->out_total = strlen(conn->out_buf->buf);
		conn->out_buf->len = conn->out_total;
		conn->sent_total = 0;
	} else {
		FindClose(hRet);
		if (strstr(conn->in_buf->buf, "HTTP/1.0") != NULL)
			strcpy(conn->out_buf->buf, "HTTP/1.0 ");
		else if (strstr(conn->in_buf->buf, "HTTP/1.1") != NULL)
			strcpy(conn->out_buf->buf, "HTTP/1.1 ");

		strcat(conn->out_buf->buf, "200 OK\n"
			"Connection: close\n"
			"Content-Length: ");
		conn->hFile = CreateFile(conn->filename,
			GENERIC_READ,
			FILE_SHARE_READ,
			NULL,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
			NULL);
		DIE(conn->hFile == INVALID_HANDLE_VALUE, "CreateFile");

		conn->out_total = GetFileSize(conn->hFile, NULL);

		sprintf(aux, "%d\r\n\r\n", conn->out_total);
		strcat(conn->out_buf->buf, aux);

		conn->out_total = strlen(conn->out_buf->buf);
		conn->out_buf->len = conn->out_total;
		conn->sent_total = 0;
	}

	conn->state = HEADER;
	send_header(conn);
}

/* Read a chunk of a dynamic type file */
static void read_dynamic_chunk(conn_state *conn)
{
	BOOL bRet;

	memset(conn->in_buf->buf, 0, BUFSIZE);
	conn->in_buf->len = BUFSIZE;

	memset(&conn->in_ov, 0, sizeof(conn->in_ov));
	conn->in_ov.Offset = conn->in_total;

	conn->total = (conn->total + BUFSIZE > conn->out_total ?
		conn->out_total - conn->total : BUFSIZE);

	bRet = ReadFile(
		conn->hFile,
		conn->in_buf->buf,
		conn->total,
		NULL,
		&conn->in_ov
		);
	DIE(bRet == FALSE && GetLastError() != ERROR_IO_PENDING, "READFILE");
}

/* Send a previously read chunk of a dynamic type file */
static void send_dynamic_chunk(conn_state *conn)
{
	DWORD flags;
	int rc;

	memset(&conn->out_ov, 0, sizeof(conn->out_ov));
	flags = 0;

	conn->sent = 0;

	rc = WSASend(
		conn->sockfd,
		conn->in_buf,
		1,
		NULL,
		flags,
		&conn->out_ov,
		NULL);

	DIE(rc && (rc != SOCKET_ERROR ||
		WSAGetLastError() != WSA_IO_PENDING), "WSASEND DYNAMIC_CHUNK");
}

/* Check if the dynamic file chunk has been completely sent */
static void check_send_dynamic_chunk(conn_state *conn, OVERLAPPED *ov)
{
	BOOL bRet;
	DWORD flags;
	HANDLE hRet;
	DWORD snt;

	bRet = WSAGetOverlappedResult(
		conn->sockfd,
		ov,
		&snt,
		FALSE,
		&flags);
	DIE(bRet == FALSE, "WSAGETOVERLAPPEDRESULT DYNAMIC");

	conn->sent += snt;
	conn->in_total += snt;

	if (conn->in_total >= conn->out_total) {
		CloseHandle(conn->hFile);
		close_connection(conn);
	} else if (conn->sent == conn->total) {
		/* prepare to read another chunk */
		conn->recv = 0;
		conn->state = READ_DYNAMIC_CHUNK;
		read_dynamic_chunk(conn);
	}
}

/* Check if the dynamic chunk read has finished */
static void check_read_dynamic_chunk(conn_state *conn)
{
	BOOL bRet;
	DWORD rcv;

	bRet = GetOverlappedResult(
		conn->hFile,
		&conn->in_ov,
		&rcv,
		FALSE);
	
	conn->recv += rcv;

	if (conn->recv == conn->total) {
		conn->state = SEND_DYNAMIC_CHUNK;
		send_dynamic_chunk(conn);
	}
}

/* Parse input events */
static void parse_input(conn_state *conn, OVERLAPPED *ov)
{
	DWORD rc, rcv;
	BOOL bRet;
	DWORD flags;
	char aux[BUFSIZE];
	int i;

	memset(aux, 0, BUFSIZE);

	rc = get_peer_address(conn->sockfd, aux, 64);

	if (rc == -1) {
		close_connection(conn);
		return;
	}

	if (conn->state == READ_DYNAMIC_CHUNK) {
		check_read_dynamic_chunk(conn);
	} else {
		bRet = WSAGetOverlappedResult(
			conn->sockfd,
			ov,
			&rcv,
			FALSE,
			&flags
			);
		DIE(bRet == FALSE, "WSAGETOVERLAPPEDRESULT REQUEST");

		if (rcv < 0 || (rcv == 0 && conn->total == 0))
				close_connection(conn);
		else if (strstr(conn->in_buf->buf, "\r\n\r\n") != NULL) {
			memcpy(aux, conn->in_buf->buf + 5, rcv - 9);

			strcpy(conn->filename, AWS_DOCUMENT_ROOT);
			strcat(conn->filename, strtok(aux, " "));
			rc = strlen(conn->filename);
			for (i = 0 ; i < rc ; i++)
				if (conn->filename[i] == '/')
					conn->filename[i] = '\\';

			if (strstr(conn->filename, "static") != NULL)
				conn->type = STATIC;
			else if (strstr(conn->filename, "dynamic") != NULL)
				conn->type = DYNAMIC;

			format_header(conn);
		}
	}
}

/* Send a static file using zero-copy method */
static void send_static_chunk(conn_state *conn)
{
	BOOL bRet;

	DWORD toSend;

	toSend = (conn->sent_total + BUFSIZE > conn->out_total ?
		conn->out_total - conn->sent_total : BUFSIZE);

	bRet = TransmitFile(
		conn->sockfd,
		conn->hFile,
		0,
		0,
		&conn->out_ov,
		NULL,
		0);
	DIE(bRet == FALSE &&
		GetLastError() != ERROR_IO_PENDING, "TRANSMITFILE");
}

/* Check if the header of the http reply has been completely sent */
static void check_header(conn_state *conn, OVERLAPPED *ov)
{
	BOOL bRet;
	DWORD flags;
	HANDLE hRet;

	bRet = WSAGetOverlappedResult(
		conn->sockfd,
		ov,
		&conn->sent,
		FALSE,
		&flags);
	DIE(bRet == FALSE, "WSAGETOVERLAPPEDRESULT HEADER");

	conn->sent_total += conn->sent;

	/* Prepare to send the requested file if it exists */
	if (conn->sent_total >= conn->out_total) {
		if (conn->hFile == INVALID_HANDLE_VALUE) {
			close_connection(conn);
			return;
		}
		conn->out_total = GetFileSize(conn->hFile, NULL);
		conn->out_buf->len = conn->out_total;
		conn->sent_total = 0;
		memset(conn->out_buf->buf, 0, BUFSIZE);

		if (conn->type == STATIC) {
			conn->state = STATIC_FILE;
			send_static_chunk(conn);
		} else if (conn->type == DYNAMIC) {
			conn->state = READ_DYNAMIC_CHUNK;
			conn->total = 0;

			hRet = w_iocp_add_key(
				iocpHandle,
				conn->hFile,
				(ULONG_PTR)conn);
			DIE(hRet != iocpHandle, "W_IOCP_ADD_KEY HFILE");

			read_dynamic_chunk(conn);
		}
	}
}

/* Check if the static file has been completely sent */
static void check_static_chunk(conn_state *conn, OVERLAPPED *ov)
{
	BOOL bRet;
	DWORD flags;

	bRet = WSAGetOverlappedResult(
		conn->sockfd,
		&conn->out_ov,
		&conn->sent,
		FALSE,
		&flags);

	conn->sent_total += conn->sent;
	
	DIE(bRet == FALSE && GetLastError() != WSA_IO_INCOMPLETE,
		"WSAGETOVERLAPPEDRESULT STATIC");

	if (conn->sent_total >= conn->out_total) {
		CloseHandle(conn->hFile);
		close_connection(conn);
	}
}

/* Parse output events */
static void parse_output(conn_state *conn, OVERLAPPED *ov)
{
	int rc;
	char aux[64];

	memset(aux, 0, 64);
	rc = get_peer_address(conn->sockfd, aux, 64);

	if (rc < 0)
		close_connection(conn);
	else if (conn->state == HEADER)
		check_header(conn, ov);
	else if (conn->state == STATIC_FILE)
		check_static_chunk(conn, ov);
	else if (conn->state == SEND_DYNAMIC_CHUNK)
		check_send_dynamic_chunk(conn, ov);
}

/* Parse events */
static void parse_aio(conn_state *conn, OVERLAPPED *ovp)
{
	if (ovp == &conn->out_ov)
		parse_output(conn, ovp);
	else if (ovp == &conn->in_ov)
		parse_input(conn, ovp);
}

int main(int argc, char **argv)
{
	BOOL bRet;
	HANDLE hRet;

	wsa_init();

	iocpHandle = w_iocp_create();
	DIE(iocpHandle < 0, "W_IOCP_CREATE");

	listenH = tcp_create_listener(AWS_LISTEN_PORT, DEFAULT_LISTEN_BACKLOG);
	DIE(listenH == INVALID_SOCKET, "TCP_CREATE_LISTENER");

	hRet = w_iocp_add_handle(iocpHandle, (HANDLE)listenH);
	DIE(hRet != iocpHandle, "W_IOCP_ADD_HANDLE LISTENFD");

	create_iocp_accept();

	while (1) {
		OVERLAPPED *ov;
		ULONG_PTR key;
		DWORD bytes;

		ZeroMemory(&ov, sizeof(OVERLAPPED));
		bRet = w_iocp_wait(iocpHandle, &bytes, &key, &ov);
		DIE(bRet == FALSE, "IOCP_WAIT");

		if (key == listenH)
			new_connection(ov);
		else
			parse_aio((conn_state *) key, ov);
	}

	closesocket(listenH);
	wsa_cleanup();

	return 0;
}
