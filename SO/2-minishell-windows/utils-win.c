/**
 * Operating Systems 2013 - Assignment 2
 *
 */

#include <windows.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"

/* do not use UNICODE */
#undef _UNICODE
#undef UNICODE

#define READ		0
#define WRITE		1

#define NO_SETENV	-2

#define READ 0
#define WRITE 1

#define MAX_SIZE_ENVIRONMENT_VARIABLE 100

/**
 * Debug method, used by DIE macro.
 */

typedef struct MyData {
	command_t c;
	int level;
	command_t father;
	HANDLE h[2];
};

static VOID PrintLastError(const PCHAR message)
{
	CHAR errBuff[1024];

	FormatMessage(
		FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_MAX_WIDTH_MASK,
		NULL,
		GetLastError(),
		0,
		errBuff,
		sizeof(errBuff) - 1,
		NULL);

	fprintf(stderr, "Execution failed for %s: %s\n", message, errBuff);
}

/*
* Returns a HANDLE to the file given as parameter,
* opened by 'type' and with 'mode' mode of opening
*/
HANDLE openFile(PCSTR file, DWORD mode, int type)
{
	SECURITY_ATTRIBUTES sa;
	DWORD des_acc;
	DWORD share;

	HANDLE hFile;

	ZeroMemory(&sa, sizeof(sa));
	sa.bInheritHandle = TRUE;

	if (type == WRITE) {
		des_acc = GENERIC_WRITE;
		share = FILE_SHARE_WRITE;
	} else {
		des_acc = GENERIC_READ;
		share = FILE_SHARE_READ;
	}

	hFile = CreateFile(
		file,
		des_acc,
		share,
		&sa,
		mode,
		FILE_ATTRIBUTE_NORMAL,
		NULL
		);

	DIE(hFile == INVALID_HANDLE_VALUE, "CREATEFILE");

	if (mode == OPEN_ALWAYS)
		SetFilePointer(hFile, 0, NULL, FILE_END);

	return hFile;
}

/**
 * Internal change-directory command.
 */
static int shell_cd(word_t *dir, char *in, char *out, char *err)
{
	int rc;
	HANDLE hFile;

	if (in != NULL) {
		hFile = openFile(in, CREATE_ALWAYS, READ);
		CloseHandle(hFile);
	}

	if (out != NULL) {
		hFile = openFile(out, CREATE_ALWAYS, WRITE);
		CloseHandle(hFile);

	}

	if (err != NULL) {
		hFile = openFile(err, CREATE_ALWAYS, WRITE);
		CloseHandle(hFile);
	}

	rc = SetCurrentDirectory(dir->string);
	if (rc == FALSE)
		PrintLastError("INVALID FOLDER");
	return rc;
}

/**
 * Internal exit/quit command.
 */
static int shell_exit(void)
{
	return SHELL_EXIT;
}

/**
* Check if cmd is a set environment variable command
* and runs it.
*/
static int shell_set_var(char *cmd)
{
	char *left = strtok(cmd, "=");
	char *right = strtok(NULL, "=");
	int rc;

	if (left != NULL && right != NULL) {
		rc = SetEnvironmentVariable(left, right);

		DIE(rc == false, "SETENVIRONMENTVARIABLE");
		return 0;
	}

	return NO_SETENV;
}

/**
 * Concatenate parts of the word to obtain the command
 */
static LPTSTR get_word(word_t *s)
{
	DWORD string_length = 0;
	DWORD substring_length = 0;

	LPTSTR string = NULL;
	CHAR substring[MAX_SIZE_ENVIRONMENT_VARIABLE];

	DWORD dwret;

	while (s != NULL) {
		strcpy(substring, s->string);

		if (s->expand == true) {
			dwret = GetEnvironmentVariable(
				substring,
				substring,
				MAX_SIZE_ENVIRONMENT_VARIABLE
			);
			if (!dwret)
				/* Environment Variable does not exist. */
				strcpy(substring, "");
		}

		substring_length = strlen(substring);

		string = realloc(string, string_length + substring_length + 1);
		if (string == NULL)
			return NULL;

		memset(string + string_length, 0, substring_length + 1);

		strcat(string, substring);
		string_length += substring_length;

		s = s->next_part;
	}

	return string;
}

/**
 * Parse arguments in order to succesfully process them using CreateProcess
 */
static LPTSTR get_argv(simple_command_t *command)
{
	LPTSTR argv = NULL;
	LPTSTR substring = NULL;
	word_t *param;

	DWORD string_length = 0;
	DWORD substring_length = 0;

	argv = get_word(command->verb);
	assert(argv != NULL);

	string_length = strlen(argv);

	param = command->params;
	while (param != NULL) {
		substring = get_word(param);
		substring_length = strlen(substring);

		argv = realloc(argv, string_length + substring_length + 4);
		assert(argv != NULL);

		strcat(argv, " ");

		/* Surround parameters with ' ' */
		strcat(argv, "'");
		strcat(argv, substring);
		strcat(argv, "'");

		string_length += substring_length + 3;
		param = param->next_word;

		free(substring);
	}

	return argv;
}

/*
* Redirects all the standard file descriptors
* to the coresponding files if they are given as
* parameter
*/
void redirect(char *in, char *out, char *err, HANDLE *h,
	STARTUPINFO *si, int append)
{
	si->hStdInput = GetStdHandle(STD_INPUT_HANDLE);
	si->hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
	si->hStdError = GetStdHandle(STD_ERROR_HANDLE);

	if (in != NULL)
		si->hStdInput = openFile(in, OPEN_EXISTING, READ);

	if (out != NULL) {
		if (append == 1)
			si->hStdOutput = openFile(out,
			OPEN_ALWAYS, WRITE);
		else
			si->hStdOutput = openFile(out,
			CREATE_ALWAYS, WRITE);
	}

	if (h != NULL) {
		if (h[0] != NULL)
			si->hStdInput = h[0];

		if (h[1] != NULL)
			si->hStdOutput = h[1];
	}

	if (err != NULL) {
		if (out != NULL && strcmp(err, out) == 0)
			si->hStdError = si->hStdOutput;
		else {
			if (append == 2)
				si->hStdError = openFile(err,
				OPEN_ALWAYS, WRITE);
			else
				si->hStdError = openFile(err,
				CREATE_ALWAYS, WRITE);
		}
	}
}

/**
 * Parse and execute a simple command, by either creating a new processing or
 * internally process it.
 */
bool parse_simple(simple_command_t *s, int level,
	command_t *father, HANDLE *h)
{
	int rc = 0;

	char *in = get_word(s->in);
	char *out = get_word(s->out);
	char *err = get_word(s->err);
	char *cmd = get_word(s->verb);

	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	DWORD dwRes;
	BOOL bRes;

	char *argv = get_argv(s);

	DIE(s == NULL, "No command");

	/* if builtin command, execute the command */
	if (strcmp(cmd, "exit") == 0 || strcmp(cmd, "quit") == 0) {
		rc = shell_exit();
		return rc;
	}

	if (strcmp(cmd, "cd") == 0) {
		rc = shell_cd(s->params, in, out, err);
		return rc;
	}

	/* if variable assignment, execute the assignment and return
	* the exit status
	*/
	rc = shell_set_var(cmd);

	if (rc != NO_SETENV)
		return rc;

	/*  if external command:
	 *  1. set handles
	 *  2. redirect standard input / output / error
	 *  3. run command
	 *  4. get exit code
	 */

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);

	ZeroMemory(&pi, sizeof(pi));
	si.dwFlags |= STARTF_USESTDHANDLES;

	redirect(in, out, err, h, &si, s->io_flags);

	bRes = CreateProcess(
		NULL,
		argv,
		NULL,
		NULL,
		TRUE,
		0,
		NULL,
		NULL,
		&si,
		&pi);

	if (bRes == false) {
		fprintf(stderr, "Execution failed for '%s'\n", cmd);

		fflush(stderr);

		if (in != NULL)
			CloseHandle(si.hStdInput);

		if (out != NULL)
			CloseHandle(si.hStdOutput);

		if (err != NULL)
			CloseHandle(si.hStdError);

		free(cmd);
		free(in);
		free(out);
		free(err);

		return -1;
	}

	dwRes = WaitForSingleObject(pi.hProcess, INFINITE);
	DIE(dwRes == WAIT_FAILED, "WAITFORSINGLEOBJECT");

	GetExitCodeProcess(pi.hProcess, &rc);

	CloseHandle(pi.hProcess);

	if (in != NULL)
		CloseHandle(si.hStdInput);

	if (out != NULL)
		CloseHandle(si.hStdOutput);

	if (err != NULL)
		CloseHandle(si.hStdError);

	free(cmd);
	free(in);
	free(out);
	free(err);

	return rc;
}

/*
* Reads the data from the LPVOID data
* and executes the parse_command, command
*/
static int WINAPI parse_command_aux(LPVOID data)
{
	struct MyData *md = (struct MyData *)data;

	int rc;

	HANDLE processHeap = GetProcessHeap();

	rc = parse_command(&md->c, md->level, &md->father, &md->h);

	return rc;
}

/**
 * Process two commands in parallel, by creating two children.
 */
static bool do_in_parallel(command_t *cmd1, command_t *cmd2,
	int level, command_t *father, HANDLE *h)
{
	/* execute cmd1 and cmd2 simultaneously */

	HANDLE hProc1, hProc2;
	DWORD id1, id2;
	DWORD dwRes1, dwRes2;

	struct MyData *md1, *md2;

	HANDLE processHeap = GetProcessHeap();

	DIE(processHeap == NULL, "GETPROCESSHEAP");

	md1 = (struct MyData *)HeapAlloc(processHeap,
		HEAP_ZERO_MEMORY, sizeof(struct MyData));
	md1->c = *cmd1;
	md1->father = *father;
	if (h != NULL) {
		md1->h[0] = h[0];
		md1->h[1] = h[1];
	}
	md1->level = level;

	md2 = (struct MyData *)HeapAlloc(processHeap,
		HEAP_ZERO_MEMORY, sizeof(struct MyData));

	md2->c = *cmd2;
	md2->father = *father;
	if (h != NULL) {
		md2->h[0] = h[0];
		md2->h[1] = h[1];
	}
	md2->level = level;

	hProc1 = CreateThread(
		NULL,
		0,
		parse_command_aux,
		md1,
		0,
		&id1
		);

	DIE(hProc1 == NULL, "CREATETHREAD");

	hProc2 = CreateThread(
		NULL,
		0,
		parse_command_aux,
		md2,
		0,
		&id2
		);

	DIE(hProc2 == NULL, "CREATETHREAD");

	dwRes1 = WaitForSingleObject(hProc1, INFINITE);

	DIE(dwRes1 == WAIT_FAILED, "WAITFORSINGLEOBJECT");

	dwRes2 = WaitForSingleObject(hProc2, INFINITE);

	DIE(dwRes2 == WAIT_FAILED, "WAITFORSINGLEOBJECT");

	GetExitCodeThread(hProc2, &dwRes2);

	CloseHandle(hProc1);
	CloseHandle(hProc2);

	HeapFree(processHeap, 0, md1);
	HeapFree(processHeap, 0, md2);

	return dwRes2;
}

/**
 * Run commands by creating an anonymous pipe (cmd1 | cmd2)
 */
static bool do_on_pipe(command_t *cmd1, command_t *cmd2,
	int level, command_t *father, HANDLE *h)
{
	HANDLE pRead, pWrite;
	SECURITY_ATTRIBUTES sa;
	BOOL bRes;
	int ret = 0;
	HANDLE processHeap;
	HANDLE *h1, *h2;
	HANDLE hProc1, hProc2;
	struct MyData *md1, *md2;
	DWORD id1, id2, dwRes1, dwRes2;

	/* redirect the output of cmd1 to the input of cmd2 */

	ZeroMemory(&sa, sizeof(sa));
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.bInheritHandle = TRUE;
	sa.lpSecurityDescriptor = NULL;

	bRes = CreatePipe(&pRead, &pWrite, &sa, INFINITE);
	DIE(!bRes, "CREATEPIPE");

	processHeap = GetProcessHeap();
	h1 = (HANDLE *)HeapAlloc(processHeap, 0, 2*sizeof(HANDLE));
	h2 = (HANDLE *)HeapAlloc(processHeap, 0, 2*sizeof(HANDLE));

	if (h != NULL && h[0] != NULL)
		h1[0] = h[0];
	else
		h1[0] = NULL;
	h1[1] = pWrite;


	h2[0] = pRead;
	if (h != NULL && h[1] != NULL)
		h2[1] = h[1];
	else
		h2[1] = NULL;

	md1 = (struct MyData *)HeapAlloc(processHeap,
		HEAP_ZERO_MEMORY, sizeof(struct MyData));
	md1->c = *cmd1;
	md1->father = *father;
	md1->h[0] = h1[0];
	md1->h[1] = h1[1];
	md1->level = level;

	md2 = (struct MyData *)HeapAlloc(processHeap,
		HEAP_ZERO_MEMORY, sizeof(struct MyData));

	md2->c = *cmd2;
	md2->father = *father;
	md2->h[0] = h2[0];
	md2->h[1] = h2[1];
	md2->level = level;
	fflush(stdout);
	hProc1 = CreateThread(
		NULL,
		0,
		parse_command_aux,
		md1,
		0,
		&id1
		);

	DIE(hProc1 == NULL, "CREATETHREAD");

	dwRes1 = WaitForSingleObject(hProc1, INFINITE);

	CloseHandle(pWrite);

	DIE(dwRes1 == WAIT_FAILED, "WAITFORSINGLEOBJECT");

	hProc2 = CreateThread(
		NULL,
		0,
		parse_command_aux,
		md2,
		0,
		&id2
		);

	DIE(hProc2 == NULL, "CREATETHREAD");

	dwRes2 = WaitForSingleObject(hProc2, INFINITE);
	CloseHandle(pRead);

	DIE(dwRes2 == WAIT_FAILED, "WAITFORSINGLEOBJECT");

	GetExitCodeThread(hProc2, &dwRes2);

	CloseHandle(hProc1);
	CloseHandle(hProc2);

	HeapFree(processHeap, 0, md1);
	HeapFree(processHeap, 0, md2);
	HeapFree(processHeap, 0, h1);
	HeapFree(processHeap, 0, h2);

	return dwRes2;
}

/**
 * Parse and execute a command.
 */
int parse_command(command_t *c, int level, command_t *father, void *h)
{
	int rc;

	DIE(c == NULL, "No command");

	if (c->op == OP_NONE) {
		rc = parse_simple(c->scmd, level, c, h);
		return rc;
	}

	switch (c->op) {
	case OP_SEQUENTIAL:
		/* execute the commands one after the other */
		parse_command(c->cmd1, level, c, h);
		rc = parse_command(c->cmd2, level, c, h);
		break;

	case OP_PARALLEL:
		/* execute the commands simultaneously */
		rc = do_in_parallel(c->cmd1, c->cmd2, level, c, h);
		break;

	case OP_CONDITIONAL_NZERO:
		/* execute the second command only if the first one
		* returns non-zero
		*/
		rc = parse_command(c->cmd1, level, c, h);

		if (rc != 0)
			rc = parse_command(c->cmd2, level, c, h);

		break;

	case OP_CONDITIONAL_ZERO:
		/* execute the second command only if the first one
		* returns zero
		*/
		rc = parse_command(c->cmd1, level, c, h);

		if (rc == 0)
			rc = parse_command(c->cmd2, level, c, h);

		break;

	case OP_PIPE:
		/* redirect the output of the first command to the
		* input of the second
		*/
		rc = do_on_pipe(c->cmd1, c->cmd2, level + 1, c, h);

		break;

	default:
		assert(false);
	}

	return rc;
}

/**
 * Readline from mini-shell.
 */
char *read_line()
{
	char *instr;
	char *chunk;
	char *ret;

	int instr_length;
	int chunk_length;

	int endline = 0;

	instr = NULL;
	instr_length = 0;

	chunk = calloc(CHUNK_SIZE, sizeof(char));
	if (chunk == NULL) {
		fprintf(stderr, ERR_ALLOCATION);
		exit(EXIT_FAILURE);
	}

	while (!endline) {
		ret = fgets(chunk, CHUNK_SIZE, stdin);
		if (ret == NULL)
			break;

		chunk_length = strlen(chunk);
		if (chunk[chunk_length - 1] == '\n') {
			chunk[chunk_length - 1] = 0;
			endline = 1;
		}

		instr = realloc(instr, instr_length + CHUNK_SIZE + 1);
		if (instr == NULL)
			break;

		memset(instr + instr_length, 0, CHUNK_SIZE);
		strcat(instr, chunk);
		instr_length += chunk_length;
	}

	free(chunk);

	return instr;
}

