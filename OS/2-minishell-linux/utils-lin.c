/**
 * Operating Systems 2013 - Assignment 2
 *
 */

#include <assert.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <unistd.h>

#include "utils.h"

#define READ		0
#define WRITE		1
#define NO_SETENV	-2

#define SINGLE 1
#define BOTH 2

/**
 * Write an error to stderr and return -1
 */
static int error(char *cmd)
{
	char *s = malloc(100 * sizeof(char));

	sprintf(s, "Execution failed for '%s'\n", cmd);
	write(STDERR_FILENO, s, strlen(s));
	free(s);

	return -1;
}
/**
 * Redirects a standard file descriptor to a given
 * file parameter, with flags. If the many parameter
 * is set to both (&>), it redirects both stdout and
 * stderr to the same file
 */
static int redirect_fd(int src, char *file, int flags, int many)
{
	int rc;
	int fd = open(file, flags, 0644);

	if (fd < 0)
		return error("OPEN");

	rc = dup2(fd, src);

	if (many == BOTH)
		rc += dup2(fd, STDERR_FILENO);

	if (rc < 0)
		return error("DUP2");

	rc = close(fd);

	if (rc < 0)
		return error("CLOSE");

	return 0;
}

/**
 * Redirects the standard file descriptors to the
 * given file parameters, if any. Bares resemblance to
 * redirect, but is modified to work accordingly for cd
 */
static int redirect_cd(char *in, char *out, char *err, int append)
{
	int out_flag = O_WRONLY | O_CREAT;
	int rc;
	int fd;

	if (append != 0)
		out_flag |= O_APPEND;
	else
		out_flag |= O_TRUNC;

	if (in != NULL) {
		fd = open(in, O_RDONLY, 0644);

		if (fd < 0)
			return error("OPEN");

		rc = close(fd);

		if (rc < 0)
			return error("CLOSE");
	}

	if (out != NULL) {
		if (err != NULL && (strcmp(out, err) == 0)) {
			rc += redirect_fd(STDOUT_FILENO, out, out_flag, BOTH);

			free(in);
			free(out);
			free(err);

			return rc;
		}

		fd = open(out, out_flag, 0644);

		if (fd < 0)
			return error("AICI OPEN");

		rc = close(fd);

		if (rc < 0)
			return error("CLOSE");
	}

	if (err != NULL) {
		fd = open(err, out_flag, 0644);

		if (fd < 0)
			return error("OPEN");

		rc = close(fd);

		if (rc < 0)
			return error("CLOSE");
	}

	return 0;
}

/**
 * Internal change-directory command.
 */
static bool shell_cd(word_t *dir)
{
	return chdir(dir->string);
}

/**
 * Internal exit/quit command.
 */
static int shell_exit(void)
{
	return SHELL_EXIT;
}

/**
 * Concatenate parts of the word to obtain the command
 */
static char *get_word(word_t *s)
{
	int string_length = 0;
	int substring_length = 0;

	char *string = NULL;
	char *substring = NULL;

	while (s != NULL) {
		substring = strdup(s->string);

		if (substring == NULL)
			return NULL;

		if (s->expand == true) {
			char *aux = substring;

			substring = getenv(substring);

			/* prevents strlen from failing */
			if (substring == NULL)
				substring = "";

			free(aux);
		}

		substring_length = strlen(substring);

		string = realloc(string, string_length + substring_length + 1);
		if (string == NULL) {
			if (s->expand == false)
				free(substring);
			return NULL;
		}

		memset(string + string_length, 0, substring_length + 1);

		strcat(string, substring);
		string_length += substring_length;

		if (s->expand == false)
			free(substring);

		s = s->next_part;
	}

	return string;
}

/**
 * Concatenate command arguments in a NULL terminated list in order to pass
 * them directly to execv.
 */
static char **get_argv(simple_command_t *command, int *size)
{
	char **argv;
	word_t *param;

	int argc = 0;

	argv = calloc(argc + 1, sizeof(char *));
	assert(argv != NULL);

	argv[argc] = get_word(command->verb);
	assert(argv[argc] != NULL);

	argc++;

	param = command->params;
	while (param != NULL) {
		argv = realloc(argv, (argc + 1) * sizeof(char *));
		assert(argv != NULL);

		argv[argc] = get_word(param);
		assert(argv[argc] != NULL);

		param = param->next_word;
		argc++;
	}

	argv = realloc(argv, (argc + 1) * sizeof(char *));
	assert(argv != NULL);

	argv[argc] = NULL;
	*size = argc;

	return argv;
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
		rc = setenv(left, right, 1);
		return rc;
	}

	return NO_SETENV;
}

/**
 * Redirects the standard file descriptors accordingly, to the
 * file name parameters given, if any
 */
static int redirect(char *in, char *out, char *err, int append)
{
	int out_flag = O_WRONLY | O_CREAT;
	int rc;

	if (append != 0)
		out_flag |= O_APPEND;
	else
		out_flag |= O_TRUNC;

	if (in != NULL)
		rc = redirect_fd(STDIN_FILENO, in, O_RDONLY, SINGLE);

	if (out != NULL) {
		if (err != NULL && (strcmp(out, err) == 0)) {
			rc += redirect_fd(STDOUT_FILENO, out, out_flag, BOTH);

			free(in);
			free(out);
			free(err);

			return rc;
		}

		rc += redirect_fd(STDOUT_FILENO, out, out_flag, SINGLE);
	}

	if (err != NULL)
		rc += redirect_fd(STDERR_FILENO, err, out_flag, SINGLE);

	free(in);
	free(out);
	free(err);

	return rc;
}

/**
 * Parse a simple command (internal, environment variable assignment,
 * external command).
 */
static int parse_simple(simple_command_t *s, int level, command_t *father)
{
	if (s == NULL)
		return error("No command");

	int rc;

	char *cmd = get_word(s->verb);

	/* if builtin command, execute the command */
	if (strcmp(cmd, "exit") == 0 || strcmp(cmd, "quit") == 0) {
		rc = shell_exit();
		return rc;
	}

	char *in = get_word(s->in);
	char *out = get_word(s->out);
	char *err = get_word(s->err);

	if (strcmp(cmd, "cd") == 0) {
		redirect_cd(in, out, err, s->io_flags);
		rc = shell_cd(s->params);
		return rc;
	}

	/* if variable assignment, execute the assignment and return
	 * the exit status
	 */
	rc = shell_set_var(cmd);

	if (rc != NO_SETENV)
		return rc;

	/*if external command:*/
	pid_t pid, wait;
	int status;

	int argc;
	char **argv = get_argv(s, &argc);

	int i;

	pid = fork();

	switch (pid) {
	case -1:
		rc = error("FORK ERROR");
		return rc;

	case 0:	/* child process */
		redirect(in, out, err, s->io_flags);

		rc = execvp(cmd, argv);

		if (rc == -1)
			error(cmd);

		for (i = 0 ; i < argc ; i++)
			free(argv[i]);

		free(argv);
		free(cmd);

		return SHELL_EXIT;

	default:	/* parent process */
		wait = waitpid(pid, &status, 0);

		if (wait < 0)
			return error("WAITPID");

		free(argv);
		free(cmd);

		return status;
	}

	return 0;
}

/**
 * Process two commands in parallel, by creating two children.
 */
static bool do_in_parallel(command_t *cmd1, command_t *cmd2, int level,
							command_t *father)
{
	/* execute cmd1 and cmd2 simultaneously */
	int rc;
	int wait1, wait2;
	int pid1, pid2;
	int status1, status2;
	char *cmd;

	pid1 = fork();

	switch (pid1) {
	case -1:
		rc = error("FORK ERROR");
		return rc;

	case 0:	/* first child process */
		rc = parse_command(cmd1, level, father);

		if (rc < 0) {
			cmd = get_word(cmd1->scmd->verb);
			rc = error(cmd);
			free(cmd);

			return rc;
		}

		exit(rc);

	default:
		pid2 = fork();

		switch (pid2) {
		case -1:
		rc = error("FORK ERROR");
		return rc;
		case 0:	/* second child process */
			rc = parse_command(cmd2, level, father);

			if (rc < 0) {
				cmd = get_word(cmd2->scmd->verb);
				rc = error(cmd);
				free(cmd);

				return rc;
			}

			exit(rc);

		default:	/* parent process */
			wait1 = waitpid(pid1, &status1, 0);
			if (wait1 < 0)
				return error("WAITPID");

			wait2 = waitpid(pid2, &status2, 0);
			if (wait2 < 0)
				return error("WAITPID");

			return status2;
		}
	}


	return 0; /* replace with actual exit status */
}

/**
 * Run commands by creating an anonymous pipe (cmd1 | cmd2)
 */
static bool do_on_pipe(command_t *cmd1, command_t *cmd2, int level,
						command_t *father)
{
	/* redirect the output of cmd1 to the input of cmd2 */
	int rc, fd[2];
	int wait1, wait2;
	int pid1, pid2;
	int status1, status2;
	char *cmd;

	rc = pipe(fd);

	if (rc < 0)
		return error("PIPE");

	pid1 = fork();

	switch (pid1) {
	case -1:
		rc = error("FORK ERROR");
		return rc;

	case 0:	/* first child process */
		rc = close(fd[0]);
		if (rc < 0)
			return error("CLOSE");

		rc = dup2(fd[1], STDOUT_FILENO);
		if (rc < 0)
			return error("DUP2");

		rc = parse_command(cmd1, level, father);
		if (rc < 0) {
			cmd = get_word(cmd1->scmd->verb);
			rc = error(cmd);
			free(cmd);

			return rc;
		}

		rc = close(fd[1]);
		if (rc < 0)
			return error("CLOSE");

		exit(rc);

	default:
		pid2 = fork();

		switch (pid2) {
		case -1:
			rc = error("FORK ERROR");
			return rc;

		case 0:	/* second child process */
			rc = close(fd[1]);
			if (rc < 0)
				return error("CLOSE");

			rc = dup2(fd[0], STDIN_FILENO);
			if (rc < 0)
				return error("DUP2");

			rc = parse_command(cmd2, level, father);
			if (rc < 0) {
				cmd = get_word(cmd2->scmd->verb);
				rc = error(cmd);
				free(cmd);

				return rc;
			}

			rc = close(fd[0]);
			if (rc < 0)
				return error("CLOSE");

			exit(rc);

		default:	/* parent process */
			rc = close(fd[0]);
			rc += close(fd[1]);
			if (rc < 0)
				return error("CLOSE");

			wait1 = waitpid(pid1, &status1, 0);
			if (wait1 < 0)
				return error("WAITPID");

			wait2 = waitpid(pid2, &status2, 0);
			if (wait2 < 0)
				return error("WAITPID");

			return status2;
		}
	}

	return 0;
}

/**
 * Parse and execute a command.
 */
int parse_command(command_t *c, int level, command_t *father)
{
	if (c == NULL)
		return error("No command");

	int rc;

	if (c->op == OP_NONE) {
		rc = parse_simple(c->scmd, level, c);
		return rc;
	}

	switch (c->op) {
	case OP_SEQUENTIAL:
		/* execute the commands one after the other */
		parse_command(c->cmd1, level, c);
		rc = parse_command(c->cmd2, level, c);
		break;

	case OP_PARALLEL:
		/* execute the commands simultaneously */
		rc = do_in_parallel(c->cmd1, c->cmd2, level, c);
		break;

	case OP_CONDITIONAL_NZERO:
		rc = parse_command(c->cmd1, level, c);

		if (rc != 0)
			rc = parse_command(c->cmd2, level, c);

		break;

	case OP_CONDITIONAL_ZERO:
		/* execute the second command only if the first one
		* returns zero
		*/
		rc = parse_command(c->cmd1, level, c);

		if (rc == 0)
			rc = parse_command(c->cmd2, level, c);

		break;

	case OP_PIPE:
		/* redirect the output of the first command to the
		* input of the second
		*/
		rc = do_on_pipe(c->cmd1, c->cmd2, level + 1, c);

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
		return instr;
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
