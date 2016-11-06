#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hashtable.h"
#include "utils.h"

#define LINESZ 20000

int main(int argc, char *argv[])
{
	struct Hashtable *h = calloc(1, sizeof(struct Hashtable));
	char *line = malloc(LINESZ*sizeof(char));
	char *cmd[3];
	FILE *f;
	int k = 2;
	int index, rc;

	DIE(argc == 1, "Invalid arguments");

	h->size = atoi(argv[1]);

	DIE(h->size == 0, "Invalid arguments");

	for (; k <= argc ; k++) {
		if (argv[k] != NULL)
			f = fopen(argv[k], "r");
		else if (k == 2)
			f = stdin;
		else
			break;

		DIE(f == NULL, "Invalid input file");

		/*read from the file descriptor while I haven't reached EOF*/
		while (fgets(line, LINESZ, f) != NULL) {
			cmd[0] = strtok(line, "\n ");
			cmd[1] = strtok(NULL, "\n ");
			cmd[2] = strtok(NULL, "\n ");

			if (cmd[0] == NULL)
				continue;

			if (strcmp(cmd[0], "add") == 0)
				add_to_hash(cmd[1], h);

			else if (strcmp(cmd[0], "remove") == 0)
				remove_from_hash(cmd[1], h);

			else if (strcmp(cmd[0], "find") == 0)
				find_in_hash(cmd[1], h, cmd[2]);

			else if (strcmp(cmd[0], "clear") == 0)
				clear(h);

			else if (strcmp(cmd[0], "print_bucket") == 0) {
				index = atoi(cmd[1]);

				print_hash_bucket(h, index,
					cmd[2]);
			} else if (strcmp(cmd[0], "print") == 0)
				print(h, cmd[1]);

			else if (strcmp(cmd[0], "resize") == 0)
				resize(&h, cmd[1]);
			else
				DIE(1, "Invalid command");
		}

		if (argv[k] != NULL) {
			rc = fclose(f);

			DIE(rc == -1, "Fclose error");
		}
	}


	clear(h);
	free(h);
	free(line);

	return 0;
}
