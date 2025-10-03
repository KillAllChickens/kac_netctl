// For testing

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PROC_FILE "/proc/kac_net"

void print_usage(const char* prog_name) {
	fprintf(stderr, "Usage: %s <status|on|off>\n", prog_name);
	exit(EXIT_FAILURE);
}

void handle_status() {
	FILE* fp = fopen(PROC_FILE, "r");
	if (fp == NULL) {
		if (errno == ENOENT) {
			fprintf(stderr, "Error: Proc file not found.\nIs the 'kac_netctl' kernel module loaded?\n");
		} else {
			perror("Error opening proc file for reading");
		}
		exit(EXIT_FAILURE);
	}

	int status_char = fgetc(fp);
	if (status_char == EOF) {
		fprintf(stderr, "Error: Could not read from proc file.\n");
		fclose(fp);
		exit(EXIT_FAILURE);
	}

	if (status_char == '1') {
		printf("Network blocking is ON\n");
	} else if (status_char == '0') {
		printf("Network blocking is OFF\n");
	} else {
		printf("Module state is unknown (read: '%c')\n", status_char);
	}

	fclose(fp);
}

// Writes the desired state ("1" for on, "0" for off) to the proc file.
void handle_set(const char* state, const char* friendly_name) {
	FILE* fp = fopen(PROC_FILE, "w");
	if (fp == NULL) {
		if (errno == EACCES) {
			fprintf(stderr, "Error: Permission denied.\nYou probably need to run this command with sudo.\n");
		} else if (errno == ENOENT) {
			fprintf(stderr, "Error: Proc file not found.\nIs the 'kac_netctl' kernel module loaded?\n");
		} else {
			perror("Error opening proc file for writing");
		}
		exit(EXIT_FAILURE);
	}

	size_t written = fwrite(state, sizeof(char), 1, fp);
	if (written < 1) {
		fprintf(stderr, "Error: Failed to write to proc file.\n");
		fclose(fp);
		exit(EXIT_FAILURE);
	}

	printf("Network blocking has been turned %s.\n", friendly_name);
	fclose(fp);
}

int main(int argc, char* argv[]) {
	if (argc != 2) {
		print_usage(argv[0]);
	}

	if (strcmp(argv[1], "status") == 0) {
		handle_status();
	} else if (strcmp(argv[1], "on") == 0) {
		handle_set("1", "ON");
	} else if (strcmp(argv[1], "off") == 0) {
		handle_set("0", "OFF");
	} else {
		// The argument was not one of our recognized commands.
		fprintf(stderr, "Error: Unknown command '%s'\n\n", argv[1]);
		print_usage(argv[0]);
	}

	return EXIT_SUCCESS;
}