#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <bpf/libbpf.h>
#include "main.skel.h"

const char target_filename[] = "/tmp/bocchi";

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	struct main_bpf *skel;
	int err;

	libbpf_set_print(libbpf_print_fn);

	skel = main_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton");
		return 1;
	}

	skel->rodata->loader_pid = getpid();

	strcpy(skel->rodata->filename, target_filename);
	skel->rodata->filename_len = strlen(target_filename);

	err = main_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load BPF skeleton");
		goto cleanup;
	}

	err = main_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton");
		goto cleanup;
	}

	fprintf(stderr, "eBPF is loaded\n");

	while (1) {
		sleep(1);
	}

cleanup:
	main_bpf__destroy(skel);
	return -err;
}
