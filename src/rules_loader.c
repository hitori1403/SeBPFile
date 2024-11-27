#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <yaml.h>
#include <stdio.h>
#include <bpf/libbpf.h>
#include <linux/limits.h>

#include "types.h"
#include "constants.h"
#include "main.skel.h"

#include "fnv1a.c"

struct proc_info {
	u32 uid;
	u32 pid;
	u32 ppid;
	char cwd[PATH_MAX];
	char path[PATH_MAX];
	u8 perm;
	u8 log;
};

enum parser_state {
	STATE_START,
	STATE_STREAM,
	STATE_DOCUMENT,
	STATE_SECTION,

	STATE_RULE,
	STATE_RULE_LIST,
	STATE_RULE_VALUE,

	STATE_FILE,

	STATE_PROCESS_LIST,
	STATE_PROCESS_VALUES,
	STATE_PROCESS,

	STATE_PROCESS_ATTRIBUTES,
	STATE_PROCESS_ATTRIBUTE_KEY,
	STATE_PROCESS_USER,
	STATE_PROCESS_PID,
	STATE_PROCESS_PPID,
	STATE_PROCESS_PERMISSION,
	STATE_PROCESS_CWD,
	STATE_PROCESS_LOG,

	STATE_LOG_LIST,

	STATE_STOP /* end state */
};

enum log_type_value { OPEN = 1, READ = 2, WRITE = 4 };

struct log_entry {
	char *log_type;
	struct log_entry *next;
};

struct process_entry {
	char *path;
	char *user;
	char *perm;
	char *cwd;
	int pid;
	int ppid;
	struct process_entry *next;
	struct log_entry *last_log;
	struct log_entry *log_list;
};

struct file_entry {
	char *path;
	struct file_entry *next;
	struct process_entry *last_process;
	struct process_entry *process_list;
};

struct yaml_parser_state {
	enum parser_state state;
	struct file_entry *last_file;
	struct file_entry *file_list;
};

int consume_event(struct yaml_parser_state *s, yaml_event_t *event)
{
	char *value;

	switch (s->state) {
	case STATE_START:
		switch (event->type) {
		case YAML_STREAM_START_EVENT:
			s->state = STATE_STREAM;
			break;

		default:
			fprintf(stderr, "Unexpected event %d in state %d.\n", event->type,
				s->state);
			return EXIT_FAILURE;
		}
		break;

	case STATE_STREAM:
		switch (event->type) {
		case YAML_DOCUMENT_START_EVENT:
			s->state = STATE_DOCUMENT;
			break;
		case YAML_STREAM_END_EVENT:
			s->state = STATE_STOP;
			break;
		default:
			fprintf(stderr, "Unexpected event %d in state %d.\n", event->type,
				s->state);
			return EXIT_FAILURE;
		}
		break;

	case STATE_DOCUMENT:
		switch (event->type) {
		case YAML_MAPPING_START_EVENT:
			s->state = STATE_RULE;
			break;
		case YAML_DOCUMENT_END_EVENT:
			s->state = STATE_STREAM;
			break;
		default:
			fprintf(stderr, "Unexpected event %d in state %d.\n", event->type,
				s->state);
			return EXIT_FAILURE;
		}
		break;

	case STATE_RULE:
		switch (event->type) {
		case YAML_SCALAR_EVENT:
			value = (char *)event->data.scalar.value;
			if (!strcmp(value, "rules")) {
				s->state = STATE_RULE_LIST;
			} else {
				fprintf(stderr, "Unexpected scalar: %s\n", value);
				return EXIT_FAILURE;
			}
			break;
		case YAML_MAPPING_END_EVENT:
			s->state = STATE_DOCUMENT;
			break;
		case YAML_DOCUMENT_END_EVENT:
			s->state = STATE_STREAM;
			break;
		default:
			fprintf(stderr, "Unexpected event %d in state %d.\n", event->type,
				s->state);
			return EXIT_FAILURE;
		}
		break;

	case STATE_RULE_LIST:
		switch (event->type) {
		case YAML_SEQUENCE_START_EVENT:
			s->state = STATE_RULE_VALUE;
			break;
		case YAML_SEQUENCE_END_EVENT:
			s->state = STATE_RULE;
			break;
		default:
			fprintf(stderr, "Unexpected event %d in state %d.\n", event->type,
				s->state);
			return EXIT_FAILURE;
		}
		break;

	case STATE_RULE_VALUE:
		switch (event->type) {
		case YAML_MAPPING_START_EVENT:
			s->state = STATE_FILE;
			break;
		case YAML_MAPPING_END_EVENT:
			s->state = STATE_RULE_LIST;
			break;
		case YAML_SEQUENCE_END_EVENT:
			s->state = STATE_RULE;
			break;
		default:
			fprintf(stderr, "Unexpected event %d in state %d.\n", event->type,
				s->state);
			return EXIT_FAILURE;
		}
		break;

	case STATE_FILE:
		switch (event->type) {
		case YAML_SCALAR_EVENT:
			value = (char *)event->data.scalar.value;
			struct file_entry *f = calloc(1, sizeof(struct file_entry));
			f->path = strdup(value);
			if (s->file_list == NULL)
				s->file_list = f;
			else
				s->last_file->next = f;
			s->last_file = f;
			s->state = STATE_PROCESS_LIST;
			break;
		case YAML_MAPPING_END_EVENT:
			s->state = STATE_RULE_VALUE;
			break;
		default:
			fprintf(stderr, "Unexpected event %d in state %d.\n", event->type,
				s->state);
			return EXIT_FAILURE;
		}
		break;

	case STATE_PROCESS_LIST:
		switch (event->type) {
		case YAML_SEQUENCE_START_EVENT:
			s->state = STATE_PROCESS_VALUES;
			break;
		case YAML_SEQUENCE_END_EVENT:
			s->state = STATE_FILE;
			break;
		default:
			fprintf(stderr, "Unexpected event %d in state %d.\n", event->type,
				s->state);
			return EXIT_FAILURE;
		}
		break;

	case STATE_PROCESS_VALUES:
		switch (event->type) {
		case YAML_MAPPING_START_EVENT:
			s->state = STATE_PROCESS;
			break;
		case YAML_MAPPING_END_EVENT:
			s->state = STATE_PROCESS_LIST;
			break;
		case YAML_SEQUENCE_END_EVENT:
			s->state = STATE_FILE;
			break;
		default:
			fprintf(stderr, "Unexpected event %d in state %d.\n", event->type,
				s->state);
			return EXIT_FAILURE;
		}
		break;

	case STATE_PROCESS:
		switch (event->type) {
		case YAML_SCALAR_EVENT:
			value = (char *)event->data.scalar.value;
			struct process_entry *p = calloc(1, sizeof(struct process_entry));
			p->path = strdup(value);
			if (s->last_file->process_list == NULL)
				s->last_file->process_list = p;
			else
				s->last_file->process_list->next = p;
			s->last_file->last_process = p;
			s->state = STATE_PROCESS_ATTRIBUTES;
			break;
		case YAML_MAPPING_END_EVENT:
			s->state = STATE_PROCESS_VALUES;
			break;
		default:
			fprintf(stderr, "Unexpected event %d in state %d.\n", event->type,
				s->state);
			return EXIT_FAILURE;
		}
		break;

	case STATE_PROCESS_ATTRIBUTES:
		switch (event->type) {
		case YAML_MAPPING_START_EVENT:
			s->state = STATE_PROCESS_ATTRIBUTE_KEY;
			break;
		default:
			fprintf(stderr, "Unexpected event %d in state %d.\n", event->type,
				s->state);
			return EXIT_FAILURE;
		}
		break;

	case STATE_PROCESS_ATTRIBUTE_KEY:
		switch (event->type) {
		case YAML_SCALAR_EVENT:
			value = (char *)event->data.scalar.value;
			if (!strcmp(value, "user"))
				s->state = STATE_PROCESS_USER;
			else if (!strcmp(value, "pid"))
				s->state = STATE_PROCESS_PID;
			else if (!strcmp(value, "ppid"))
				s->state = STATE_PROCESS_PPID;
			else if (!strcmp(value, "perm"))
				s->state = STATE_PROCESS_PERMISSION;
			else if (!strcmp(value, "cwd"))
				s->state = STATE_PROCESS_CWD;
			else if (!strcmp(value, "log"))
				s->state = STATE_PROCESS_LOG;
			break;
		case YAML_MAPPING_END_EVENT:
			s->state = STATE_PROCESS;
			break;
		default:
			fprintf(stderr, "Unexpected event %d in state %d.\n", event->type,
				s->state);
			return EXIT_FAILURE;
		}
		break;

	case STATE_PROCESS_USER:
		switch (event->type) {
		case YAML_SCALAR_EVENT:
			value = (char *)event->data.scalar.value;
			s->last_file->last_process->user = strdup(value);
			s->state = STATE_PROCESS_ATTRIBUTE_KEY;
			break;

		default:
			fprintf(stderr, "Unexpected event %d in state %d.\n", event->type,
				s->state);
			return EXIT_FAILURE;
		}
		break;

	case STATE_PROCESS_PID:
		switch (event->type) {
		case YAML_SCALAR_EVENT:
			value = (char *)event->data.scalar.value;
			s->last_file->last_process->pid = atoi(value);
			s->state = STATE_PROCESS_ATTRIBUTE_KEY;
			break;

		default:
			fprintf(stderr, "Unexpected event %d in state %d.\n", event->type,
				s->state);
			return EXIT_FAILURE;
		}
		break;

	case STATE_PROCESS_PPID:
		switch (event->type) {
		case YAML_SCALAR_EVENT:
			value = (char *)event->data.scalar.value;
			s->last_file->last_process->ppid = atoi(value);
			s->state = STATE_PROCESS_ATTRIBUTE_KEY;
			break;

		default:
			fprintf(stderr, "Unexpected event %d in state %d.\n", event->type,
				s->state);
			return EXIT_FAILURE;
		}
		break;

	case STATE_PROCESS_PERMISSION:
		switch (event->type) {
		case YAML_SCALAR_EVENT:
			value = (char *)event->data.scalar.value;
			s->last_file->last_process->perm = strdup(value);
			s->state = STATE_PROCESS_ATTRIBUTE_KEY;
			break;

		default:
			fprintf(stderr, "Unexpected event %d in state %d.\n", event->type,
				s->state);
			return EXIT_FAILURE;
		}
		break;

	case STATE_PROCESS_CWD:
		switch (event->type) {
		case YAML_SCALAR_EVENT:
			value = (char *)event->data.scalar.value;
			s->last_file->last_process->cwd = strdup(value);
			s->state = STATE_PROCESS_ATTRIBUTE_KEY;
			break;

		default:
			fprintf(stderr, "Unexpected event %d in state %d.\n", event->type,
				s->state);
			return EXIT_FAILURE;
		}
		break;

	case STATE_PROCESS_LOG:
		switch (event->type) {
		case YAML_SEQUENCE_START_EVENT:
			s->state = STATE_LOG_LIST;
			break;

		default:
			fprintf(stderr, "Unexpected event %d in state %d.\n", event->type,
				s->state);
			return EXIT_FAILURE;
		}
		break;

	case STATE_LOG_LIST:
		switch (event->type) {
		case YAML_SCALAR_EVENT:
			value = (char *)event->data.scalar.value;
			struct log_entry *l = calloc(1, sizeof(struct log_entry));
			l->log_type = strdup(value);
			if (s->last_file->last_process->log_list == NULL)
				s->last_file->last_process->log_list = l;
			else
				s->last_file->last_process->last_log->next = l;
			s->last_file->last_process->last_log = l;
			s->state = STATE_LOG_LIST;
			break;
		case YAML_SEQUENCE_END_EVENT:
			s->state = STATE_PROCESS_ATTRIBUTE_KEY;
			break;
		default:
			fprintf(stderr, "Unexpected event %d in state %d.\n", event->type,
				s->state);
			return EXIT_FAILURE;
		}
		break;

	case STATE_STOP:
		return 0;

	default:
		break;
	}

	return 0;
}

/* void clean(struct yaml_parser_state *state)
{
	for (struct file_entry *f = state->file_list; f;) {
		for (struct process_entry *p = f->process_list; p;) {
			free(p->path);
			free(p->user);
			free(p->cwd);
			free(p->perm);
			for (struct log_entry *l = p->log_list; l;) {
				struct log_entry *tmp = l->next;
				free(l->log_type);
				free(l);
				l = tmp;
			}
			struct process_entry *tmp = p->next;
			free(p);
			p = tmp;
		}
		struct file_entry *tmp = f->next;
		free(f);
		f = tmp;
	}
} */

int perm_to_num(const char *perm)
{
	if (!perm)
		return 0;

	int num = 0;
	for (const char *c = perm; *c; ++c) {
		switch (*c) {
		case 'r':
			num |= 4;
			break;
		case 'w':
			num |= 2;
			break;
		case 'x':
			num |= 1;
			break;
		default:
			fprintf(stderr, "Unknown permission: %s", perm);
			exit(EXIT_FAILURE);
		}
	}
	return num;
}

int load_rules_to_bpf_map(struct main_bpf *skel, const char *file_path)
{
	FILE *input = fopen(file_path, "rb");
	if (!input) {
		perror("Failed to open rules file");
		exit(EXIT_FAILURE);
	}

	int exit_code = 0;

	yaml_parser_t parser;
	yaml_event_t event;
	struct yaml_parser_state *state = malloc(sizeof(struct yaml_parser_state));

	memset(state, 0, sizeof(struct yaml_parser_state));

	state->state = STATE_START;

	if (!yaml_parser_initialize(&parser)) {
		perror("Could not initialize the parser object");
		exit(EXIT_FAILURE);
	}

	yaml_parser_set_input_file(&parser, input);

	do {
		if (!yaml_parser_parse(&parser, &event)) {
			perror(parser.problem);
			exit(EXIT_FAILURE);
		}

		if (consume_event(state, &event)) {
			fprintf(stderr, "consume_event error\n");
			exit_code = EXIT_FAILURE;
			goto cleanup;
		}

	} while (state->state != STATE_STOP);

	// TODO: vaidate value
	for (struct file_entry *f = state->file_list; f; f = f->next) {
		struct proc_info proc[MAX_PROCESSES_PER_FILE];
		int i = 0;

		for (struct process_entry *p = f->process_list; p; p = p->next) {
			if (p->path)
				strcpy(proc[i].path, p->path);

			if (p->cwd)
				strcpy(proc[i].cwd, p->cwd);

			if (p->pid)
				proc[i].pid = p->pid;

			if (p->ppid)
				proc[i].ppid = p->ppid;

			if (p->perm)
				proc[i].perm = perm_to_num(p->perm);

			if (p->user) {
				struct passwd *pw;
				if ((pw = getpwnam(p->user)) == NULL) {
					fprintf(stderr, "Username not found: %s\n", p->user);
					exit(EXIT_FAILURE);
				}
				proc[i].uid = pw->pw_uid;
			}

			proc[i].log = 0;
			for (struct log_entry *l = p->log_list; l; l = l->next) {
				if (!strcmp(l->log_type, "read"))
					proc[i].log |= READ;
				else if (!strcmp(l->log_type, "write"))
					proc[i].log |= WRITE;
				else if (!strcmp(l->log_type, "open"))
					proc[i].log |= OPEN;
				else {
					fprintf(stderr, "Unknown log type: %s", l->log_type);
					exit(EXIT_FAILURE);
				}
			}

			++i;
		}

		if (!f->path) {
			fprintf(stderr, "File path not found");
			exit(EXIT_FAILURE);
		}

		// TODO: using u128 for improved hash collision resistance
		u64 path_hash = fnv1a((u8 *)f->path, strlen(f->path));

		bpf_map__update_elem(skel->maps.map_path_rules, &path_hash, sizeof(path_hash),
				     &proc, sizeof(proc), BPF_ANY);
	}

cleanup:
	yaml_parser_delete(&parser);
	free(state);
	fclose(input);

	if (exit_code)
		exit(exit_code);

	return exit_code;
}
