#include <yaml.h>
#include <stdio.h>
#include <assert.h>

void handle_error(const char *msg)
{
	fprintf(stderr, "%s\n", msg);
	exit(1);
}

enum state {
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
	STATE_PROCESS_LOGGING,

	STATE_LOGGING_LIST,

	STATE_STOP /* end state */
};

struct logging {
	struct logging *next;
	char *logging_type;
};

struct process {
	struct process *next;
	char *path;
	char *user;
	char *permission;
	char *cwd;
	int pid;
	int ppid;
	struct logging *l; // last l
	struct logging *llist; // list l
};

struct file {
	struct file *next;
	char *path;
	struct process *p; // last p
	struct process *plist; // list p
};

struct parser_state {
	enum state state;
	struct file *f; // last f
	struct file *flist; // list f
};

enum status { FAILURE = 0, SUCCESS = 1 };

int consume_event(struct parser_state *s, yaml_event_t *event)
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
			return FAILURE;
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
			return FAILURE;
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
			return FAILURE;
		}
		break;

	case STATE_RULE:
		switch (event->type) {
		case YAML_SCALAR_EVENT:
			value = (char *)event->data.scalar.value;
			if (!strcmp(value, "rule")) {
				s->state = STATE_RULE_LIST;
			} else {
				fprintf(stderr, "Unexpected scalar: %s\n", value);
				return FAILURE;
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
			return FAILURE;
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
			return FAILURE;
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
			return FAILURE;
		}
		break;

	case STATE_FILE:
		switch (event->type) {
		case YAML_SCALAR_EVENT:
			value = (char *)event->data.scalar.value;
			struct file *f = calloc(1, sizeof(struct file));
			f->path = strdup(value);
			if (s->flist == NULL)
				s->flist = f;
			else
				s->f->next = f;
			s->f = f;
			s->state = STATE_PROCESS_LIST;
			break;
		case YAML_MAPPING_END_EVENT:
			s->state = STATE_RULE_VALUE;
			break;
		default:
			fprintf(stderr, "Unexpected event %d in state %d.\n", event->type,
				s->state);
			return FAILURE;
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
			return FAILURE;
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
			return FAILURE;
		}
		break;

	case STATE_PROCESS:
		switch (event->type) {
		case YAML_SCALAR_EVENT:
			value = (char *)event->data.scalar.value;
			struct process *p = calloc(1, sizeof(struct process));
			p->path = strdup(value);
			if (s->f->plist == NULL)
				s->f->plist = p;
			else
				s->f->plist->next = p;
			s->f->p = p;
			s->state = STATE_PROCESS_ATTRIBUTES;
			break;
		case YAML_MAPPING_END_EVENT:
			s->state = STATE_PROCESS_VALUES;
			break;
		default:
			fprintf(stderr, "Unexpected event %d in state %d.\n", event->type,
				s->state);
			return FAILURE;
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
			return FAILURE;
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
			else if (!strcmp(value, "permission"))
				s->state = STATE_PROCESS_PERMISSION;
			else if (!strcmp(value, "cwd"))
				s->state = STATE_PROCESS_CWD;
			else if (!strcmp(value, "logging"))
				s->state = STATE_PROCESS_LOGGING;
			break;
		case YAML_MAPPING_END_EVENT:
			s->state = STATE_PROCESS;
			break;
		default:
			fprintf(stderr, "Unexpected event %d in state %d.\n", event->type,
				s->state);
			return FAILURE;
		}
		break;

	case STATE_PROCESS_USER:
		switch (event->type) {
		case YAML_SCALAR_EVENT:
			value = (char *)event->data.scalar.value;
			s->f->p->user = strdup(value);
			s->state = STATE_PROCESS_ATTRIBUTE_KEY;
			break;

		default:
			fprintf(stderr, "Unexpected event %d in state %d.\n", event->type,
				s->state);
			return FAILURE;
		}
		break;

	case STATE_PROCESS_PID:
		switch (event->type) {
		case YAML_SCALAR_EVENT:
			value = (char *)event->data.scalar.value;
			s->f->p->pid = atoi(value);
			s->state = STATE_PROCESS_ATTRIBUTE_KEY;
			break;

		default:
			fprintf(stderr, "Unexpected event %d in state %d.\n", event->type,
				s->state);
			return FAILURE;
		}
		break;

	case STATE_PROCESS_PPID:
		switch (event->type) {
		case YAML_SCALAR_EVENT:
			value = (char *)event->data.scalar.value;
			s->f->p->ppid = atoi(value);
			s->state = STATE_PROCESS_ATTRIBUTE_KEY;
			break;

		default:
			fprintf(stderr, "Unexpected event %d in state %d.\n", event->type,
				s->state);
			return FAILURE;
		}
		break;

	case STATE_PROCESS_PERMISSION:
		switch (event->type) {
		case YAML_SCALAR_EVENT:
			value = (char *)event->data.scalar.value;
			s->f->p->permission = strdup(value);
			s->state = STATE_PROCESS_ATTRIBUTE_KEY;
			break;

		default:
			fprintf(stderr, "Unexpected event %d in state %d.\n", event->type,
				s->state);
			return FAILURE;
		}
		break;

	case STATE_PROCESS_CWD:
		switch (event->type) {
		case YAML_SCALAR_EVENT:
			value = (char *)event->data.scalar.value;
			s->f->p->cwd = strdup(value);
			s->state = STATE_PROCESS_ATTRIBUTE_KEY;
			break;

		default:
			fprintf(stderr, "Unexpected event %d in state %d.\n", event->type,
				s->state);
			return FAILURE;
		}
		break;

	case STATE_PROCESS_LOGGING:
		switch (event->type) {
		case YAML_SEQUENCE_START_EVENT:
			s->state = STATE_LOGGING_LIST;
			break;

		default:
			fprintf(stderr, "Unexpected event %d in state %d.\n", event->type,
				s->state);
			return FAILURE;
		}
		break;

	case STATE_LOGGING_LIST:
		switch (event->type) {
		case YAML_SCALAR_EVENT:
			value = (char *)event->data.scalar.value;
			struct logging *l = calloc(1, sizeof(struct logging));
			l->logging_type = strdup(value);
			if (s->f->p->llist == NULL)
				s->f->p->llist = l;
			else
				s->f->p->l->next = l;
			s->f->p->l = l;
			s->state = STATE_LOGGING_LIST;
			break;
		case YAML_SEQUENCE_END_EVENT:
			s->state = STATE_PROCESS_ATTRIBUTE_KEY;
			break;
		default:
			fprintf(stderr, "Unexpected event %d in state %d.\n", event->type,
				s->state);
			return FAILURE;
		}
		break;

	case STATE_STOP:
		return SUCCESS;

	default:
		break;
	}

	return SUCCESS;
}

void clean(struct parser_state *state)
{
	for (struct file *f = state->flist; f;) {
		for (struct process *p = f->plist; p;) {
			free(p->path);
			free(p->user);
			free(p->cwd);
			free(p->permission);
			for (struct logging *l = p->llist; l;) {
				struct logging *tmp = l->next;
				free(l->logging_type);
				free(l);
				l = tmp;
			}
			struct process *tmp = p->next;
			free(p);
			p = tmp;
		}
		struct file *tmp = f->next;
		free(f);
		f = tmp;
	}
}

int parse(struct parser_state *state, char *rulefile)
{
	FILE *input = fopen(rulefile, "rb");
	int code;
	yaml_parser_t parser;
	yaml_event_t event;
	enum status status;

	memset(state, 0, sizeof(struct parser_state));
	state->state = STATE_START;
	assert(input);

	if (!yaml_parser_initialize(&parser))
		handle_error("Could not initialize the parser object");

	yaml_parser_set_input_file(&parser, input);

	do {
		if (!yaml_parser_parse(&parser, &event))
			handle_error(parser.problem);

		status = consume_event(state, &event);

		if (status == FAILURE) {
			fprintf(stderr, "consume_event error\n");
			code = EXIT_FAILURE;
			goto done;
		}

		yaml_event_delete(&event);
		if (status == FAILURE) {
			fprintf(stderr, "consume_event error\n");
			code = EXIT_FAILURE;
			goto done;
		}
	} while (state->state != STATE_STOP);

	for (struct file *f = state->flist; f; f = f->next) {
		printf("file: path: %s\n", f->path);
		for (struct process *p = f->plist; p; p = p->next) {
			printf("   process: %s\n", p->path);
			printf("      user: %s\n", p->user);
			printf("      pid: %d\n", p->pid);
			printf("      ppid: %d\n", p->ppid);
			printf("      cwd: %s\n", p->cwd);
			printf("      permission: %s\n", p->permission);
			printf("      logging: ");
			for (struct logging *l = p->llist; l; l = l->next)
				printf("%s, ", l->logging_type);
			putchar('\n');
		}
	}
	code = EXIT_SUCCESS;

done:
	yaml_parser_delete(&parser);
	fclose(input);
	return code;
}

// int main()
// {
//     int code = parse("rules.yaml");
//     return code;
// }