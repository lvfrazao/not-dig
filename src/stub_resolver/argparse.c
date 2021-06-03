#include <stdlib.h>
#include <argp.h>

int isint(char *str);

const char *argp_program_version =
    "not-dig 0.0.1";
const char *argp_program_bug_address =
    "<not-dig@frazao.ca>";
static char doc[] =
    "not-dig -- A minimal clone of BIND's dig tool";
static char args_doc[] = "QNAME QTYPE";
/* The options we understand. */
static struct argp_option options[] = {
    {"short", 's', 0, 0, "Only print answer rdata"},
    {"bin", 'b', 0, 0, "Output rdata in wire format"},
    {"port", 'p', "PORT", 0, "Port to send DNS query to"},
    {"server", '@', "SERVER", 0, "Server to send DNS query to"},
    {"output", 'o', "FILE", 0,
     "Output to FILE instead of standard output"},
    {0}};

/* Used by main to communicate with parse_opt. */
struct arguments
{
    char *args[2], *server_opt, *port_opt;
    int short_opt, bin_opt;
    char *output_file;
};

/* Parse a single option. */
static error_t
parse_opt(int key, char *arg, struct argp_state *state)
{
    /* Get the input argument from argp_parse, which we
     know is a pointer to our arguments structure. */
    struct arguments *arguments = state->input;
    #ifdef DEBUG
    printf("Key = %d, *arg = %p (%s)\n", key, arg, arg);
    #endif

    switch (key)
    {
    case 's':
        arguments->short_opt = 1;
        break;
    case 'b':
        arguments->bin_opt = 1;
        break;
    case 'p':
        if (arg != NULL && isint(arg) && atoi(arg) <= 65535 && atoi(arg) > 0)
        arguments->port_opt = arg;
        else
        {
            fprintf(stderr, "Port must be an integer under 65535\n");
            argp_usage(state);
        }
        break;
    case '@':
        arguments->server_opt = arg;
        break;
    case 'o':
        arguments->output_file = arg;
        break;

    case ARGP_KEY_ARG:
        if (state->arg_num >= 2)
            /* Too many arguments. */
            argp_usage(state);

        arguments->args[state->arg_num] = arg;

        break;

    case ARGP_KEY_END:
        if (state->arg_num < 1)
            /* Not enough arguments. */
            argp_usage(state);
        else if (state->arg_num == 1)
            arguments->args[1] = "A";
        break;

    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static struct argp argp = {options, parse_opt, args_doc, doc};

int isint(char *str)
{
    char *c = str;
    while (*c != '\0')
    {
        if (!isdigit(*c))
            return 0;
        c++;
    }
    return 1;
}
