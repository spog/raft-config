/*
# The RAFT-CONFIG project source code file
#
# Copyright (C) 2017 Samo Pogacnik <samo_pogacnik@t-2.net>
# All rights reserved.
#
# This file is part of the RAFT-CONFIG software project.
# This file is provided under the terms of the BSD 3-Clause license,
# available in the LICENSE file of the "daemonize" software project.
*/

#include <stdio.h>
#include <errno.h>
#include <getopt.h>
#include <stdlib.h>
#include <limits.h>

#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>

#include "log_module.h"
#include "raft-config.h"
#include "raft_netlink.h"

/*
 * The MAIN part.
 */
EVMLOG_MODULE_INIT(RAFT_CONFIG, 1);
#define EVMLOG_MODULE_DEBUG 1
#define EVMLOG_MODULE_TRACE 1

unsigned int log_mask;
unsigned int evmlog_normal = 1;
unsigned int evmlog_verbose = 0;
unsigned int evmlog_trace = 0;
unsigned int evmlog_debug = 0;
unsigned int evmlog_use_syslog = 0;
unsigned int evmlog_add_header = 0;

static void usage_help(char *argv[])
{
	printf("Usage:\n");
	printf("  %s [OPTIONS] COMMAND OBJECT [ObjectID] [PARAMS]\n", argv[0]);
	printf("\n");
	printf("OPTIONS:\n");
#if 0
	printf("  -q, --quiet              Disable all output.\n");
	printf("  -v, --verbose            Enable verbose output.\n");
#if (EVMLOG_MODULE_TRACE != 0)
	printf("  -t, --trace              Enable trace output.\n");
#endif
#endif
#if (EVMLOG_MODULE_DEBUG != 0)
	printf("  -g, --debug              Enable debug output.\n");
#endif
#if 0
	printf("  -s, --syslog             Enable syslog output (instead of stdout, stderr).\n");
	printf("  -n, --no-header          No EVMLOG header added to every evm_log_... output.\n");
#endif
	printf("  -h, --help               Displays this text.\n");
	printf("\n");
	printf(" if COMMAND := {add | set}\n");
	printf("then OBJECT := {{cluster | domain | node} ObjectID}\n");
	printf("    if OBJECT := {cluster value}\n");
	printf("  then PARAMS := {}\n");
	printf("    if OBJECT := {domain value}\n");
	printf("  then PARAMS := {clusterid value [heartbeat value] [election value] [maxnodes value]}\n");
	printf("    if OBJECT := {node value}\n");
	printf("  then PARAMS := {clusterid value domainid value [contact v4ip_address]}\n");
	printf("\n");
	printf(" if COMMAND := {del | show}\n");
	printf("then OBJECT := {{cluster | domain | node} [ObjectID]}\n");
	printf("    if OBJECT := {cluster [value]}\n");
	printf("  then PARAMS := {}\n");
	printf("    if OBJECT := {domain [value]}\n");
	printf("  then PARAMS := {clusterid value}\n");
	printf("    if OBJECT := {node [value]}\n");
	printf("  then PARAMS := {clusterid value domainid value}\n");
	printf("\n");
}

static const char *object_str[] = {
	RAFT_OBJ_UNSPEC_STR,
	RAFT_OBJ_CLUSTER_STR,
	RAFT_OBJ_DOMAIN_STR,
	RAFT_OBJ_NODE_STR,
};

static const char *command_str[] = {
	RAFT_CFG_CMD_UNSPEC_STR,
	RAFT_CFG_CMD_ADD_STR,
	RAFT_CFG_CMD_DEL_STR,
	RAFT_CFG_CMD_SET_STR,
	RAFT_CFG_CMD_SHOW_STR,
};

static int parse_param_value_v4addr(char *str, uint32_t *val)
{
	int err;
	struct nl_addr *a;

	if (str == NULL) return -1;
	if (val == NULL) return -1;

	err = nl_addr_parse(str, AF_INET, &a);
	if (err) {
		evm_log_error("Invalid address format\n");
		return -1;
	}

	*val = *(uint32_t*)nl_addr_get_binary_addr(a);;
	return 0;
}

static int parse_param_value_u32(char *str, uint32_t *val)
{
	char *endptr;
	unsigned long tmp;

	if (str == NULL) return -1;
	if (val == NULL) return -1;

	tmp = strtoul(str, &endptr, 10);

	/* Check for various possible errors */
	if ((errno == ERANGE && (tmp == ULONG_MAX))
	 || (errno != 0 && tmp == 0)) {
		perror("strtol");
		return -1;
	}
	if ((*str == '\0') || (*endptr != '\0')) {
		evm_log_error("Invalid digits were found\n");
		return -1;
	}

	*val = (uint32_t)tmp;
	return 0;
}

static const char *cluster_param_str[] = {
	RAFT_PAR_CLUSTER_UNSPEC_STR,
	RAFT_PAR_CLUSTER_ID_STR,
};

/* Params follow the "name value" pattern! */
static int parse_cluster_params(struct raft_config_req *cfg_req, int *optind, int argc, char *argv[])
{
	static struct raft_cluster_params cluster_params = {
		.param_type = RAFT_NLA_CLUSTER_UNSPEC,
		.id_value = 0,
	};

	if (cfg_req) {
		cluster_params.id_value = cfg_req->object_id;
	}
	while (*optind < argc) {
		int i;
		evm_log_debug("Parsing expected cluster param name: %s\n", argv[*optind]);
		cluster_params.param_type = RAFT_NLA_CLUSTER_UNSPEC;
		for (i = RAFT_NLA_CLUSTER_UNSPEC; i <= RAFT_NLA_CLUSTER_MAX; i++) {
			if (strstr(cluster_param_str[i], argv[*optind]) == cluster_param_str[i]) {
				cluster_params.param_type = i;
				break;
			}
		}
		(*optind)++;
		if (*optind >= argc) {
			evm_log_error("Missing cluster parameter value!\n");
			exit(EXIT_FAILURE);
		}
		evm_log_debug("Parsing expected cluster param value: %s\n", argv[*optind]);
		switch (cluster_params.param_type) {
		case RAFT_NLA_CLUSTER_UNSPEC:
		default:
			evm_log_error("Unknown parameter: %s!\n", argv[*optind]);
			exit(EXIT_FAILURE);
		}
		(*optind)++;
	}
	if (cluster_params.id_value == 0) {
		if (cfg_req->command_action != RAFT_CFG_CMD_SHOW) {
			evm_log_error("Missing cluster id!\n");
			exit(EXIT_FAILURE);
		}
	}
	cfg_req->command_params = (void *)&cluster_params;
	return 0;
}

static const char *domain_param_str[] = {
	RAFT_PAR_DOMAIN_UNSPEC_STR,
	RAFT_PAR_DOMAIN_ID_STR,
	RAFT_PAR_DOMAIN_HEARTBEAT_STR,
	RAFT_PAR_DOMAIN_ELECTION_STR,
	RAFT_PAR_DOMAIN_MAXNODES_STR,
	RAFT_PAR_DOMAIN_CLUSTERID_STR,
};

/* Params follow the "name value" pattern! */
static int parse_domain_params(struct raft_config_req *cfg_req, int *optind, int argc, char *argv[])
{
	static struct raft_domain_params domain_params = {
		.param_type = RAFT_NLA_DOMAIN_UNSPEC,
		.id_value = 0,
		.clusterid_value = 0,
		.is_set = {
			.heartbeat = 0,
			.election = 0,
			.maxnodes = 0,
		},
	};

	if (cfg_req) {
		domain_params.id_value = cfg_req->object_id;
	}
	while (*optind < argc) {
		int i;
		evm_log_debug("Parsing expected domain param name: %s\n", argv[*optind]);
		domain_params.param_type = RAFT_NLA_DOMAIN_UNSPEC;
		for (i = RAFT_NLA_DOMAIN_UNSPEC; i <= RAFT_NLA_DOMAIN_MAX; i++) {
			if (strstr(domain_param_str[i], argv[*optind]) == domain_param_str[i]) {
				domain_params.param_type = i;
				break;
			}
		}
		(*optind)++;
		if (*optind >= argc) {
			evm_log_error("Missing domain parameter value!\n");
			exit(EXIT_FAILURE);
		}
		evm_log_debug("Parsing expected domain param value: %s\n", argv[*optind]);
		switch (domain_params.param_type) {
		case RAFT_NLA_DOMAIN_HEARTBEAT:
			if (parse_param_value_u32(argv[*optind], &domain_params.heartbeat_value) < 0) {
				exit(EXIT_FAILURE);
			}
			evm_log_debug("Parsed expected domain heartbeat value: %lu\n", domain_params.heartbeat_value);
			domain_params.is_set.heartbeat = 1;
			break;
		case RAFT_NLA_DOMAIN_ELECTION:
			if (parse_param_value_u32(argv[*optind], &domain_params.election_value) < 0) {
				exit(EXIT_FAILURE);
			}
			evm_log_debug("Parsed expected domain election value: %lu\n", domain_params.election_value);
			domain_params.is_set.election = 1;
			break;
		case RAFT_NLA_DOMAIN_MAXNODES:
			if (parse_param_value_u32(argv[*optind], &domain_params.maxnodes_value) < 0) {
				exit(EXIT_FAILURE);
			}
			evm_log_debug("Parsed expected domain maxnodes value: %lu\n", domain_params.maxnodes_value);
			domain_params.is_set.maxnodes = 1;
			break;
		case RAFT_NLA_DOMAIN_CLUSTERID:
			if (parse_param_value_u32(argv[*optind], &domain_params.clusterid_value) < 0) {
				exit(EXIT_FAILURE);
			}
			evm_log_debug("Parsed expected domain clusterid value: %lu\n", domain_params.clusterid_value);
			break;
		case RAFT_NLA_DOMAIN_UNSPEC:
		default:
			evm_log_error("Unknown domain parameter: %s!\n", argv[*optind]);
			exit(EXIT_FAILURE);
		}
		(*optind)++;
	}
	if (domain_params.id_value == 0) {
		if (cfg_req->command_action != RAFT_CFG_CMD_SHOW) {
			evm_log_error("Missing domain id!\n");
			exit(EXIT_FAILURE);
		}
	}
	if (domain_params.clusterid_value == 0) {
		evm_log_error("Missing clusterid!\n");
		exit(EXIT_FAILURE);
	}
	cfg_req->command_params = (void *)&domain_params;
	return 0;
}

static const char *node_param_str[] = {
	RAFT_PAR_NODE_UNSPEC_STR,
	RAFT_PAR_NODE_ID_STR,
	RAFT_PAR_NODE_CONTACT_STR,
	RAFT_PAR_NODE_DOMAINID_STR,
	RAFT_PAR_NODE_CLUSTERID_STR,
};

/* Params follow the "name value" pattern! */
static int parse_node_params(struct raft_config_req *cfg_req, int *optind, int argc, char *argv[])
{
	static struct raft_node_params node_params = {
		.param_type = RAFT_NLA_NODE_UNSPEC,
		.id_value = 0,
		.domainid_value = 0,
		.clusterid_value = 0,
		.is_set = {
			.contact = 0,
		},
	};

	if (cfg_req) {
		node_params.id_value = cfg_req->object_id;
	}
	while (*optind < argc) {
		int i;
		evm_log_debug("Parsing expected node param name: %s\n", argv[*optind]);
		node_params.param_type = RAFT_NLA_NODE_UNSPEC;
		for (i = RAFT_NLA_NODE_UNSPEC; i <= RAFT_NLA_NODE_MAX; i++) {
			if (strstr(node_param_str[i], argv[*optind]) == node_param_str[i]) {
				node_params.param_type = i;
				break;
			}
		}
		if (node_params.param_type == RAFT_NLA_NODE_UNSPEC) {
			evm_log_error("Unknown node parameter: %s!\n", argv[*optind]);
			exit(EXIT_FAILURE);
		}
		(*optind)++;
		if (*optind >= argc) {
			evm_log_error("Missing node parameter value!\n");
			exit(EXIT_FAILURE);
		}
		evm_log_debug("Parsing expected node param value: %s\n", argv[*optind]);
		switch (node_params.param_type) {
		case RAFT_NLA_NODE_CONTACT:
			if (parse_param_value_v4addr(argv[*optind], &node_params.contact_value) < 0) {
				exit(EXIT_FAILURE);
			}
			evm_log_debug("Parsed expected node contact value: 0x%x\n", node_params.contact_value);
			node_params.is_set.contact = 1;
			break;
		case RAFT_NLA_NODE_DOMAINID:
			if (parse_param_value_u32(argv[*optind], &node_params.domainid_value) < 0) {
				exit(EXIT_FAILURE);
			}
			evm_log_debug("Parsed expected node domainid value: %lu\n", node_params.domainid_value);
			break;
		case RAFT_NLA_NODE_CLUSTERID:
			if (parse_param_value_u32(argv[*optind], &node_params.clusterid_value) < 0) {
				exit(EXIT_FAILURE);
			}
			evm_log_debug("Parsed expected node clusterid value: %lu\n", node_params.clusterid_value);
			break;
		case RAFT_NLA_NODE_UNSPEC:
		default:
			evm_log_error("Unknown node parameter: %s!\n", argv[*optind]);
			exit(EXIT_FAILURE);
		}
		(*optind)++;
	}
	if (node_params.id_value == 0) {
		if (cfg_req->command_action != RAFT_CFG_CMD_SHOW) {
			evm_log_error("Missing node id!\n");
			exit(EXIT_FAILURE);
		}
	}
	if (node_params.domainid_value == 0) {
		evm_log_error("Missing domainid!\n");
		exit(EXIT_FAILURE);
	}
	if (node_params.clusterid_value == 0) {
		evm_log_error("Missing clusterid!\n");
		exit(EXIT_FAILURE);
	}
	cfg_req->command_params = (void *)&node_params;
	return 0;
}

static int usage_check(int argc, char *argv[], struct raft_config_req **req)
{
	int c;
	int ret = 0;
	static struct raft_config_req cfg_req = {
		.object_type = RAFT_NLA_UNSPEC,
		.command_action = RAFT_CFG_CMD_UNSPEC,
		.command_params = NULL,
	};

	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
#if 0
			{"quiet", 0, 0, 'q'},
			{"verbose", 0, 0, 'v'},
#if (EVMLOG_MODULE_TRACE != 0)
			{"trace", 0, 0, 't'},
#endif
#endif
#if (EVMLOG_MODULE_DEBUG != 0)
			{"debug", 0, 0, 'g'},
#endif
#if 0
			{"no-header", 0, 0, 'n'},
			{"syslog", 0, 0, 's'},
#endif
			{"help", 0, 0, 'h'},
			{0, 0, 0, 0}
		};

#if 0
#if (EVMLOG_MODULE_TRACE != 0) && (EVMLOG_MODULE_DEBUG != 0)
		c = getopt_long(argc, argv, "qvtgnsh", long_options, &option_index);
#elif (EVMLOG_MODULE_TRACE == 0) && (EVMLOG_MODULE_DEBUG != 0)
		c = getopt_long(argc, argv, "qvgnsh", long_options, &option_index);
#elif (EVMLOG_MODULE_TRACE != 0) && (EVMLOG_MODULE_DEBUG == 0)
		c = getopt_long(argc, argv, "qvtnsh", long_options, &option_index);
#else
		c = getopt_long(argc, argv, "qvnsh", long_options, &option_index);
#endif
#endif
		c = getopt_long(argc, argv, "gh", long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
#if 0
		case 'q':
			evmlog_normal = 0;
			break;

		case 'v':
			evmlog_verbose = 1;
			break;

#if (EVMLOG_MODULE_TRACE != 0)
		case 't':
			evmlog_trace = 1;
			break;
#endif
#endif

#if (EVMLOG_MODULE_DEBUG != 0)
		case 'g':
			evmlog_debug = 1;
			break;
#endif

#if 0
		case 'n':
			evmlog_add_header = 0;
			break;

		case 's':
			evmlog_use_syslog = 1;
			break;
#endif

		case 'h':
			usage_help(argv);
			exit(EXIT_SUCCESS);

		case '?':
			usage_help(argv);
			exit(EXIT_FAILURE);
			break;

		default:
			printf("?? getopt returned character code 0%o ??\n", c);
			usage_help(argv);
			exit(EXIT_FAILURE);
		}
	}

	log_mask = LOG_MASK(LOG_EMERG) | LOG_MASK(LOG_ALERT) | LOG_MASK(LOG_CRIT) | LOG_MASK(LOG_ERR);

	/* Setup LOG_MASK according to startup arguments! */
	if (evmlog_normal) {
		log_mask |= LOG_MASK(LOG_WARNING);
		log_mask |= LOG_MASK(LOG_NOTICE);
	}
	if ((evmlog_verbose) || (evmlog_trace))
		log_mask |= LOG_MASK(LOG_INFO);
	if (evmlog_debug)
		log_mask |= LOG_MASK(LOG_DEBUG);

	setlogmask(log_mask);

	if (optind < argc) {
		int i;

		evm_log_debug("Parsing expected command action string: %s\n", argv[optind]);
		for (i = RAFT_CFG_CMD_UNSPEC; i <= RAFT_CFG_CMD_MAX; i++) {
			if (strstr(command_str[i], argv[optind]) == command_str[i]) {
				cfg_req.command_action = i;
				break;
			}
		}
		if (cfg_req.command_action == RAFT_CFG_CMD_UNSPEC) {
			evm_log_error("Unknown COMMAND: %s!\n", argv[optind]);
			exit(EXIT_FAILURE);
		}

		optind++;
		if (optind < argc) {
			evm_log_debug("Parsing expected object string: %s\n", argv[optind]);
			for (i = RAFT_NLA_UNSPEC; i <= RAFT_NLA_MAX; i++) {
				if (strstr(object_str[i], argv[optind]) == object_str[i]) {
					cfg_req.object_type = i;
					break;
				}
			}
			if (cfg_req.object_type == RAFT_NLA_UNSPEC) {
				evm_log_error("Unknown object: %s!\n", argv[optind]);
				exit(EXIT_FAILURE);
			}
		} else {
			evm_log_error("Missing OBJECT!\n");
			exit(EXIT_FAILURE);
		}

		optind++;
		if (optind < argc) {
			evm_log_debug("Parsing expected Object_ID value: %s\n", argv[optind]);
			if (parse_param_value_u32(argv[optind], &cfg_req.object_id) < 0) {
				if (cfg_req.command_action != RAFT_CFG_CMD_SHOW) {
					exit(EXIT_FAILURE);
				}
			}
			evm_log_debug("Parsed expected Object_ID value: %lu\n", cfg_req.object_id);
			if (cfg_req.object_id == 0) {
				if (cfg_req.command_action != RAFT_CFG_CMD_SHOW) {
					evm_log_error("Unknown Object_ID: %s!\n", argv[optind]);
					exit(EXIT_FAILURE);
				} else
					optind--;
			}
		} else {
			if (cfg_req.command_action != RAFT_CFG_CMD_SHOW) {
				evm_log_error("Missing Object_ID!\n");
				exit(EXIT_FAILURE);
			}
		}

		optind++;
		switch (cfg_req.object_type) {
		case RAFT_NLA_CLUSTER:
			ret = parse_cluster_params(&cfg_req, &optind, argc, argv);
			break;
		case RAFT_NLA_DOMAIN:
			ret = parse_domain_params(&cfg_req, &optind, argc, argv);
			break;
		case RAFT_NLA_NODE:
			ret = parse_node_params(&cfg_req, &optind, argc, argv);
			break;
		default:
			evm_log_error("Missing command parameters!\n");
			exit(EXIT_FAILURE);
		}
		if (optind < argc) {
			printf("Unknown ARGV-elements: ");
			while (optind < argc)
				printf("%s ", argv[optind++]);
			printf("\n");
			exit(EXIT_FAILURE);
		}
	} else {
		evm_log_error("Missing COMMAND!\n");
		usage_help(argv);
		exit(EXIT_FAILURE);
	}

	if (req != NULL)
		*req = &cfg_req;

	return ret;
}

int main(int argc, char *argv[])
{
	struct raft_config_req *raft_cfg_req = NULL;

	usage_check(argc, argv, &raft_cfg_req);

	evm_log_debug("raft_cfg_req=%p\n", raft_cfg_req);
	if (raft_config_request(raft_cfg_req) < 0)
		exit(EXIT_FAILURE);

	exit(EXIT_SUCCESS);
}

static int recv_msg(struct nl_msg *msg, void *arg)
{
	int *ret = arg;
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct nlattr *attrs[RAFT_NLA_MAX+1];

	printf("recv_msg\n");
	/* in theory we could use genlmsg_parse
 	 * but on my system it does not work ->
 	 * we use nla_parse */
//	genlmsg_parse(nlh, 0, attrs, DOC_EXMPL_A_MAX, NULL);
	struct genlmsghdr *ghdr = nlmsg_data(nlh);
	if (nla_parse(attrs, RAFT_NLA_MAX, genlmsg_attrdata(ghdr, 0),
			 genlmsg_attrlen(ghdr, 0), NULL) < 0) {
		printf("couldn't parse attributes\n");
		return -1;
	}

	/* the data is in the attribute RAFT_NLA_CLUSTER */
	if (attrs[RAFT_NLA_CLUSTER]) {
		char *value = nla_get_string(attrs[RAFT_NLA_CLUSTER]);
		printf("message received: %s\n", value);
	}
	else {
		printf("error receiving message\n");
	}

	*ret = 0;
	return 0;
}

static int put_cluster_attrs(struct nl_msg *msg, struct raft_config_req *cfg_req)
{
	struct nlattr *opts;
	struct raft_cluster_params *cfg_params = (struct raft_cluster_params *)cfg_req->command_params;

	if (!(opts = nla_nest_start(msg, RAFT_NLA_CLUSTER)))
		goto nla_put_failure;

	nla_put_u32(msg, RAFT_NLA_CLUSTER_ID, cfg_params->id_value);
//	NLA_PUT_U32(msg, RAFT_NLA_CLUSTER_ID, cfg_params->id_value);
//	NLA_PUT_STRING(msg, NESTED_BAR, "some text");

	nla_nest_end(msg, opts);
	return 0;

nla_put_failure:
	nla_nest_cancel(msg, opts);
	return -EMSGSIZE;
}

static int put_domain_attrs(struct nl_msg *msg, struct raft_config_req *cfg_req)
{
	struct nlattr *opts;
	struct raft_domain_params *cfg_params = (struct raft_domain_params *)cfg_req->command_params;

	if (!(opts = nla_nest_start(msg, RAFT_NLA_DOMAIN)))
		goto nla_put_failure;

	nla_put_u32(msg, RAFT_NLA_DOMAIN_ID, cfg_params->id_value);
	if (cfg_params->is_set.heartbeat)
		nla_put_u32(msg, RAFT_NLA_DOMAIN_HEARTBEAT, cfg_params->heartbeat_value);
	if (cfg_params->is_set.election)
		nla_put_u32(msg, RAFT_NLA_DOMAIN_ELECTION, cfg_params->election_value);
	if (cfg_params->is_set.maxnodes)
		nla_put_u32(msg, RAFT_NLA_DOMAIN_MAXNODES, cfg_params->maxnodes_value);
	nla_put_u32(msg, RAFT_NLA_DOMAIN_CLUSTERID, cfg_params->clusterid_value);

	nla_nest_end(msg, opts);
	return 0;

nla_put_failure:
	nla_nest_cancel(msg, opts);
	return -EMSGSIZE;
}

static int put_node_attrs(struct nl_msg *msg, struct raft_config_req *cfg_req)
{
	struct nlattr *opts;
	struct raft_node_params *cfg_params = (struct raft_node_params *)cfg_req->command_params;

	if (!(opts = nla_nest_start(msg, RAFT_NLA_NODE)))
		goto nla_put_failure;

	nla_put_u32(msg, RAFT_NLA_NODE_ID, cfg_params->id_value);
	if (cfg_params->is_set.contact)
		nla_put_u32(msg, RAFT_NLA_NODE_CONTACT, cfg_params->contact_value);
	nla_put_u32(msg, RAFT_NLA_NODE_DOMAINID, cfg_params->domainid_value);
	nla_put_u32(msg, RAFT_NLA_NODE_CLUSTERID, cfg_params->clusterid_value);

	nla_nest_end(msg, opts);
	return 0;

nla_put_failure:
	nla_nest_cancel(msg, opts);
	return -EMSGSIZE;
}

int raft_config_request(struct raft_config_req *cfg_req)
{
	int family_id;
	int family;
	int ret;
	int err = 1;
	int nl_cmd;
	int nl_flags;

//	struct rtgenmsg rt_hdr = { .rtgen_family = AF_PACKET, };
	struct nl_msg *msg;
	struct nl_cb *cb;

	// Open socket to kernel.
	struct nl_sock *socket = nl_socket_alloc();  // Allocate new netlink socket in memory.
	if (!socket) {
		evm_log_error("Failed to allocate netlink socket.\n");
		return -ENOMEM;
	}

	genl_connect(socket);  // Create file descriptor and bind socket.
	family = genl_ctrl_resolve(socket, RAFT_GENL_V2_NAME);  

	msg = nlmsg_alloc();
	if (!msg) {
		evm_log_error("Failed to allocate netlink message.\n");
		return -ENOMEM;
	}
#if 0
	cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (!cb) {
		fprintf(stderr, "Failed to allocate netlink callback.\n");
		nlmsg_free(msg);
		return -ENOMEM;
	}
	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, list_interface_handler, NULL);
#endif

	evm_log_debug("i am raft-config (family=%d)!\n", family);

	switch (cfg_req->object_type) {
	case RAFT_NLA_CLUSTER:
		switch (cfg_req->command_action) {
		case RAFT_CFG_CMD_ADD:
			nl_cmd = RAFT_NL_CLUSTER_ADD;
			nl_flags = NLM_F_REQUEST;
			genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family, 0, nl_flags, nl_cmd, 0);
			put_cluster_attrs(msg, cfg_req);
			break;
		case RAFT_CFG_CMD_DEL:
			nl_cmd = RAFT_NL_CLUSTER_DEL;
			nl_flags = NLM_F_REQUEST;
			genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family, 0, nl_flags, nl_cmd, 0);
			put_cluster_attrs(msg, cfg_req);
			break;
		case RAFT_CFG_CMD_SET:
			nl_cmd = RAFT_NL_CLUSTER_SET;
			nl_flags = NLM_F_REQUEST;
			genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family, 0, nl_flags, nl_cmd, 0);
			put_cluster_attrs(msg, cfg_req);
			break;
		case RAFT_CFG_CMD_SHOW:
			nl_cmd = RAFT_NL_CLUSTER_SHOW;
			nl_flags = NLM_F_DUMP;
			genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family, 0, nl_flags, nl_cmd, 0);
			put_cluster_attrs(msg, cfg_req);
			break;
		default:
			evm_log_error("Command not defined!\n");
			exit(EXIT_FAILURE);
		}
		break;
	case RAFT_NLA_DOMAIN:
		switch (cfg_req->command_action) {
		case RAFT_CFG_CMD_ADD:
			nl_cmd = RAFT_NL_DOMAIN_ADD;
			nl_flags = NLM_F_REQUEST;
			genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family, 0, nl_flags, nl_cmd, 0);
			put_domain_attrs(msg, cfg_req);
			break;
		case RAFT_CFG_CMD_DEL:
			nl_cmd = RAFT_NL_DOMAIN_DEL;
			nl_flags = NLM_F_REQUEST;
			genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family, 0, nl_flags, nl_cmd, 0);
			put_domain_attrs(msg, cfg_req);
			break;
		case RAFT_CFG_CMD_SET:
			nl_cmd = RAFT_NL_DOMAIN_SET;
			nl_flags = NLM_F_REQUEST;
			genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family, 0, nl_flags, nl_cmd, 0);
			put_domain_attrs(msg, cfg_req);
			break;
		case RAFT_CFG_CMD_SHOW:
			nl_cmd = RAFT_NL_DOMAIN_SHOW;
			nl_flags = NLM_F_DUMP;
			genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family, 0, nl_flags, nl_cmd, 0);
			put_domain_attrs(msg, cfg_req);
			break;
		default:
			evm_log_error("Command not defined!\n");
			exit(EXIT_FAILURE);
		}
		break;
	case RAFT_NLA_NODE:
		switch (cfg_req->command_action) {
		case RAFT_CFG_CMD_ADD:
			nl_cmd = RAFT_NL_NODE_ADD;
			nl_flags = NLM_F_REQUEST;
			genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family, 0, nl_flags, nl_cmd, 0);
			put_node_attrs(msg, cfg_req);
			break;
		case RAFT_CFG_CMD_DEL:
			nl_cmd = RAFT_NL_NODE_DEL;
			nl_flags = NLM_F_REQUEST;
			genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family, 0, nl_flags, nl_cmd, 0);
			put_node_attrs(msg, cfg_req);
			break;
		case RAFT_CFG_CMD_SET:
			nl_cmd = RAFT_NL_NODE_SET;
			nl_flags = NLM_F_REQUEST;
			genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family, 0, nl_flags, nl_cmd, 0);
			put_node_attrs(msg, cfg_req);
			break;
		case RAFT_CFG_CMD_SHOW:
			nl_cmd = RAFT_NL_NODE_SHOW;
			nl_flags = NLM_F_DUMP;
			genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family, 0, nl_flags, nl_cmd, 0);
			put_node_attrs(msg, cfg_req);
			break;
		default:
			evm_log_error("Command not defined!\n");
			exit(EXIT_FAILURE);
		}
		break;
	default:
		evm_log_error("Object not defined!\n");
		exit(EXIT_FAILURE);
	}
//	genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family, 0, nl_flags, nl_cmd, 0);
	nl_send_auto_complete(socket, msg);
	nlmsg_free(msg);

//	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);

	/* set the callback function to receive answers to recv_msg */
	if (nl_socket_modify_cb(socket, NL_CB_MSG_IN, NL_CB_CUSTOM, recv_msg, &err) < 0) {
		evm_log_error("error setting callback function\n");
		
		goto out;
	}

	while (err > 0)
//		nl_recvmsgs(socket, cb);
		nl_recvmsgs_default(socket);

out:
//	nl_cb_put(cb);

	nl_socket_free(socket);

	return 0;
}


