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
unsigned int log_mask;
unsigned int evmlog_normal = 1;
unsigned int evmlog_verbose = 0;
unsigned int evmlog_trace = 0;
unsigned int evmlog_debug = 0;
unsigned int evmlog_use_syslog = 0;
unsigned int evmlog_add_header = 1;

static void usage_help(char *argv[])
{
	printf("Usage:\n");
	printf("\t%s [options] object [command]\n", argv[0]);
	printf("options:\n");
	printf("\t-q, --quiet              Disable all output.\n");
	printf("\t-v, --verbose            Enable verbose output.\n");
#if (EVMLOG_MODULE_TRACE != 0)
	printf("\t-t, --trace              Enable trace output.\n");
#endif
#if (EVMLOG_MODULE_DEBUG != 0)
	printf("\t-g, --debug              Enable debug output.\n");
#endif
	printf("\t-s, --syslog             Enable syslog output (instead of stdout, stderr).\n");
	printf("\t-n, --no-header          No EVMLOG header added to every evm_log_... output.\n");
	printf("\t-h, --help               Displays this text.\n");
}

static const char *object_str[] = {
	RAFT_OBJ_UNSPEC_STR,
	RAFT_OBJ_CLUSTER_STR,
	RAFT_OBJ_DOMAIN_STR,
	RAFT_OBJ_NODE_STR,
};

static const char *cluster_param_str[] = {
	RAFT_PAR_CLUSTER_UNSPEC_STR,
	RAFT_PAR_CLUSTER_ID_STR,
};

static int parse_cluster_param_value_id(char *str, unsigned long *val)
{
	char *endptr;

	if (str == NULL) return -1;
	if (val == NULL) return -1;

	*val = strtol(str, &endptr, 10);

	/* Check for various possible errors */
	if ((errno == ERANGE && (*val == LONG_MAX || *val == LONG_MIN))
	 || (errno != 0 && *val == 0)) {
		perror("strtol");
		return -1;
	}
	if ((*str == '\0') || (*endptr != '\0')) {
		fprintf(stderr, "Invalid digits were found\n");
		return -1;
	}

	return 0;
}

/* Params follow the "name value" pattern! */
static int parse_cluster_params(struct raft_config_req *cfg_req, int *optind, int argc, char *argv[])
{
	static struct raft_cluster_params cluster_params = {
		.param_type = RAFT_NLA_CLUSTER_UNSPEC,
		.id_value = 0,
	};

	while (*optind < argc) {
		int i;
		printf("Parsing expected cluster param name: %s\n", argv[*optind]);
		for (i = RAFT_NLA_CLUSTER_UNSPEC; i <= RAFT_NLA_CLUSTER_MAX; i++) {
			if (strstr(cluster_param_str[i], argv[*optind]) == cluster_param_str[i]) {
				cluster_params.param_type = i;
				break;
			}
		}
		(*optind)++;
		if (*optind >= argc) {
			printf("Missing parameter value!\n");
			exit(EXIT_FAILURE);
		}
		printf("Parsing expected cluster param value: %s\n", argv[*optind]);
		switch (cluster_params.param_type) {
		case RAFT_NLA_CLUSTER_ID:
			if (parse_cluster_param_value_id(argv[*optind], &cluster_params.id_value) < 0) {
				exit(EXIT_FAILURE);
			}
			break;
		case RAFT_NLA_CLUSTER_UNSPEC:
		default:
			printf("Unknown parameter required!\n");
			exit(EXIT_FAILURE);
		}
		(*optind)++;
	}
	return 0;
}

/* Params follow the "name value" pattern! */
static int parse_domain_params(struct raft_config_req *cfg_req, int *optind, int argc, char *argv[])
{
	return 0;
}

/* Params follow the "name value" pattern! */
static int parse_node_params(struct raft_config_req *cfg_req, int *optind, int argc, char *argv[])
{
	return 0;
}

static int usage_check(int argc, char *argv[])
{
	int c;
	int ret = 0;
	struct raft_config_req cfg_req = {
		.object_type = RAFT_NLA_UNSPEC,
		.command_action = RAFT_CFG_CMD_UNSPEC,
		.command_params = NULL,
	};

	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
			{"quiet", 0, 0, 'q'},
			{"verbose", 0, 0, 'v'},
#if (EVMLOG_MODULE_TRACE != 0)
			{"trace", 0, 0, 't'},
#endif
#if (EVMLOG_MODULE_DEBUG != 0)
			{"debug", 0, 0, 'g'},
#endif
			{"no-header", 0, 0, 'n'},
			{"syslog", 0, 0, 's'},
			{"help", 0, 0, 'h'},
			{0, 0, 0, 0}
		};

#if (EVMLOG_MODULE_TRACE != 0) && (EVMLOG_MODULE_DEBUG != 0)
		c = getopt_long(argc, argv, "qvtgnsh", long_options, &option_index);
#elif (EVMLOG_MODULE_TRACE == 0) && (EVMLOG_MODULE_DEBUG != 0)
		c = getopt_long(argc, argv, "qvgnsh", long_options, &option_index);
#elif (EVMLOG_MODULE_TRACE != 0) && (EVMLOG_MODULE_DEBUG == 0)
		c = getopt_long(argc, argv, "qvtnsh", long_options, &option_index);
#else
		c = getopt_long(argc, argv, "qvnsh", long_options, &option_index);
#endif
		if (c == -1)
			break;

		switch (c) {
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

#if (EVMLOG_MODULE_DEBUG != 0)
		case 'g':
			evmlog_debug = 1;
			break;
#endif

		case 'n':
			evmlog_add_header = 0;
			break;

		case 's':
			evmlog_use_syslog = 1;
			break;

		case 'h':
			usage_help(argv);
			exit(EXIT_SUCCESS);

		case '?':
			exit(EXIT_FAILURE);
			break;

		default:
			printf("?? getopt returned character code 0%o ??\n", c);
			exit(EXIT_FAILURE);
		}
	}

	if (optind < argc) {
		int i;
		printf("Parsing expected object string: %s\n", argv[optind]);
		for (i = RAFT_NLA_UNSPEC; i <= RAFT_NLA_MAX; i++) {
			if (strstr(object_str[i], argv[optind]) == object_str[i]) {
				cfg_req.object_type = i;
				break;
			}
		}
		if (cfg_req.object_type == RAFT_NLA_UNSPEC) {
			printf("Unknown object required!\n");
			exit(EXIT_FAILURE);
		}
		optind++;
		if (optind < argc) {
			printf("Parsing expected command action string: %s\n", argv[optind]);
			for (i = RAFT_CFG_CMD_UNSPEC; i <= RAFT_CFG_CMD_MAX; i++) {
				if (strstr(object_str[i], argv[optind]) == object_str[i]) {
					cfg_req.object_type = i;
					break;
				}
			}
			if (cfg_req.object_type == RAFT_CFG_CMD_UNSPEC) {
				printf("Unknown command action required!\n");
				exit(EXIT_FAILURE);
			}
		}
		optind++;
		if (optind < argc) {
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
			};
		}
		if (optind < argc) {
			printf("Unknown ARGV-elements: ");
			while (optind < argc)
				printf("%s ", argv[optind++]);
			printf("\n");
			exit(EXIT_FAILURE);
		}
	}

	return ret;
}

int main(int argc, char *argv[])
{
	usage_check(argc, argv);

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

	if (raft_config_request() < 0)
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

int raft_config_request(void)
{
	int family_id;
	int family;
	int ret;
	int err = 1;

//	struct rtgenmsg rt_hdr = { .rtgen_family = AF_PACKET, };
	struct nl_msg *msg;
	struct nl_cb *cb;

	// Open socket to kernel.
	struct nl_sock *socket = nl_socket_alloc();  // Allocate new netlink socket in memory.
	if (!socket) {
		fprintf(stderr, "Failed to allocate netlink socket.\n");
		return -ENOMEM;
	}

	genl_connect(socket);  // Create file descriptor and bind socket.
	family = genl_ctrl_resolve(socket, RAFT_GENL_V2_NAME);  

	msg = nlmsg_alloc();
	if (!msg) {
		fprintf(stderr, "Failed to allocate netlink message.\n");
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

	printf("i am raft-config (family=%d)!\n", family);

	genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family, 0, NLM_F_REQUEST, RAFT_NL_CLUSTER_ADD, 0);
	nl_send_auto_complete(socket, msg);
	nlmsg_free(msg);

//	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);

	/* set the callback function to receive answers to recv_msg */
	if (nl_socket_modify_cb(socket, NL_CB_MSG_IN, NL_CB_CUSTOM, recv_msg, &err) < 0) {
		printf("error setting callback function\n");
		
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

#if 0
#define fatal(fmt, arg...)	do { printf(fmt, ##arg); exit(EXIT_FAILURE); } while (0)

static int callback(struct nl_msg *msg, void *arg) {
    struct nlmsghdr *nlh = nlmsg_hdr(msg);
    struct ifinfomsg *iface = NLMSG_DATA(nlh);
    struct rtattr *hdr = IFLA_RTA(iface);
    int remaining = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*iface));

    //printf("Got something.\n");
    //nl_msg_dump(msg, stdout);

    while (RTA_OK(hdr, remaining)) {
        //printf("Loop\n");

        if (hdr->rta_type == IFLA_IFNAME) {
            printf("Found network interface %d: %s\n", iface->ifi_index, (char *) RTA_DATA(hdr));
        }

        hdr = RTA_NEXT(hdr, remaining);
    }

    return NL_OK;
}

static int list_interface_handler(struct nl_msg *msg, void *arg)
{
#if 0
	struct nlattr *tb_msg[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));

	nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
	genlmsg_attrlen(gnlh, 0), NULL);

	if (tb_msg[NL80211_ATTR_IFNAME])
		printf("Interface: %s\n", nla_get_string(tb_msg[NL80211_ATTR_IFNAME]));
#endif
	printf("This is list_interface_handler\n");

	return NL_SKIP;
}

static int finish_handler(struct nl_msg *msg, void *arg)
{
	int *ret = arg;
	*ret = 0;
	printf("This is finish_handler\n");
	return NL_SKIP;
}

#if 0
/******************************************************************************
 *
 * Routines used to exchange messages over Netlink sockets
 *
 */

#define NLA_SIZE(type)	(NLA_HDRLEN + NLA_ALIGN(sizeof(type)))

#define nla_for_each_attr(pos, head, len, rem) \
	for (pos = head, rem = len; nla_ok(pos, rem); pos = nla_next(pos, &(rem)))

static inline void *nla_data(const struct nlattr *nla)
{
	return (char *) nla + NLA_HDRLEN;
}

static inline int nla_ok(const struct nlattr *nla, int remaining)
{
	return remaining >= sizeof(*nla) &&
	       nla->nla_len >= sizeof(*nla) &&
	       nla->nla_len <= remaining;
}

static inline struct nlattr *nla_next(const struct nlattr *nla, int *remaining) {
	int totlen = NLA_ALIGN(nla->nla_len);

	*remaining -= totlen;
	return (struct nlattr *) ((char *) nla + totlen);
}

static inline int nla_put_string(struct nlattr *nla, int type, const char *str)
{
	int attrlen = strlen(str) + 1;

	nla->nla_len = NLA_HDRLEN + attrlen;
	nla->nla_type = type;
	memcpy(nla_data(nla), str, attrlen);

	return NLA_HDRLEN + NLA_ALIGN(attrlen);
}

static inline __u16 nla_get_u16(struct nlattr *nla)
{
	return *(__u16 *) nla_data(nla);
}

static int write_uninterrupted(int sk, const char *buf, int len)
{
	int c;

	while ((c = write(sk, buf, len)) < len) {
		if (c == -1) {
			if (errno == EINTR)
				continue;
			return -1;
		}

		buf += c;
		len -= c;
	}

	return 0;
}
#endif

static int genetlink_call(__u16 family_id, __u8 cmd, void *header,
                          size_t header_len, void *request, size_t request_len,
                          void *reply, size_t reply_len)
{
	struct msg {
		struct nlmsghdr n;
		struct genlmsghdr g;
		char payload[0];
	};

	struct msg *request_msg;
	struct msg *reply_msg;
	int request_msg_size;
	int reply_msg_size;

	struct sockaddr_nl local;
	struct pollfd pfd;
	int sndbuf = 32*1024; /* 32k */
	int rcvbuf = 32*1024; /* 32k */
	int len;
	int sk;

	/*
	 * Prepare request/reply messages
	 */
	request_msg_size = NLMSG_LENGTH(GENL_HDRLEN + header_len + request_len);
	request_msg = malloc(request_msg_size);
	request_msg->n.nlmsg_len = request_msg_size;
	request_msg->n.nlmsg_type = family_id;
	request_msg->n.nlmsg_flags = NLM_F_REQUEST;
	request_msg->n.nlmsg_seq = 0;
	request_msg->n.nlmsg_pid = getpid();
	request_msg->g.cmd = cmd;
	request_msg->g.version = 0;
	if (header_len)
		memcpy(&request_msg->payload[0], header, header_len);
	if (request_len)
		memcpy(&request_msg->payload[header_len], request, request_len);

	reply_msg_size = NLMSG_LENGTH(GENL_HDRLEN + header_len + reply_len);
	reply_msg = malloc(reply_msg_size);

	/*
	 * Create socket
	 */
	memset(&local, 0, sizeof(local));
	local.nl_family = AF_NETLINK;

	if ((sk = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_GENERIC)) == -1)
		fatal("error creating Netlink socket\n");

	if ((bind(sk, (struct sockaddr*)&local, sizeof(local)) == -1) ||
	                (setsockopt(sk, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) == -1) ||
	                (setsockopt(sk, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) == -1)) {
		fatal("error creating Netlink socket\n");
	}

	/*
	 * Send request
	 */
	if (write_uninterrupted(sk, (char*)request_msg, request_msg_size) < 0)
		fatal("error sending message via Netlink\n");

	/*
	 * Wait for reply
	 */
	pfd.fd = sk;
	pfd.events = ~POLLOUT;
	if ((poll(&pfd, 1, 3000) != 1) || !(pfd.revents & POLLIN))
		fatal("no reply detected from Netlink\n");

	/*
	 * Read reply
	 */
	len = recv(sk, (char*)reply_msg, reply_msg_size, 0);
	if (len < 0)
		fatal("error receiving reply message via Netlink\n");

	close(sk);

	/*
	 * Validate response
	 */
	if (!NLMSG_OK(&reply_msg->n, len))
		fatal("invalid reply message received via Netlink\n");

	if (reply_msg->n.nlmsg_type == NLMSG_ERROR) {
		len = -1;
		goto out;
	}

	if ((request_msg->n.nlmsg_type != reply_msg->n.nlmsg_type) ||
	                (request_msg->n.nlmsg_seq != reply_msg->n.nlmsg_seq))
		fatal("unexpected message received via Netlink\n");

	/*
	 * Copy reply header
	 */
	len -= NLMSG_LENGTH(GENL_HDRLEN);
	if (len < header_len)
		fatal("too small reply message received via Netlink\n");
	if (header_len > 0)
		memcpy(header, &reply_msg->payload[0], header_len);

	/*
	 * Copy reply payload
	 */
	len -= header_len;
	if (len > reply_len)
		fatal("reply message too large to copy\n");
	if (len > 0)
		memcpy(reply, &reply_msg->payload[header_len], len);

out:
	free(request_msg);
	free(reply_msg);

	return len;
}

static int get_genl_family_id(const char* name)
{
	struct nlattr_family_name {
		char value[GENL_NAMSIZ];
	};

	struct nlattr_family_id {
		__u16 value;
	};

	/*
	 * Create request/reply buffers
	 *
	 * Note that the reply buffer is larger than necessary in case future
	 * versions of Netlink return additional protocol family attributes
	 */
	char request[NLA_SIZE(struct nlattr_family_name)];
	int request_len = nla_put_string((struct nlattr *)request, CTRL_ATTR_FAMILY_NAME, name);

	char reply[REPLY_LEN];

	/*
	 * Call control service
	 */
	int len = genetlink_call(GENL_ID_CTRL, CTRL_CMD_GETFAMILY,
	                         0, 0,
	                         request, request_len,
	                         reply, sizeof(reply));

	if (len == -1)
		return -1;

	/*
	 * Parse reply
	 */
	struct nlattr *head = (struct nlattr *) reply;
	struct nlattr *nla;
	int rem;

	nla_for_each_attr(nla, head, len, rem) {
		if (nla->nla_type == CTRL_ATTR_FAMILY_ID)
			return nla_get_u16(nla);
	}

	if (rem > 0)
		fatal("%d bytes leftover after parsing Netlink attributes\n", rem);

	return -1;
}

#if 0
static int do_command_netlink(__u16 cmd, void *req_tlv, __u32 req_tlv_space,
                              void *rep_tlv, __u32 rep_tlv_space)
{
	struct tipc_genlmsghdr header;
	int family_id;
	int len;

	/*
	 * Request header
	 */
	header.dest = dest;
	header.cmd = cmd;

	/*
	 * Get TIPC family id
	 */
	if ((family_id = get_genl_family_id(TIPC_GENL_NAME)) == -1)
		fatal("no Netlink service registered for %s\n", TIPC_GENL_NAME);

	/*
	 * Call control service
	 */
	len = genetlink_call(family_id, TIPC_GENL_CMD,
	                     &header, sizeof(header),
	                     req_tlv, req_tlv_space,
	                     rep_tlv, rep_tlv_space);

	return len;
}
#endif
#endif

