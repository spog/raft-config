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

#ifndef __raft_config_h__
#define __raft_config_h__

#define RAFT_OBJ_UNSPEC_STR ""
#define RAFT_OBJ_CLUSTER_STR "cluster"
#define RAFT_OBJ_DOMAIN_STR "domain"
#define RAFT_OBJ_NODE_STR "node"

enum {
	RAFT_CFG_CMD_UNSPEC,
	RAFT_CFG_CMD_ADD,
	RAFT_CFG_CMD_DEL,
	RAFT_CFG_CMD_SET,
	RAFT_CFG_CMD_SHOW,

	__RAFT_CFG_CMD_MAX,
	RAFT_CFG_CMD_MAX = __RAFT_CFG_CMD_MAX - 1
};

#define RAFT_CFG_CMD_UNSPEC_STR ""
#define RAFT_CFG_CMD_ADD_STR "add"
#define RAFT_CFG_CMD_DEL_STR "del"
#define RAFT_CFG_CMD_SET_STR "set"
#define RAFT_CFG_CMD_SHOW_STR "show"

struct raft_config_req {
	int object_type;
	int command_action;
	void *command_params;
};

#define RAFT_PAR_CLUSTER_UNSPEC_STR ""
#define RAFT_PAR_CLUSTER_ID_STR "id"

struct raft_cluster_params {
	int param_type;
	unsigned long id_value;
};

struct raft_domain_params {
};

struct raft_node_params {
};

int raft_config_request(void);

#endif /*__raft_config_h__*/
