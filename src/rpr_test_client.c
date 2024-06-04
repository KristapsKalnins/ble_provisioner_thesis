#include <zephyr/kernel.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/mesh.h>
#include "rpr_test_client.h"

#define LOG_LEVEL 4
#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(rpr_test_client);

extern void configure_node(struct bt_mesh_cdb_node *node);
extern void configure_self(struct bt_mesh_cdb_node *node);

uint16_t self_addr = 1;

struct remote_prov_data{
    uint16_t server;
    uint8_t uuid[16];
};

struct k_msgq rpr_scan_results;

K_MSGQ_DEFINE(rpr_scan_results, sizeof(struct remote_prov_data), 10, 1);

static void rpr_scan_report(struct bt_mesh_rpr_cli *cli,
			    const struct bt_mesh_rpr_node *srv,
			    struct bt_mesh_rpr_unprov *unprov,
			    struct net_buf_simple *adv_data)
{
	char uuid_hex_str[32 + 1];

	bin2hex(unprov->uuid, 16, uuid_hex_str, sizeof(uuid_hex_str));

	printk( "Server 0x%04x:\n"
		    "\tuuid:   %s\n"
		    "\tOOB:    0x%04x\n",
		    srv->addr, uuid_hex_str, unprov->oob);
	
	// Better to use a message queue instead of this
	/* send data to consumers */
	struct remote_prov_data data;

	data.server = srv->addr;
	memcpy(&(data.uuid), unprov->uuid, 16);

    while (k_msgq_put(&rpr_scan_results, &data, K_NO_WAIT) != 0) {
        /* message queue is full: purge old data & try again */
        k_msgq_get(&rpr_scan_results, NULL, K_NO_WAIT);
    }

	while (adv_data && adv_data->len > 2) {
		uint8_t len, type;
		uint8_t data[31];

		len = net_buf_simple_pull_u8(adv_data);
		if (len == 0) {
			/* No data in this AD Structure. */
			continue;
		}

		if (len > adv_data->len) {
			/* Malformed AD Structure. */
			break;
		}

		type = net_buf_simple_pull_u8(adv_data);
		if ((--len) > 0) {
			uint8_t dlen;

			/* Pull all length, but print only what fits into `data` array. */
			dlen = MIN(len, sizeof(data) - 1);
			memcpy(data, net_buf_simple_pull_mem(adv_data, len), dlen);
			len = dlen;
		}
		data[len] = '\0';

		if (type == BT_DATA_URI) {
			printk( "\tURI:    \"\\x%02x%s\"",
				    data[0], &data[1]);
		} else if (type == BT_DATA_NAME_COMPLETE) {
			printk( "\tName:   \"%s\"", data);
		} else {
			char string[64 + 1];

			bin2hex(data, len, string, sizeof(string));
			printk( "\t0x%02x:  %s", type, string);
		}
	}
}

struct bt_mesh_rpr_cli rpr_cli = {
	.scan_report = rpr_scan_report,
};

static int rpr_scan(uint16_t dest_node, uint8_t timeout)
{
	struct bt_mesh_rpr_scan_status rsp;
	const struct bt_mesh_rpr_node srv = {
		.addr = dest_node,
		.net_idx = 0,
		.ttl = BT_MESH_TTL_DEFAULT,
	};
	int err = 0;

	err = bt_mesh_rpr_scan_start(&rpr_cli,
				     &srv, NULL, timeout,
				     BT_MESH_RPR_SCAN_MAX_DEVS_ANY, &rsp);
	if (err) {
		printk("Scan start failed: %d", err);
		return err;
	}

	if (rsp.status == BT_MESH_RPR_SUCCESS) {
		printk("Scan started.\n");
	} else {
		printk("Scan start response: %d\n", rsp.status);
	}

	return 0;
}

int rpr_provision(uint8_t* uuid, uint16_t node_addr){
	int err = 0;
	
	struct bt_mesh_rpr_node srv = {
		.addr = node_addr,
		.net_idx = 0,
		.ttl = BT_MESH_TTL_DEFAULT,
	};

	err = bt_mesh_provision_remote(&rpr_cli,
				       &srv, uuid, 0, 0);
	if (err) {
		printk("Prov remote start failed: %d\n", err);
	}

	return err;
}

static uint8_t rpr_check_unconfigured(struct bt_mesh_cdb_node *node, void *data)
{
	if (!atomic_test_bit(node->flags, BT_MESH_CDB_NODE_CONFIGURED)) {
		if (node->addr == self_addr) {
			configure_self(node);
		} else {
			configure_node(node);
		}
	}

	return BT_MESH_CDB_ITER_CONTINUE;
}

void start_rpr(){

	uint16_t list_of_nodes[10];

	int num_nodes = get_list_of_node_addresses(list_of_nodes);

    while(1){

	    for(int i = 0; i < num_nodes; i++){

	    	rpr_scan(list_of_nodes[i], 60);

	    }

	    struct remote_prov_data found_node;
	
	    int rc = 0;

	    int64_t start_time = k_uptime_get();
    	while(((k_uptime_get() - start_time)/1000) < 60){
	    	// Do this for a total of 60 seconds - keep retrieving the uuids 
		    if ((rc = k_msgq_peek(&rpr_scan_results, &found_node)) == 0){
			    rc = rpr_provision(found_node.uuid, found_node.server);
                if(rc == 0){
                    // Clear message from queue if provisioning started successfully
                    LOG_INF("Clear message");
                    k_msgq_get(&rpr_scan_results, &found_node, K_NO_WAIT);
                }
		    }else{
		    	printk("... %d\n", rc);
		    }
		    bt_mesh_cdb_node_foreach(rpr_check_unconfigured, NULL);
            k_sleep(K_SECONDS(1));
	    }

    }
}