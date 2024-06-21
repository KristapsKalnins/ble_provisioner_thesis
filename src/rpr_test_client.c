#include <zephyr/kernel.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/mesh.h>
#include "rpr_test_client.h"

#define LOG_LEVEL 4
#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(rpr_test_client);
extern int64_t end_time;
extern int64_t start_time;
extern int provisioned_count;
extern int provisioned_and_configured_count;
extern void configure_node(struct bt_mesh_cdb_node *node);
extern void configure_self(struct bt_mesh_cdb_node *node);
extern void set_publications(uint16_t starting_address);

K_SEM_DEFINE(sem_provisioning_complete, 1, 1);

extern struct k_sem sem_node_added;
extern struct k_sem sem_button_four_pressed;

uint16_t self_addr = 1;

#define TOTAL_PROVISIONED_DEVICE_COUNT	20
#define SCAN_TIME						60


struct k_msgq rpr_scan_results;

K_MSGQ_DEFINE(rpr_scan_results, sizeof(struct remote_prov_data), 20, 1);



static void provset_oob_static_val(){
	int err;
	if((err = bt_mesh_auth_method_set_static("NL].KffQkz~DR+$2|^hdYethZ`n{'?vF", sizeof("NL].KffQkz~DR+$2|^hdYethZ`n{'?vF") - 1)) == 0){
		//printk("Static Val set\n");
	}else{
		printk("Could not set static val %d\n", err);
	}
}


static bool rpr_check_for_duplicates(char* uuid){
	int peek_count = 0;
	bool res = false;
	struct remote_prov_data found_node;
	int num_of_msg = k_msgq_num_used_get(&rpr_scan_results);

	char uuid_hex[33];
	char found_node_uuid_hex[33];

	for(int i = 0; i < num_of_msg; i++){
		k_msgq_peek_at(&rpr_scan_results,&found_node, i);
		bin2hex(uuid, 16, uuid_hex, 33);
		bin2hex(found_node.uuid, 16, found_node_uuid_hex, 33);
		//LOG_INF("Comparing %s\n%s", found_node_uuid_hex, uuid_hex);
		peek_count++;
		if(memcmp(found_node.uuid, uuid, 16) == 0){
			//LOG_INF("Duplicates!");
			res = true;
			break;
		}
	}

	//LOG_INF("Peeked %d", peek_count);

	return res;
}

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
	
	bool duplicate = rpr_check_for_duplicates(unprov->uuid);

	if(duplicate){
		return;
	}

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
		printk("Scan start failed: %d\n", err);
	}

	if (rsp.status == BT_MESH_RPR_SUCCESS) {
		printk("Scan started.\n");
	} else {
		printk("Scan start response: %d\n", rsp.status);
	}

	return err;
}

int rpr_provision(uint8_t* uuid, uint16_t node_addr){
	int err = 0;
	
	struct bt_mesh_rpr_node srv = {
		.addr = node_addr,
		.net_idx = 0,
		.ttl = BT_MESH_TTL_DEFAULT,
	};
	
	char uuid_hex_str[32 + 1];
	bin2hex(uuid, 16, uuid_hex_str, sizeof(uuid_hex_str));


	LOG_INF("Provisioning %s", uuid_hex_str);
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
			if(atomic_test_bit(node->flags, BT_MESH_CDB_NODE_CONFIGURED)){
				provisioned_and_configured_count++;
				k_sem_give(&sem_provisioning_complete);
			}
		}
	}

	return BT_MESH_CDB_ITER_CONTINUE;
}

void start_rpr(){

	uint16_t list_of_nodes[25];

	int num_nodes = get_list_of_node_addresses(list_of_nodes);

    while(1){

	    for(int i = 0; i < num_nodes; i++){

	    	rpr_scan(list_of_nodes[i], SCAN_TIME);

	    }

	    struct remote_prov_data found_node;
	
	    int rc = 0;

	    int64_t rpr_start_time = k_uptime_get();
    	while(((k_uptime_get() - rpr_start_time)/1000) < SCAN_TIME){
			k_sem_reset(&sem_node_added);
	    	bt_mesh_cdb_node_foreach(rpr_check_unconfigured, NULL);
#if DT_NODE_HAS_STATUS(SW3_NODE, okay)
				k_sem_reset(&sem_button_four_pressed);
				//printk("Press button 4 to start rpr scan and provision\n");
				res = k_sem_take(&sem_button_four_pressed, K_NO_WAIT);
				if (res == 0) {
					set_publications(0x0002);
					k_sleep(K_FOREVER);
				}
#endif
			if(provisioned_count >= TOTAL_PROVISIONED_DEVICE_COUNT && provisioned_and_configured_count >= TOTAL_PROVISIONED_DEVICE_COUNT){
				end_time = k_uptime_get();
				LOG_INF("Provisioning took %lld seconds", (end_time - start_time)/1000);
				break;
			}else if(provisioned_count >= TOTAL_PROVISIONED_DEVICE_COUNT){
				LOG_INF("Provisioned enough, configuring");
				continue;
			}
			// Do this for a total of 60 seconds - keep retrieving the uuids 
		    if ((rc = k_msgq_peek(&rpr_scan_results, &found_node)) == 0){
				provset_oob_static_val();
			    rc = rpr_provision(found_node.uuid, found_node.server);
				k_sem_take(&sem_node_added, K_SECONDS(10));
                if(rc == 0){
                    // Clear message from queue if provisioning started successfully
                    
                }
		    }else{
		    	printk("... %d\n", rc);
		    }
            k_sleep(K_SECONDS(1));
			
	    }
		if(provisioned_count >= TOTAL_PROVISIONED_DEVICE_COUNT){
				set_publications(0x0002);
				break;
		}

    }
}
