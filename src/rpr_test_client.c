#include <zephyr/kernel.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/mesh.h>
#include "rpr_test_client.h"
#include "prov.h"

#define LOG_LEVEL 4
#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(rpr_test_client);
extern int64_t end_time;
extern int64_t start_time;
extern int64_t first_stage_end;
extern int provisioned_count;
extern int provisioned_and_configured_count;
extern void configure_node(struct bt_mesh_cdb_node *node);
extern void configure_self(struct bt_mesh_cdb_node *node);
extern void set_publications(uint16_t starting_address);

K_SEM_DEFINE(sem_provisioning_complete, 1, 1);

extern struct k_sem sem_node_added;
extern struct k_sem sem_button_four_pressed;

int current_array_size = 0;

struct remote_prov_data unprov[25];

uint16_t self_addr = 1;

#define TOTAL_PROVISIONED_DEVICE_COUNT	20
#define SCAN_TIME						50
#define SW3_NODE	DT_ALIAS(sw3)

//struct k_msgq rpr_scan_results;

//K_MSGQ_DEFINE(rpr_scan_results, sizeof(struct remote_prov_data), 20, 1);



static void provset_oob_static_val(){
	int err;
	if((err = bt_mesh_auth_method_set_static("NL].KffQkz~DR+$2|^hdYethZ`n{'?vF", sizeof("NL].KffQkz~DR+$2|^hdYethZ`n{'?vF") - 1)) == 0){
		//printk("Static Val set\n");
	}else{
		printk("Could not set static val %d\n", err);
	}
}

static bool insertionSortComapre(struct remote_prov_data* first, struct remote_prov_data* other){
	return (first->rssi < other->rssi);
}

static void insertionSort(struct remote_prov_data* arr, int n)
{
    int i, j;
	struct remote_prov_data key;
    for (i = 1; i < n; i++) {
        key = arr[i];
        j = i - 1;

        /* Move elements of arr[0..i-1], that are
          greater than key, to one position ahead
          of their current position */
        while (j >= 0 && insertionSortComapre(&arr[j],&key)) {
            arr[j + 1] = arr[j];
            j = j - 1;
        }
        arr[j + 1] = key;
    }
}

int rpr_find_duplicate(struct remote_prov_data* item){
	for(int i = 0; i < current_array_size; i++){
		if(memcmp(item->uuid, unprov[i].uuid, 16) == 0){
			if(item->rssi > unprov[i].rssi){
				// Better RSSI, can be replaced
				return i;
			}else{
				// Better RSSI is already in the array
				return -2;
			}
		}

	}
	// Not duplciate
	return -1;
}

int rpr_store_prov_data(struct remote_prov_data item){

	int ret = rpr_find_duplicate(&item);
	
	if(ret >= 0){
		// replace resort
		unprov[ret] = item;
		insertionSort(unprov, current_array_size);
	}else if(ret == -1){
		// append resort
		unprov[current_array_size++] = item;
		insertionSort(unprov, current_array_size);
	}

	LOG_INF("current_array_size %d", current_array_size);

	return 0;
}

int rpr_find_index_uuid(uint8_t* uuid){
	for(int i = 0; i < current_array_size; i++){
		if(memcmp(uuid, unprov[i].uuid, 16) == 0){
			return i;
		}
	}
	return -1;
}

void rpr_clear_oldest_prov_data(uint8_t* uuid){

	int ret = rpr_find_index_uuid(uuid);
	if(ret >= 0){
		// shift everything to the left
		LOG_INF("Clearing from %d", ret);
		for(int i = ret; i < current_array_size; i++){
			unprov[i] = unprov[i + 1];
		}
		current_array_size--;
	}else{
		LOG_INF("Could not find UUID!");
	}
	return;
}

int rpr_peek_prov_data(struct remote_prov_data* item){
	
	if(current_array_size > 0){
		*item = unprov[0];
	}else{
		return -1;
	}


	return 0;
}

/*
static bool rpr_compare_unprov(struct remote_prov_data* item, struct remote_prov_data* found_node, int item_index){
		if(memcmp(item->uuid, found_node->uuid, 16) == 0){
			//LOG_INF("Duplicates!");
			if (found_node->rssi > item->rssi){
				LOG_INF("Better RSSI found!");
				unprov[item_index] = *found_node;
			}
			return true;
		}else{
			return false;
		}
}
*//*
static bool rpr_check_for_duplicates(struct remote_prov_data* found_node){
	int peek_count = 0;
	//int num_of_msg = k_msgq_num_used_get(&rpr_scan_results);

	char uuid_hex[33];
	char found_node_uuid_hex[33];

	int end_of_queue  = (write_index < read_index ? 25 : write_index);

	bool res = false;

	for(int i = read_index; i < end_of_queue; i++){
		struct remote_prov_data item = unprov[i];
		res = rpr_compare_unprov(&item, found_node, i);
		if(res){break;}
	}
	if((end_of_queue = 25) && !res){
		for(int i = 0; i < write_index; i++){
			struct remote_prov_data item = unprov[i];
			res = rpr_compare_unprov(&item, found_node, i);
		}
	}

	//LOG_INF("Peeked %d", peek_count);

	return res;
}*/

static void rpr_scan_report(struct bt_mesh_rpr_cli *cli,
			    const struct bt_mesh_rpr_node *srv,
			    struct bt_mesh_rpr_unprov *unprov,
			    struct net_buf_simple *adv_data)
{
	char uuid_hex_str[32 + 1];

	bin2hex(unprov->uuid, 16, uuid_hex_str, sizeof(uuid_hex_str));

	printk( "Server 0x%04x:\n"
		    "\tuuid:   %s\n"
		    "\tOOB:    0x%04x\n"
			"\tRSSI:    %d db\n",
		    srv->addr, uuid_hex_str, unprov->oob, unprov->rssi);
	
	// Better to use a message queue instead of this
	/* send data to consumers */
	
	struct remote_prov_data data;

	data.server = srv->addr;
	memcpy(&(data.uuid), unprov->uuid, 16);
	data.rssi = unprov->rssi;
	
    rpr_store_prov_data(data);

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

int rpr_provision(struct remote_prov_data* found_node){
	int err = 0;
	
	struct bt_mesh_rpr_node srv = {
		.addr = found_node->server,
		.net_idx = 0,
		.ttl = BT_MESH_TTL_DEFAULT,
	};
	
	char uuid_hex_str[32 + 1];
	bin2hex(found_node->uuid, 16, uuid_hex_str, sizeof(uuid_hex_str));


	LOG_INF("Provisioning %s from 0x%04x with %d RSSI", uuid_hex_str, found_node->server, found_node->rssi);
	err = bt_mesh_provision_remote(&rpr_cli,
				       &srv, found_node->uuid, 0, 0);
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


    while(1){
		bt_mesh_cdb_node_foreach(rpr_check_unconfigured, NULL);

		int num_nodes = get_list_of_node_addresses(list_of_nodes);
	    
		for(int i = 0; i < num_nodes; i++){

	    	rpr_scan(list_of_nodes[i], SCAN_TIME);

	    }

	    struct remote_prov_data found_node;
	
	    int rc = 0;
	    int64_t rpr_start_time = k_uptime_get();
    	while(((k_uptime_get() - rpr_start_time)/1000) < SCAN_TIME){
			k_sem_reset(&sem_node_added);
#if DT_NODE_HAS_STATUS(SW3_NODE, okay)
				k_sem_reset(&sem_button_four_pressed);
				//printk("Press button 4 to start rpr scan and provision\n");
				int res = k_sem_take(&sem_button_four_pressed, K_MSEC(500));
				if (res == 0) {
					set_publications(0x0002);
					k_sleep(K_FOREVER);
				}
#endif
			if(provisioned_count >= TOTAL_PROVISIONED_DEVICE_COUNT && provisioned_and_configured_count >= TOTAL_PROVISIONED_DEVICE_COUNT){
				end_time = k_uptime_get();
				LOG_INF("Second phase took %lld seconds", (end_time - first_stage_end)/1000);
				LOG_INF("Provisioning took %lld seconds", (end_time - start_time)/1000);
				break;
			}else if(provisioned_count >= TOTAL_PROVISIONED_DEVICE_COUNT){
				LOG_INF("Provisioned enough, configuring");
				bt_mesh_cdb_node_foreach(rpr_check_unconfigured, NULL);
				continue;
			}
			// Do this for a total of 60 seconds - keep retrieving the uuids 
		    if ((rc = rpr_peek_prov_data(&found_node)) == 0){
				provset_oob_static_val();
			    rc = rpr_provision(&found_node);
				if (rc == -16) {
					LOG_INF("Busy, waiting for node");
				}
				else if (rc < 0){
					LOG_INF("Provisioning failed (err %d)", rc);
					continue;
				}
				LOG_INF("Waiting for node to be added...");
				rc = k_sem_take(&sem_node_added, K_SECONDS(20));
		    }else{
		    	printk("... %d\n", rc);
		    }
            k_sleep(K_MSEC(100));
			
	    }
		if(provisioned_and_configured_count >= TOTAL_PROVISIONED_DEVICE_COUNT){
				LOG_INF("Second phase took %lld seconds", (end_time - first_stage_end)/1000);
				LOG_INF("Provisioning took %lld seconds", (end_time - start_time)/1000);
				set_publications(0x0002);
				k_sleep(K_FOREVER);
				break;
		}

    }
}
