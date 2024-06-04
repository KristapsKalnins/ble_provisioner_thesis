/*
 * Copyright (c) 2019 Tobias Svehagen
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/sys/printk.h>
#include <zephyr/settings/settings.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/mesh.h>
#include <zephyr/drivers/gpio.h>
#include "prov_helper_cli.h"
#include "prov_helper_srv.h"
#include "rpr_test_client.h"

#define SW0_NODE	DT_ALIAS(sw0)
#define SW1_NODE	DT_ALIAS(sw1)
#define SW2_NODE	DT_ALIAS(sw2)
#define SW3_NODE	DT_ALIAS(sw3)

static const uint16_t net_idx = 0;
static const uint16_t app_idx = 0;
static uint16_t self_addr = 1, node_addr;
static const uint8_t dev_uuid[16] = { 0xdd, 0xdd };
static uint8_t node_uuid[16];
static uint8_t net_key[16];
static uint8_t app_key[16];
static uint16_t current_node_address;
static uint16_t provisioning_address_range_start = 0x0002;
static uint16_t provisioning_address_range_end = 0x400;
static int64_t end_time = 0;
static int64_t start_time = 0;
extern struct bt_mesh_rpr_cli rpr_cli;

#define LOG_LEVEL 4
#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(main);


K_SEM_DEFINE(sem_unprov_beacon, 0, 1);
K_SEM_DEFINE(sem_node_added, 0, 1);
#if DT_NODE_HAS_STATUS(SW0_NODE, okay)
K_SEM_DEFINE(sem_button_pressed, 0, 1);
#endif
#if DT_NODE_HAS_STATUS(SW1_NODE, okay)
K_SEM_DEFINE(sem_button_two_pressed, 0, 1);
#endif
#if DT_NODE_HAS_STATUS(SW2_NODE, okay)
K_SEM_DEFINE(sem_button_three_pressed, 0, 1);
#endif
#if DT_NODE_HAS_STATUS(SW3_NODE, okay)
K_SEM_DEFINE(sem_button_four_pressed, 0, 1);
#endif


static struct bt_mesh_cfg_cli cfg_cli = {
};

static void health_current_status(struct bt_mesh_health_cli *cli, uint16_t addr,
				  uint8_t test_id, uint16_t cid, uint8_t *faults,
				  size_t fault_count)
{
	size_t i;

	printk("Health Current Status from 0x%04x\n", addr);

	if (!fault_count) {
		printk("Health Test ID 0x%02x Company ID 0x%04x: no faults\n",
		       test_id, cid);
		return;
	}

	printk("Health Test ID 0x%02x Company ID 0x%04x Fault Count %zu:\n",
	       test_id, cid, fault_count);

	for (i = 0; i < fault_count; i++) {
		printk("\t0x%02x\n", faults[i]);
	}
}

static struct bt_mesh_health_cli health_cli = {
	.current_status = health_current_status,
};

int provisioned_count = 0;


void save_remote_node_in_cdb(struct bt_mesh_prov_helper_srv* srv, struct bt_mesh_msg_ctx *ctx,
		struct net_buf_simple *buf){
	
		
	char* uuid_p = net_buf_simple_pull_mem(buf, 16);
    uint16_t addr = net_buf_simple_pull_le16(buf);
    uint16_t net_idx = net_buf_simple_pull_le16(buf);
    uint8_t num_elem = net_buf_simple_pull_u8(buf);
    char* dev_key_p = net_buf_simple_pull_mem(buf, 16);
	
	struct bt_mesh_cdb_node* new_node =  bt_mesh_cdb_node_alloc(uuid_p, addr, num_elem, net_idx);

	char* flags;
	flags = net_buf_simple_pull_mem(buf, sizeof(new_node->flags));

	memcpy(new_node->flags, flags, sizeof(new_node->flags));

	printk("Flags received %d for node 0x%04X\n", *((uint32_t*)flags), addr);

	bt_mesh_cdb_node_key_import(new_node, dev_key_p);
	
	provisioned_count++;

	if(provisioned_count >= 5){
		end_time = k_uptime_get();
		LOG_INF("Provisioning took %lld seconds", (end_time - start_time)/1000);
	}

	return;
}

int get_list_of_node_addresses(uint16_t nodes[]){
	
	int node_counter = 0;

	struct bt_mesh_cdb_node *found_node;
	uint16_t current_node = 0;

	uint16_t starting_address = self_addr + 1;

	while((found_node = bt_mesh_cdb_node_get(starting_address++))){
		if(found_node->addr == current_node){
			continue;
		}
		current_node = found_node->addr;
		nodes[node_counter++] = current_node;
	}
	return node_counter;
}


const struct bt_mesh_time_srv_handlers srv_helper_handlers = {
	.prov_helper_message_appkey = NULL,
	.prov_helper_message_netkey = NULL,
	.prov_helper_message_nodeinfo = save_remote_node_in_cdb,
};


struct bt_mesh_prov_helper_cli helper_cli = BT_MESH_PROV_HELPER_CLI_INIT();
struct bt_mesh_prov_helper_srv helper_srv = BT_MESH_PROV_HELPER_SRV_INIT(&srv_helper_handlers);


static struct bt_mesh_model root_models[] = {
	BT_MESH_MODEL_CFG_SRV,
	BT_MESH_MODEL_CFG_CLI(&cfg_cli),
	BT_MESH_MODEL_HEALTH_CLI(&health_cli),
	BT_MESH_MODEL_RPR_CLI(&rpr_cli),
};

static struct bt_mesh_elem elements[] = {
	BT_MESH_ELEM(0, root_models,  BT_MESH_MODEL_LIST(BT_MESH_MODEL_PROV_HELPER_CLI(&helper_cli),
													 BT_MESH_MODEL_PROV_HELPER_SRV(&helper_srv))),
};

static const struct bt_mesh_comp mesh_comp = {
	.cid = BT_COMP_ID_LF,
	.elem = elements,
	.elem_count = ARRAY_SIZE(elements),
};

static void setup_cdb(void)
{
	struct bt_mesh_cdb_app_key *key;
	int err;

	key = bt_mesh_cdb_app_key_alloc(net_idx, app_idx);
	if (key == NULL) {
		printk("Failed to allocate app-key 0x%04x\n", app_idx);
		return;
	}

	bt_rand(app_key, 16);

	err = bt_mesh_cdb_app_key_import(key, 0, app_key);
	if (err) {
		printk("Failed to import appkey into cdb. Err:%d\n", err);
		return;
	}

	if (IS_ENABLED(CONFIG_BT_SETTINGS)) {
		bt_mesh_cdb_app_key_store(key);
	}
}

void configure_self(struct bt_mesh_cdb_node *self)
{
	struct bt_mesh_cdb_app_key *key;
	uint8_t app_key[16];
	uint8_t status = 0;
	int err;

	printk("Configuring self...\n");

	key = bt_mesh_cdb_app_key_get(app_idx);
	if (key == NULL) {
		printk("No app-key 0x%04x\n", app_idx);
		return;
	}

	err = bt_mesh_cdb_app_key_export(key, 0, app_key);
	if (err) {
		printk("Failed to export appkey from cdb. Err:%d\n", err);
		return;
	}

	/* Add Application Key */
	err = bt_mesh_cfg_cli_app_key_add(self->net_idx, self->addr, self->net_idx, app_idx,
					  app_key, &status);
	if (err || status) {
		printk("Failed to add app-key (err %d, status %d)\n", err,
		       status);
		return;
	}

	err = bt_mesh_cfg_cli_mod_app_bind(self->net_idx, self->addr, self->addr, app_idx,
					   BT_MESH_MODEL_ID_HEALTH_CLI, &status);
	if (err || status) {
		printk("Failed to bind app-key (err %d, status %d)\n", err,
		       status);
		return;
	}

	err = bt_mesh_cfg_cli_mod_app_bind_vnd(self->net_idx, self->addr, self->addr, app_idx,
					   BT_MESH_VND_MODEL_ID_PROV_HELPER_CLI, COMPANY_ID, &status);
	if (err || status) {
		printk("Failed to bind app-key for prov helper cli(err %d, status %d)\n", err,
		       status);
		//return;
	}

	err = bt_mesh_cfg_cli_mod_app_bind_vnd(self->net_idx, self->addr, self->addr, app_idx,
					   BT_MESH_VND_MODEL_ID_PROV_HELPER_SRV, COMPANY_ID, &status);
	if (err || status) {
		printk("Failed to bind app-key for prov helper srv(err %d, status %d)\n", err,
		       status);
		return;
	}


	atomic_set_bit(self->flags, BT_MESH_CDB_NODE_CONFIGURED);

	if (IS_ENABLED(CONFIG_BT_SETTINGS)) {
		bt_mesh_cdb_node_store(self);
	}

	printk("Configuration complete\n");
}

void configure_node(struct bt_mesh_cdb_node *node)
{
	NET_BUF_SIMPLE_DEFINE(buf, BT_MESH_RX_SDU_MAX);
	struct bt_mesh_comp_p0_elem elem;
	struct bt_mesh_cdb_app_key *key;
	uint8_t app_key[16];
	struct bt_mesh_comp_p0 comp;
	uint8_t status;
	int err, elem_addr;

	printk("Configuring node 0x%04x...\n", node->addr);

	key = bt_mesh_cdb_app_key_get(app_idx);
	if (key == NULL) {
		printk("No app-key 0x%04x\n", app_idx);
		return;
	}

	err = bt_mesh_cdb_app_key_export(key, 0, app_key);
	if (err) {
		printk("Failed to export appkey from cdb. Err:%d\n", err);
		return;
	}

	/* Add Application Key */
	err = bt_mesh_cfg_cli_app_key_add(net_idx, node->addr, net_idx, app_idx, app_key, &status);
	if (err || status) {
		printk("Failed to add app-key (err %d status %d)\n", err, status);
		return;
	}

	/* Get the node's composition data and bind all models to the appkey */
	err = bt_mesh_cfg_cli_comp_data_get(net_idx, node->addr, 0, &status, &buf);
	if (err || status) {
		printk("Failed to get Composition data (err %d, status: %d)\n",
		       err, status);
		return;
	}

	err = bt_mesh_comp_p0_get(&comp, &buf);
	if (err) {
		printk("Unable to parse composition data (err: %d)\n", err);
		return;
	}

	elem_addr = node->addr;
	while (bt_mesh_comp_p0_elem_pull(&comp, &elem)) {
		printk("Element @ 0x%04x: %u + %u models\n", elem_addr,
		       elem.nsig, elem.nvnd);
		for (int i = 0; i < elem.nsig; i++) {
			uint16_t id = bt_mesh_comp_p0_elem_mod(&elem, i);
			// Bind the AppKey only to the generic OnOff Server and Client
			//if ((id == BT_MESH_MODEL_ID_CFG_CLI ||
			//    id == BT_MESH_MODEL_ID_CFG_SRV || 
			//	(id != BT_MESH_MODEL_ID_GEN_ONOFF_SRV &&
			//	id != BT_MESH_MODEL_ID_GEN_ONOFF_CLI) ||
			//	(id != BT_MESH_MODEL_ID_BLOB_CLI &&
			//	id != BT_MESH_MODEL_ID_BLOB_SRV))) {
			//	continue;
			//}
			printk("Binding AppKey to model 0x%03x:%04x\n",
			       elem_addr, id);

			err = bt_mesh_cfg_cli_mod_app_bind(net_idx, node->addr, elem_addr, app_idx,
							   id, &status);
			if (err || status) {
				printk("Failed (err: %d, status: %d)\n", err,
				       status);
			}


		}

		for (int i = 0; i < elem.nvnd; i++) {
			struct bt_mesh_mod_id_vnd id =
				bt_mesh_comp_p0_elem_mod_vnd(&elem, i);

			printk("Binding AppKey to model 0x%03x:%04x:%04x\n",
			       elem_addr, id.company, id.id);

			err = bt_mesh_cfg_cli_mod_app_bind_vnd(net_idx, node->addr, elem_addr,
							       app_idx, id.id, id.company, &status);
			if (err || status) {
				printk("Failed (err: %d, status: %d)\n", err,
				       status);
			}
		}

		elem_addr++;
	}

	atomic_set_bit(node->flags, BT_MESH_CDB_NODE_CONFIGURED);

	if (IS_ENABLED(CONFIG_BT_SETTINGS)) {
		bt_mesh_cdb_node_store(node);
	}

	printk("Configuration complete\n");
}

void set_provisioner_publications(){
	NET_BUF_SIMPLE_DEFINE(buf, BT_MESH_RX_SDU_MAX);
	struct bt_mesh_comp_p0_elem elem;
	struct bt_mesh_comp_p0 comp;
	uint8_t status;
	int err, elem_addr;
	struct bt_mesh_cfg_cli_mod_pub pub_prov;

	struct bt_mesh_cdb_node *self_node;

	self_node = bt_mesh_cdb_node_get(self_addr);

	// Get the composition of the publisher(sender)
	err = bt_mesh_cfg_cli_comp_data_get(net_idx, self_node->addr, 0, &status, &buf);
	if (err || status) {
		printk("Failed to get Composition data (err %d, status: %d)\n",
		    	err, status);
		//return;
	}
	
	err = bt_mesh_comp_p0_get(&comp, &buf);
	if (err) {
		printk("Unable to parse composition data (err: %d)\n", err);
		return;
	}

	uint16_t list_of_nodes[10];

	int num_nodes = get_list_of_node_addresses(list_of_nodes);

	elem_addr = self_node->addr;
	while (bt_mesh_comp_p0_elem_pull(&comp, &elem)) {
		printk("Element @ 0x%04x: %u + %u models\n", elem_addr,
		       elem.nsig, elem.nvnd);
	
		for (int i = 0; i < elem.nvnd; i++){
			struct bt_mesh_mod_id_vnd vnd_id = bt_mesh_comp_p0_elem_mod_vnd(&elem, i);
			if(vnd_id.id == BT_MESH_VND_MODEL_ID_PROV_HELPER_CLI){
				printk("Found Provisioner Helper Client for 0x%03x:0x%04x\n",
						self_node->addr, elem_addr);
				for(int i = 0; i < num_nodes; i++){		
					// Set a publication on the provisioned device to publish
					// back to the provisioner
					// For outer provisioners, this address would be the original provisioners addres
					pub_prov.addr = list_of_nodes[i];
					pub_prov.uuid = NULL;
					pub_prov.app_idx = app_idx;
					pub_prov.cred_flag = false;
					pub_prov.ttl = 35;
					pub_prov.period = 0;
					pub_prov.transmit = BT_MESH_TRANSMIT(0, 50);
					int err = bt_mesh_cfg_cli_mod_pub_set_vnd(net_idx, self_addr, elem_addr, BT_MESH_VND_MODEL_ID_PROV_HELPER_CLI, COMPANY_ID, &pub_prov, &status);
					if (err || status) {
						printk("Failed to set publication (err %d, status: %d)\n",
		    	   			err, status);
					}else{
						printk("Publication set! 0x%04x:0x%04x -> 0x%04x\n", self_addr, elem_addr, list_of_nodes[i]);
					}
				}
			}
			if(vnd_id.id == BT_MESH_VND_MODEL_ID_PROV_HELPER_SRV){
				printk("Found Provisioner Helper Server for 0x%03x:0x%04x\n",
						self_node->addr, elem_addr);
			
			}
		}
		elem_addr++;
	}
}

int send_provisioning_data_to_outer_nodes(){
	//NET_BUF_SIMPLE_DEFINE(buf, BT_MESH_RX_SDU_MAX);
	//struct bt_mesh_comp_p0_elem elem;
	//struct bt_mesh_cdb_app_key *key;
	//uint8_t app_key[16];

	LOG_INF("Sending info to outer nodes");

	uint16_t nodes[32];
	//struct bt_mesh_comp_p0 comp;
	//uint8_t status;
	//int err, elem_addr;

	//struct bt_mesh_cdb_node *found_node;

	//uint16_t current_node = 0;

	int num_of_nodes = get_list_of_node_addresses(nodes);

	uint16_t remaining_address_count = provisioning_address_range_end - current_node_address;	

	if (!remaining_address_count){
		return 0;
	}
	
	if(!num_of_nodes){
		return 0;
	}

	uint16_t addresses_per_next_provisioner = remaining_address_count / num_of_nodes;
	
	if(addresses_per_next_provisioner == 0){
		addresses_per_next_provisioner = 1;
	} 

	for(int i = 0; i < num_of_nodes; i++){
		
		uint16_t start_addr = current_node_address + (addresses_per_next_provisioner * i);
		uint16_t end_addr = start_addr + addresses_per_next_provisioner;

		remaining_address_count -= addresses_per_next_provisioner;

		printk("Sending 0x%04X -> 0x%04X with 0x%04X origin to 0x%04X\n", start_addr, end_addr,
																		  self_addr,
																		  nodes[i]);
		
		bt_mesh_prov_helper_cli_send_addrinfo(&elements[0].vnd_models[0], start_addr,end_addr, self_addr, nodes[i]);
	
		if(remaining_address_count <= 0){
			break;
		}
	}
	return 0; 	
}

// Start from 0x0002 to exclude the initial provisioner
void set_publications(uint16_t starting_address){
	NET_BUF_SIMPLE_DEFINE(buf, BT_MESH_RX_SDU_MAX);
	struct bt_mesh_comp_p0_elem elem;
	//struct bt_mesh_cdb_app_key *key;
	//uint8_t app_key[16];
	struct bt_mesh_comp_p0 comp;
	uint8_t status;
	int err, elem_addr;
	struct bt_mesh_cfg_cli_mod_pub pub_cfg, pub_prov;

	uint32_t switches[16] = {0};
	uint16_t switch_counter = 0;
	uint32_t lights[16] = {0};
	uint16_t light_counter = 0;
/*
	key = bt_mesh_cdb_app_key_get(app_idx);
	if (key == NULL) {
		printk("No app-key 0x%04x\n", app_idx);
		return;
	}

	err = bt_mesh_cdb_app_key_export(key, 0, app_key);
	if (err) {
		printk("Failed to export appkey from cdb. Err:%d\n", err);
		return;
	}
*/
	struct bt_mesh_cdb_node *found_node;

	uint16_t current_node = 0;
	while(starting_address < provisioning_address_range_end){
		found_node = bt_mesh_cdb_node_get(starting_address);
		starting_address += 1;
		if(found_node->addr == current_node || found_node == NULL || found_node->addr + 1 != starting_address){
			continue;
		}
		current_node = found_node->addr;
		printk("Found node with id 0x%03x\n", found_node->addr);

		// Get the composition of the publisher(sender)
		err = bt_mesh_cfg_cli_comp_data_get(net_idx, found_node->addr, 0, &status, &buf);
		if (err || status) {
			printk("Failed to get Composition data (err %d, status: %d)\n",
		    	   err, status);
			//return;
		}
	
		err = bt_mesh_comp_p0_get(&comp, &buf);
		if (err) {
			printk("Unable to parse composition data (err: %d)\n", err);
			return;
		}

		elem_addr = found_node->addr;
		while (bt_mesh_comp_p0_elem_pull(&comp, &elem)) {
			printk("Element @ 0x%04x: %u + %u models\n", elem_addr,
			       elem.nsig, elem.nvnd);
			for (int i = 0; i < elem.nsig; i++) {
				uint16_t id = bt_mesh_comp_p0_elem_mod(&elem, i);
				
				if ((id == BT_MESH_MODEL_ID_GEN_ONOFF_CLI)) {
					printk("Found OnOff client for 0x%03x:0x%04x\n",
					found_node->addr, elem_addr);
					switches[switch_counter] = (uint32_t)(found_node->addr) << 16;
					switches[switch_counter++] |= elem_addr;
				} else if ((id == BT_MESH_MODEL_ID_GEN_ONOFF_SRV)) {
					printk("Found OnOff server for 0x%03x:0x%04x\n",
					found_node->addr, elem_addr);
					lights[light_counter] = (uint32_t)(found_node->addr) << 16;
					lights[light_counter++] |= elem_addr;
				}
			}

			/* for (int i = 0; i < elem.nvnd; i++){
				struct bt_mesh_mod_id_vnd vnd_id = bt_mesh_comp_p0_elem_mod_vnd(&elem, i);
				if(vnd_id.id == BT_MESH_VND_MODEL_ID_PROV_HELPER_CLI){
					printk("Found Provisioner Helper Client for 0x%03x:0x%04x\n",
							found_node->addr, elem_addr);

					// Set a publication on the provisioned device to publish
					// back to the provisioner
					// For outer provisioners, this address would be the original provisioners addres

					pub_prov.addr = self_addr;
					pub_prov.uuid = NULL;
					pub_prov.app_idx = app_idx;
					pub_prov.cred_flag = false;
					pub_prov.ttl = 35;
					pub_prov.period = 0;
					pub_prov.transmit = BT_MESH_TRANSMIT(0, 50);


					int err = bt_mesh_cfg_cli_mod_pub_set_vnd(net_idx, found_node->addr, elem_addr, BT_MESH_VND_MODEL_ID_PROV_HELPER_CLI, COMPANY_ID, &pub_prov, &status);
					if (err || status) {
						printk("Failed to set publication (err %d, status: %d)\n",
		    	   			err, status);
					}else{
						printk("Publication set! 0x%04x:0x%04x -> 0x%04x\n", found_node->addr, elem_addr, self_addr);
					}
				}
				if(vnd_id.id == BT_MESH_VND_MODEL_ID_PROV_HELPER_SRV){
					printk("Found Provisioner Helper Server for 0x%03x:0x%04x\n",
							found_node->addr, elem_addr);
				
				}

			} */

			elem_addr++;
		}

	}

	for(int i = 0; i < light_counter; i++ ){
		printk("Lights 0x%08x\n", lights[i]);
		printk("Switches 0x%08x\n", switches[i]);
	}

	if(switch_counter == 0 || light_counter == 0){
		printk("Skipping %d %d", switch_counter, light_counter);
		goto skip_pub_set;
	}

	pub_cfg.addr = 0;
	pub_cfg.uuid = NULL;
	pub_cfg.app_idx = app_idx;
	pub_cfg.cred_flag = false;
	pub_cfg.ttl = 35;
	pub_cfg.period = 0;
	pub_cfg.transmit = BT_MESH_TRANSMIT(0, 50);

	//int publication_counter = 0;

	int max_elements = (switch_counter < light_counter ? light_counter : switch_counter);

	int light_count = 0;
	int switch_count = 0;

	while (switch_count < max_elements && light_count < max_elements) {

			if(switches[switch_count] == 0){
				switch_count = 0;
			}

			if(lights[light_count] == 0){
				light_count = 0;
			}

			pub_cfg.addr = (uint16_t)(lights[light_count] & 0xFFFF);
			printk("Setting publication 0x%03x:%04x -> %04x\n", (uint16_t)((switches[switch_count] & 0xFFFF0000) >> 16), (uint16_t)(switches[switch_count] & 0x0000FFFF) , pub_cfg.addr);
			err = bt_mesh_cfg_cli_mod_pub_set(net_idx, (uint16_t)((switches[switch_count] & 0xFFFF0000) >> 16), (uint16_t)(switches[switch_count] & 0x0000FFFF), BT_MESH_MODEL_ID_GEN_ONOFF_CLI, &pub_cfg, &status);
			if (err || status) {
			printk("Failed to set publication (err %d, status: %d)\n",
		    	   err, status);
				//return;
			}
			switch_count++;
			light_count++;

	}


	printk("Publication configuration set\n");
skip_pub_set:
	return;

}


static void unprovisioned_beacon(uint8_t uuid[16],
				 bt_mesh_prov_oob_info_t oob_info,
				 uint32_t *uri_hash)
{
	memcpy(node_uuid, uuid, 16);
	k_sem_give(&sem_unprov_beacon);
}

static void node_added(uint16_t idx, uint8_t uuid[16], uint16_t addr, uint8_t num_elem)
{
	node_addr = addr;
	k_sem_give(&sem_node_added);
}

static const struct bt_mesh_prov prov = {
	.uuid = dev_uuid,
	.unprovisioned_beacon = unprovisioned_beacon,
	.node_added = node_added,
	//.oob_info = BT_MESH_PROV_OOB_CERTIFICATE,
	//.static_val = "testtesttesttes",
	//.static_val_len = 15,
};

static int bt_ready(void)
{
	uint8_t dev_key[16];
	int err;

	err = bt_mesh_init(&prov, &mesh_comp);
	if (err) {
		printk("Initializing mesh failed (err %d)\n", err);
		return err;
	}
/*
	if((err = bt_mesh_auth_method_set_static("testtesttesttes", sizeof("testtesttesttes"))) == 0){
		printk("Static Val set\n");
	}else{
		printk("Could not set static val %d\n", err);
	}
*/
	printk("Mesh initialized\n");

	if (IS_ENABLED(CONFIG_BT_SETTINGS)) {
		printk("Loading stored settings\n");
		settings_load();
	}

	bt_rand(net_key, 16);

	// This part can be skipped on the outer provisioners
	
	err = bt_mesh_cdb_create(net_key);
	if (err == -EALREADY) {
		printk("Using stored CDB\n");
	} else if (err) {
		printk("Failed to create CDB (err %d)\n", err);
		return err;
	} else {
		printk("Created CDB\n");
		setup_cdb();
	}

	bt_rand(dev_key, 16);

	err = bt_mesh_provision(net_key, BT_MESH_NET_PRIMARY, 0, 0, self_addr,
				dev_key);
	if (err == -EALREADY) {
		printk("Using stored settings\n");
	} else if (err) {
		printk("Provisioning failed (err %d)\n", err);
		return err;
	} else {
		printk("Provisioning completed\n");
	}

	return 0;
}

static uint8_t check_unconfigured(struct bt_mesh_cdb_node *node, void *data)
{
	if (!atomic_test_bit(node->flags, BT_MESH_CDB_NODE_CONFIGURED)) {
		if (node->addr == self_addr) {
			configure_self(node);
		} else {
			configure_node(node);

			while(bt_mesh_prov_helper_cli_send_appkey(&elements[0].vnd_models[0], app_key, node->addr) == -EBUSY){k_sleep(K_MSEC(100));};
		
			while(bt_mesh_prov_helper_cli_send_netkey(&elements[0].vnd_models[0], net_key, node->addr) == -EBUSY){k_sleep(K_MSEC(100));};

			struct bt_mesh_cdb_node* newnode = bt_mesh_cdb_node_get(node_addr);

			printk("New node has %d elements\n", newnode->num_elem);
			current_node_address += newnode->num_elem;


			provisioned_count++;

			if(provisioned_count >= 3){
				send_provisioning_data_to_outer_nodes();
			}
		}
	}

	return BT_MESH_CDB_ITER_CONTINUE;
}

#if DT_NODE_HAS_STATUS(SW0_NODE, okay)
static const struct gpio_dt_spec button_one = GPIO_DT_SPEC_GET_OR(SW0_NODE, gpios, {0});
static const struct gpio_dt_spec button_two = GPIO_DT_SPEC_GET_OR(SW1_NODE, gpios, {0});
static const struct gpio_dt_spec button_three = GPIO_DT_SPEC_GET_OR(SW2_NODE, gpios, {0});
static const struct gpio_dt_spec button_four = GPIO_DT_SPEC_GET_OR(SW3_NODE, gpios, {0});
static struct gpio_callback button_one_cb_data;
static struct gpio_callback button_two_cb_data;
static struct gpio_callback button_three_cb_data;
static struct gpio_callback button_four_cb_data;

static void button_one_pressed(const struct device *dev, struct gpio_callback *cb, uint32_t pins)
{
	k_sem_give(&sem_button_pressed);
}

static void button_two_pressed(const struct device *dev, struct gpio_callback *cb, uint32_t pins)
{
	k_sem_give(&sem_button_two_pressed);
}

static void button_three_pressed(const struct device *dev, struct gpio_callback *cb, uint32_t pins)
{
	k_sem_give(&sem_button_three_pressed);
}

static void button_four_pressed(const struct device *dev, struct gpio_callback *cb, uint32_t pins)
{
	k_sem_give(&sem_button_four_pressed);
}

static void button_init(void)
{
	int ret;

	if (!gpio_is_ready_dt(&button_one)) {
		printk("Error: button device %s is not ready\n", button_one.port->name);
		return;
	}

	if (!gpio_is_ready_dt(&button_two)) {
		printk("Error: button device %s is not ready\n", button_two.port->name);
		return;
	}

	if (!gpio_is_ready_dt(&button_three)) {
		printk("Error: button device %s is not ready\n", button_three.port->name);
		return;
	}
	
	if (!gpio_is_ready_dt(&button_four)) {
		printk("Error: button device %s is not ready\n", button_four.port->name);
		return;
	}

	ret = gpio_pin_configure_dt(&button_one, GPIO_INPUT);
	if (ret != 0) {
		printk("Error %d: failed to configure %s pin %d\n", ret, button_one.port->name,
		       button_one.pin);
		return;
	}

	ret = gpio_pin_configure_dt(&button_two, GPIO_INPUT);
	if (ret != 0) {
		printk("Error %d: failed to configure %s pin %d\n", ret, button_two.port->name,
		       button_two.pin);
		return;
	}

	ret = gpio_pin_configure_dt(&button_three, GPIO_INPUT);
	if (ret != 0) {
		printk("Error %d: failed to configure %s pin %d\n", ret, button_three.port->name,
		       button_three.pin);
		return;
	}

	ret = gpio_pin_configure_dt(&button_four, GPIO_INPUT);
	if (ret != 0) {
		printk("Error %d: failed to configure %s pin %d\n", ret, button_four.port->name,
		       button_four.pin);
		return;
	}

	ret = gpio_pin_interrupt_configure_dt(&button_one, GPIO_INT_EDGE_TO_ACTIVE);
	if (ret != 0) {
		printk("Error %d: failed to configure interrupt on %s pin %d\n", ret,
		       button_one.port->name, button_one.pin);
		return;
	}

	ret = gpio_pin_interrupt_configure_dt(&button_two, GPIO_INT_EDGE_TO_ACTIVE);
	if (ret != 0) {
		printk("Error %d: failed to configure interrupt on %s pin %d\n", ret,
		       button_two.port->name, button_two.pin);
		return;
	}

	ret = gpio_pin_interrupt_configure_dt(&button_three, GPIO_INT_EDGE_TO_ACTIVE);
	if (ret != 0) {
		printk("Error %d: failed to configure interrupt on %s pin %d\n", ret,
		       button_three.port->name, button_three.pin);
		return;
	}

	ret = gpio_pin_interrupt_configure_dt(&button_four, GPIO_INT_EDGE_TO_ACTIVE);
	if (ret != 0) {
		printk("Error %d: failed to configure interrupt on %s pin %d\n", ret,
		       button_four.port->name, button_four.pin);
		return;
	}

	gpio_init_callback(&button_one_cb_data, button_one_pressed, BIT(button_one.pin));
	gpio_init_callback(&button_two_cb_data, button_two_pressed, BIT(button_two.pin));
	gpio_init_callback(&button_three_cb_data, button_three_pressed, BIT(button_three.pin));
	gpio_init_callback(&button_four_cb_data, button_four_pressed, BIT(button_four.pin));
	gpio_add_callback(button_one.port, &button_one_cb_data);
	gpio_add_callback(button_two.port, &button_two_cb_data);
	gpio_add_callback(button_three.port, &button_three_cb_data);
	gpio_add_callback(button_four.port, &button_four_cb_data);
}
#endif

int main(void)
{
	char uuid_hex_str[32 + 1];
	int err;

	current_node_address = provisioning_address_range_start;

	printk("Initializing...\n");

	/* Initialize the Bluetooth Subsystem */
	err = bt_enable(NULL);
	if (err) {
		printk("Bluetooth init failed (err %d)\n", err);
		return 0;
	}

	printk("Bluetooth initialized\n");
	bt_ready();

#if DT_NODE_HAS_STATUS(SW0_NODE, okay)
	button_init();
#endif

	start_time = k_uptime_get();
	while (1) {
		k_sem_reset(&sem_unprov_beacon);
		k_sem_reset(&sem_node_added);
		bt_mesh_cdb_node_foreach(check_unconfigured, NULL);
		if(provisioned_count >= 3){
			k_sleep(K_FOREVER);
		}
/*
#if DT_NODE_HAS_STATUS(SW1_NODE, okay)
		k_sem_reset(&sem_button_two_pressed);
		printk("Press button 2 to configure publications\n");
		err = k_sem_take(&sem_button_two_pressed, K_SECONDS(5));
		if (err == -EAGAIN) {
			printk("Timed out, button 2 wasn't pressed in time.\n");
			goto skip_publication_config;
		}
#endif

		set_publications(0x0002);
		set_provisioner_publications();


skip_publication_config:


#if DT_NODE_HAS_STATUS(SW2_NODE, okay)
		k_sem_reset(&sem_button_three_pressed);
		printk("Press button 3 to forward prov data\n");
		err = k_sem_take(&sem_button_three_pressed, K_SECONDS(5));
		if (err == -EAGAIN) {
			printk("Timed out, button 3 wasn't pressed in time.\n");
			goto skip_prov_data_forward;
		}
#endif


		send_provisioning_data_to_outer_nodes();




skip_prov_data_forward:
#if DT_NODE_HAS_STATUS(SW3_NODE, okay)
		k_sem_reset(&sem_button_four_pressed);
		printk("Press button 4 to start rpr scan and provision\n");
		err = k_sem_take(&sem_button_four_pressed, K_SECONDS(5));
		if (err == -EAGAIN) {
			printk("Timed out, button 4 wasn't pressed in time.\n");
			goto skip_rpr_start;
		}
#endif

		start_rpr();

skip_rpr_start:
*/
		printk("Waiting for unprovisioned beacon...\n");
		err = k_sem_take(&sem_unprov_beacon, K_SECONDS(5));
		if (err == -EAGAIN) {
			continue;
		}

		bin2hex(node_uuid, 16, uuid_hex_str, sizeof(uuid_hex_str));
/*
#if DT_NODE_HAS_STATUS(SW0_NODE, okay)
		k_sem_reset(&sem_button_pressed);
		printk("Device %s detected, press button 1 to provision.\n", uuid_hex_str);
		err = k_sem_take(&sem_button_pressed, K_SECONDS(30));
		if (err == -EAGAIN) {
			printk("Timed out, button 1 wasn't pressed in time.\n");
			continue;
		}
#endif
*/
		printk("Provisioning %s\n", uuid_hex_str);
		err = bt_mesh_provision_adv(node_uuid, net_idx, 0, 0);
		if (err < 0) {
			printk("Provisioning failed (err %d)\n", err);
			continue;
		}

		printk("Waiting for node to be added...\n");
		err = k_sem_take(&sem_node_added, K_SECONDS(10));
		if (err == -EAGAIN) {
			printk("Timeout waiting for node to be added\n");
			continue;
		}

		printk("Added node 0x%04x\n", node_addr);
	}
	return 0;
}
