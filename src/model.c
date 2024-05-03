
#include <zephyr/kernel.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/mesh.h>


#define COMPANY_ID 0x1234
#define MODEL_ID   0x5678

#define MESSAGE_APPKEY_OPCODE       BT_MESH_MODEL_OP_3(0x01, COMPANY_ID)
#define MESSAGE_NETKEY_OPCODE       BT_MESH_MODEL_OP_3(0x02, COMPANY_ID)
#define MESSAGE_NODEINFO_OPCODE     BT_MESH_MODEL_OP_3(0x03, COMPANY_ID)

#define MESSAGE_APPKEY_LEN          16
#define MESSAGE_NETKEY_LEN          16
#define MESSAGE_NODEINFO_LEN        16


BT_MESH_MODEL_VND_CB(COMPANY_ID,
                     MODEL_ID,
                     _opcode_list,
                     NULL,
                     NULL,
                     NULL);


static int send_appkey(struct bt_mesh_model *model, uint16_t addr){

    struct bt_mesh_msg_ctx ctx = {
        .addr = addr,
        .app_idx = model->keys[0],
        .send_ttl = BT_MESH_TTL_DEFAULT,
    };
    BT_MESH_MODEL_BUF_DEFINE(buf, MESSAGE_APPKEY_OPCODE, MESSAGE_APPKEY_LEN);
    bt_mesh_model_msg_init(&buf, MESSAGE_APPKEY_OPCODE);

    // Fill message buffer

    return bt_mesh_model_send(model, &ctx, &buf, NULL, NULL);
}

static int send_netkey(struct bt_mesh_model *model, uint16_t addr){

    struct bt_mesh_msg_ctx ctx = {
        .addr = addr,
        .app_idx = model->keys[0],
        .send_ttl = BT_MESH_TTL_DEFAULT,
    };
    BT_MESH_MODEL_BUF_DEFINE(buf, MESSAGE_NETKEY_OPCODE, MESSAGE_NETKEY_LEN);
    bt_mesh_model_msg_init(&buf, MESSAGE_NETKEY_OPCODE);

    // Fill message buffer

    return bt_mesh_model_send(model, &ctx, &buf, NULL, NULL);
}

static int send_nodeinfo(struct bt_mesh_model *model, uint16_t addr){

    struct bt_mesh_msg_ctx ctx = {
        .addr = addr,
        .app_idx = model->keys[0],
        .send_ttl = BT_MESH_TTL_DEFAULT,
    };
    BT_MESH_MODEL_BUF_DEFINE(buf, MESSAGE_NODEINFO_OPCODE, MESSAGE_NODEINFO_LEN);
    bt_mesh_model_msg_init(&buf, MESSAGE_NODEINFO_OPCODE);

    // Fill message buffer

    return bt_mesh_model_send(model, &ctx, &buf, NULL, NULL);
}

static void handle_message_appkey(struct bt_mesh_model *model,
                                  struct bt_mesh_msg_ctx *ctx,
                                  struct net_buf_simple *buf){

                                

}

static void handle_message_netkey(struct bt_mesh_model *model,
                                  struct bt_mesh_msg_ctx *ctx,
                                  struct net_buf_simple *buf){


}

static void handle_message_nodeinfo(struct bt_mesh_model *model,
                                  struct bt_mesh_msg_ctx *ctx,
                                  struct net_buf_simple *buf){

}

const struct bt_mesh_model_op _opcode_list[] = {
    { MESSAGE_APPKEY_OPCODE, MESSAGE_APPKEY_LEN, handle_message_appkey },
    { MESSAGE_NETKEY_OPCODE, MESSAGE_NETKEY_LEN, handle_message_netkey },
    { MESSAGE_NODEINFO_OPCODE, MESSAGE_NODEINFO_LEN, handle_message_nodeinfo },
    BT_MESH_MODEL_OP_END,
};
