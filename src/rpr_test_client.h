#ifndef RPR_TEST_CLIENT_H_
#define RPR_TEST_CLIENT_H_

struct remote_prov_data{
    uint16_t server;
    uint8_t uuid[16];
    int8_t rssi;
};
void start_rpr();
void rpr_clear_oldest_prov_data();


#endif