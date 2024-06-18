#ifndef RPR_TEST_CLIENT_H_
#define RPR_TEST_CLIENT_H_

struct remote_prov_data{
    uint16_t server;
    uint8_t uuid[16];
};
void start_rpr();


#endif