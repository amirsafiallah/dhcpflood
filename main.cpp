#include "DHCPFlood.h"

int main() {
    DHCPFlood flood("wlp5s0");
    flood.start(0,255);
    return 0;
}