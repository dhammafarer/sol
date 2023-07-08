#include "mqtt.h"

#include <stdio.h>

int main() {
  char buf[1024];
  size_t len = 16383;
  mqtt_encode_length(buf, len);
  int val = mqtt_decode_length(buf);
  printf("total bytes: %d\n", val);
}
