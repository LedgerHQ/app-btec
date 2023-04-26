#ifndef SIGN_H_
#define SIGN_H_

#include <stdint.h>

#define SIGNING_ROOT_SIZE 32

int handler_sign(uint32_t index, uint8_t *signing_root);

#endif  // SIGN_H_
