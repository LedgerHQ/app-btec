#ifndef SIGN_H_
#define SIGN_H_

#include <stdbool.h>

#define SIGNING_ROOT_SIZE 32

int handler_sign(uint32_t index, uint8_t *signing_root);
void sign(bool approved);

#endif  // SIGN_H_
