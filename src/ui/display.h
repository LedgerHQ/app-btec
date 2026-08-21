#pragma once

extern char g_index_str[10 + 1];
extern char g_signing_root_str[2 + (SIGNING_ROOT_SIZE * 2) + 1];

void ui_display_sign(void);
