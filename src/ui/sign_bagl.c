#ifdef HAVE_BAGL

#include <stdio.h>
#include "ux.h"
#include "menu.h"
#include "../handler/sign.h"

// length of the max value of an uint32 represented as a string + '\0'
char g_index_str[10 + 1];

// "0x" + signing root size represented as a string + '\0'
char g_signing_root_str[2 + (SIGNING_ROOT_SIZE * 2) + 1];

// Calls the handler function and go back to the home page
static void ui_sign(bool approved) {
    sign(approved);
    ui_menu_main();
}

// Step with icon and text
UX_STEP_NOCB(ux_display_review_step,
             pnn,
             {
                 &C_icon_eye,
                 "Review",
                 "signature",
             });
// Step with title/text for index
UX_STEP_NOCB(ux_display_index_step,
             bnnn_paging,
             {
                 .title = "Account index",
                 .text = g_index_str,
             });
// Step with title/text for signing root
UX_STEP_NOCB(ux_display_signing_root_step,
             bnnn_paging,
             {
                 .title = "Signing root",
                 .text = g_signing_root_str,
             });
// Step with approve button
UX_STEP_CB(ux_display_approve_step,
           pb,
           ui_sign(true),
           {
               &C_icon_validate_14,
               "Approve",
           });
// Step with reject button
UX_STEP_CB(ux_display_reject_step,
           pb,
           ui_sign(false),
           {
               &C_icon_crossmark,
               "Reject",
           });

// FLOW to display sign information:
// #1 screen : eye icon + "Review signature"
// #2 screen : display index
// #3 screen : display signing root
// #4 screen : approve button
// #5 screen : reject button
UX_FLOW(ux_display_sign_flow,
        &ux_display_review_step,
        &ux_display_index_step,
        &ux_display_signing_root_step,
        &ux_display_approve_step,
        &ux_display_reject_step);

void ui_display_sign(void) {
    ux_flow_init(0, ux_display_sign_flow, NULL);
}

#endif  // HAVE_BAGL
