#include "project.h"
#include "xcpmd.h"
#include "rpcgen/vglass_client.h"
#include "rules.h"

//Function prototypes
void screen_on(struct arg_node * args);
void screen_off(struct arg_node * args);


//Private data structures
struct action_table_row {
    char * name;
    void (* func)(struct arg_node *);
    char * prototype;
    char * pretty_prototype;
};


//Private data
static struct action_table_row action_table[] = {
    {"screenOn"          , screen_on          , "n" , "void"                    } ,
    {"screenOff"         , screen_off         , "n" , "void"                    }
};

static unsigned int num_action_types = sizeof(action_table) / sizeof(action_table[0]);
static int times_loaded = 0;


//Registers this module's action types.
//The constructor attribute causes this function to run at load (dlopen()) time.
__attribute__ ((constructor)) static void init_module() {

    unsigned int i;

    if (times_loaded > 0)
        return;

    for (i=0; i < num_action_types; ++i) {
        add_action_type(action_table[i].name, action_table[i].func, action_table[i].prototype, action_table[i].pretty_prototype);
    }
}


//Cleans up after this module.
//The destructor attribute causes this to run at unload (dlclose()) time.
__attribute__ ((destructor)) static void uninit_module() {

    --times_loaded;

    //if (times_loaded > 0)
    //    return;

    return;
}


//Actions
void screen_on(struct arg_node * args) {
    mil_af_secureview_vglass_set_dpms_(xcdbus_conn, "mil.af.secureview.vglass", "/mil/af/secureview/vglass", false);
}


void screen_off(struct arg_node * args) {
    mil_af_secureview_vglass_set_dpms_(xcdbus_conn, "mil.af.secureview.vglass", "/mil/af/secureview/vglass", true);
}
