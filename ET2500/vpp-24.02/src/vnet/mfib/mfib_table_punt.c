#include <stdlib.h>
#include <string.h>
#include <vnet/mfib/mfib_table_punt.h>

#define MAX_TABLE_ID 256

typedef struct {
    bool punt_enabled[MAX_TABLE_ID];
    bool valid[MAX_TABLE_ID];  
    u32 max_table_id;         
} table_punt_array_t;

static table_punt_array_t *table_punt_array = NULL;

int table_punt_array_init(void) {
    if (table_punt_array) {
        return 0;
    }
    
    table_punt_array = (table_punt_array_t *)calloc(1, sizeof(table_punt_array_t));
    if (!table_punt_array) {
        return -1;
    }
    
    memset(table_punt_array->valid, 0, sizeof(table_punt_array->valid));
    memset(table_punt_array->punt_enabled, 0, sizeof(table_punt_array->punt_enabled));
    table_punt_array->max_table_id = 0;
    
    return 0;
}

int table_punt_array_set(u32 table_id, bool punt_enabled) {
    if (!table_punt_array) {
        int ret = table_punt_array_init();
        if (ret != 0) return ret;
    }
    
    if (table_id >= MAX_TABLE_ID) {
        return -1; 
    }
    
    table_punt_array->punt_enabled[table_id] = punt_enabled;
    table_punt_array->valid[table_id] = true;
    
    if (table_id > table_punt_array->max_table_id) {
        table_punt_array->max_table_id = table_id;
    }
    
    return 0;
}

bool table_punt_array_get(u32 table_id) {
    if (!table_punt_array || table_id >= MAX_TABLE_ID) {
        return false; 
    }
    
    if (!table_punt_array->valid[table_id]) {
        return false;
    }
    
    return table_punt_array->punt_enabled[table_id];
}