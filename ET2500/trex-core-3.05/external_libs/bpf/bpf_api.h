/*
 Itay Marom
 Cisco Systems, Inc.
*/

/*
Copyright (c) 2015-2015 Cisco Systems, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef __BPF_API_H__
#define __BPF_API_H__

#include <stdint.h>
#include "bpfjit/bpfjit.h"

typedef void * bpf_h;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * a value to set bpf_h as none
 */
#define BPF_H_NONE       (NULL)

/**
 * compile a BPF filter pattern 
 *  
 * returns a BPF handler 
 * which later needs to be destroyed 
 * 
 */
bpf_h
bpf_compile(const char *bpf_filter);


/**
 * destroys a previously created BPF handler
 */
void
bpf_destroy(bpf_h bpf);


/**
 * execute a BPF program against a buffer 
 *  
 * returns a nonzero value for match and zero for no match
 */
int
bpf_run(bpf_h bpf, const char *buffer, uint32_t len);


/**
 * verifies a BPF pattern 
 * returns nonzero value on success
 * 
 * @author imarom (7/5/2017)
 * 
 * @param bpf_filter 
 * 
 * @return int 
 */
int
bpf_verify(const char *bpf_filter);


/**
 * returns the pattern used to compile the BPF filter
 * 
 * @author imarom (7/5/2017)
 * 
 * @param bpf 
 * 
 * @return const char* 
 */
const char *
bpf_get_pattern(bpf_h bpf);


/**
 * compiles a BPF pattern to x86 native code
 *  
 * bpfjit_func_t can be executed by passing NULL and bpf_args_t 
 */
bpf_h
bpfjit_compile(const char *bpf_filter);


/**
 * destroy an object compiled with bpfjit_compile
 * 
 */
void
bpfjit_destroy(bpf_h bpfjit);


/**
 * execute a BPF JIT-compiled program on a buffer
 * 
 * return nonzero in case of a match
 */
static inline int
bpfjit_run(bpf_h bpfjit, const char *buffer, uint32_t len) {
    bpfjit_func_t func = (bpfjit_func_t)bpfjit;
    bpf_args_t args;
    
    args.pkt     = (const uint8_t *)buffer;
    args.buflen  = len;
    args.wirelen = len;
    
    return func(NULL, &args);
}


#ifdef __cplusplus
}
#endif

#endif /* __BPF_API_H__*/

