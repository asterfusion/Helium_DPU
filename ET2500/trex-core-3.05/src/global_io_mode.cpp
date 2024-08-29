/*
 Hanoh Haim
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
#include "global_io_mode.h"
#include "utl_term_io.h"
#include <stdlib.h>


void CTrexGlobalIoMode::set_mode(CliDumpMode  mode){
    switch (mode) {
    case  cdDISABLE:
        m_g_mode=gDISABLE;
        m_g_disable_first=false;
        break;
    case  cdNORMAL:
        Reset();
        break;
    case cdSHORT:
        m_g_mode=gNORMAL;
        m_pp_mode=ppDISABLE;
        m_ap_mode=apENABLE;
        m_l_mode=lDISABLE;
        m_rc_mode=rcDISABLE;
        break;
    }
}


bool CTrexGlobalIoMode::handle_io_modes(void){
    int c=utl_termio_try_getch();
    if (c) {
        if (c==3) {
            return true;
        }
        switch (c)  {
        case ccHELP:
            if (m_g_mode==gHELP) {
                m_g_mode=gNORMAL;
            }else{
                m_g_mode=gHELP;
            }
            break;
        case ccGDISABLE:
            if (m_g_mode==gDISABLE) {
                m_g_mode=gNORMAL;
            }else{
                m_g_mode=gDISABLE;
                m_g_disable_first=true;
            }
            break;
        case ccGNORAML:
            Reset();
            break;
        case ccGPP:
            m_g_mode=gNORMAL;
            m_pp_mode++;
            if (m_pp_mode==ppLAST) {
                m_pp_mode = ppDISABLE;
            }
            break;
        case ccGAP:
            m_g_mode=gNORMAL;
            m_ap_mode++;
            if (m_ap_mode == apLAST) {
                m_ap_mode = apDISABLE;
            }
            break;
        case ccGL:
            m_g_mode=gNORMAL;
            m_l_mode++;
            if (m_l_mode == lLAST) {
                m_l_mode = lDISABLE;
            }
            break;
        case ccGRC:
            m_g_mode=gNORMAL;
            m_rc_mode++;
            if (m_rc_mode == rcLAST) {
                m_rc_mode = rcDISABLE;
            }
            break;
        case ccMem:
            if ( m_g_mode==gNORMAL ){
                m_g_mode=gMem;
            }else{
                m_g_mode=gNORMAL;
            }
            break;
        case ccsTT:
            if ( m_g_mode==gNORMAL ){
                m_g_mode=gSTT;
            }else{
                m_g_mode=gNORMAL;
            }
            break;

        case ccNat:
            m_g_mode=gNAT;
            m_nat_mode++;
            if (m_nat_mode==natLAST) {
                m_nat_mode = natDISABLE;
                m_g_mode = gNORMAL;
            }
            break;
        }


    }
    return false;
}

void CTrexGlobalIoMode::Dump(FILE *fd){
    fprintf(fd,"\033[2J");
    fprintf(fd,"\033[2H");
    fprintf(fd," global: %d \n",(int)m_g_mode);
    fprintf(fd," pp    : %d \n",(int)m_pp_mode);
    fprintf(fd," ap    : %d \n",(int)m_ap_mode);
    fprintf(fd," l     : %d \n",(int)m_l_mode);
    fprintf(fd," rc    : %d \n",(int)m_rc_mode);
}

void CTrexGlobalIoMode::DumpHelp(FILE *fd){
        fprintf(fd, "Help for Interactive Commands\n" );
        fprintf(fd, "  %c  : Toggle, Disable all/Default \n", ccGDISABLE);
        fprintf(fd, "  %c  : Go back to default mode \n", ccGNORAML);
        fprintf(fd, "  %c  : Toggle, Help/Default  \n", ccHELP);
        fprintf(fd, "\n");
        fprintf(fd, "  %c  : Per ports    toggle disable -> table -> normal \n", ccGPP);
        fprintf(fd, "  %c  : Global ports toggle disable/enable \n", ccGAP);
        fprintf(fd, "  %c  : Latency      toggle disable -> enable -> enhanced  \n", ccGL);
        fprintf(fd, "  %c  : Rx check  toggle disable -> enable -> enhanced  \n", ccGRC);
        fprintf(fd, "  %c  : Memory stats toggle disable/enable   \n", ccMem);
        fprintf(fd, "  %c  : NAT pending flows toggle disable/enable   \n", ccNat);
        fprintf(fd, "  Press %c or %c to go back to Normal mode \n", ccHELP, ccGNORAML);
}



