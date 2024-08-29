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


#include "TcpHeader.h"



void TCPHeader::dump(FILE *fd)
{
    fprintf(fd, "\nTCPHeader");
    fprintf(fd, "\nSourcePort 0x%.4X, DestPort 0x%.4X",
            getSourcePort(), getDestPort());
    fprintf(fd, "\nSeqNum 0x%.8lX, AckNum 0x%.8lX, Window %d",
            (ulong)getSeqNumber(), (ulong)getAckNumber(), getWindowSize());
    fprintf(fd, "\nHeader Length : %d, Checksum : 0x%.4X",
            getHeaderLength(), getChecksum());
    fprintf(fd, "\nFlags : SYN - %d, FIN - %d, ACK - %d, URG - %d, RST - %d, PSH - %d",
            getSynFlag(), getFinFlag(), getAckFlag(), getUrgentFlag(), getResetFlag(), getPushFlag());
    fprintf(fd, "\nUrgent Offset %d", getUrgentOffset());
	fprintf(fd, "\n");
}
