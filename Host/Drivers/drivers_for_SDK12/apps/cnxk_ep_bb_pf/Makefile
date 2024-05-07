#******************************************************************************
#
#   Copyright (c) 2020 Intel.
#   Copyright (c) 2022 Marvell.
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#
#******************************************************************************/

CC=gcc
CFLAGS=-Wall -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE -z relro -z now -z noexecstack -s -O1
ODIR=build
SRC = main.c

ifeq ($(shell cat /usr/include/linux/vfio.h | grep VFIO_DEVICE_FEATURE_PCI_VF_TOKEN > /dev/null && echo 0), 0)

OBJ = $(patsubst %.c,$(ODIR)/%.o,$(SRC))

.PHONY: clean

all: cnxk_ep_bb_pf

$(ODIR):
	mkdir -p $(ODIR)

$(OBJ): $(ODIR)/%.o: ./%.c | $(DEPS) $(ODIR)
	@mkdir -p $(@D)
	$(CC) -c -o $@ $< $(CFLAGS) $(INCLUDE)

cnxk_ep_bb_pf: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

clean:
	rm -rf $(ODIR)
	rm -rf cnxk_ep_bb_pf
else

all:
	touch .cnxk_ep_bb_pf_not_built
clean:
	rm -f .cnxk_ep_bb_pf_not_built
endif
