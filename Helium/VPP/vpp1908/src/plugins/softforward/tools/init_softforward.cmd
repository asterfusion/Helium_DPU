set interface state C1 up
set interface state C2 up

set interface promiscuous on C1
set interface promiscuous on C2

set interface asic-priv-proc enable C1
set interface asic-priv-proc enable C2

create softforward mapping name test1
softforward bind C1 mapping test1
softforward bind C2 mapping test1

softforward mapping name test1 add dst 1.2.3.1 dst-map 4.4.4.101 forward 52 src-modify 5.5.5.101
softforward mapping name test1 add dst 1.2.3.2 dst-map 4.4.4.102 forward 52 src-modify 5.5.5.102
softforward mapping name test1 add dst 1.2.3.3 dst-map 4.4.4.103 forward 52 src-modify 5.5.5.103
softforward mapping name test1 add dst 1.2.3.4 dst-map 4.4.4.104 forward 52 src-modify 5.5.5.104
softforward mapping name test1 add dst 1.2.3.5 dst-map 4.4.4.105 forward 52 src-modify 5.5.5.105
softforward mapping name test1 add dst 1.2.3.6 dst-map 4.4.4.106 forward 52 src-modify 5.5.5.106
softforward mapping name test1 add dst 1.2.3.7 dst-map 4.4.4.107 forward 52 src-modify 5.5.5.107
softforward mapping name test1 add dst 1.2.3.8 dst-map 4.4.4.108 forward 52 src-modify 5.5.5.108
softforward mapping name test1 add dst 1.2.3.9 dst-map 4.4.4.109 forward 52 src-modify 5.5.5.109
softforward mapping name test1 add dst 1.2.3.10 dst-map 4.4.4.110 forward 52 src-modify 5.5.5.110