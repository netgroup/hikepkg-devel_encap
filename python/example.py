import os
import sys
import json
import subprocess
import ipaddress
from time import sleep

# add the common eclat python modules to the PYTONPATH
sys.path.append(os.path.abspath(os.getcwd()))
# it works assuming that this python program is called from
# the main eclat-daemon folder (by default /opt/eclat-daemon)
# sys.path.append('/opt/eclat-daemon')

# Command Abstraction Layer
import cal
import hex_types as ht
from sidlist import Sidlist

BASE_PATH =  '/sys/fs/bpf/maps'
PACKAGE = 'devel_encap'
PROGRAM = 'show_pkt_info'
MAP = 'sid_list_1'
map_path = f"{BASE_PATH}/{PACKAGE}/{PROGRAM}/{MAP}"

map_path2 = f"{BASE_PATH}/{PACKAGE}/{PROGRAM}/sid_list_2"

map_as_array = []

MAP_KEY_1 = 2
MAP_KEY_2 = 5


IP_SRC = 0x01000000000000000e0003000a00fbfc
ipv6_addr = ipaddress.IPv6Address('ff00::1')

my_sidlist = Sidlist()
my_sidlist.set(['ff00::12','ff00::13'])
#my_sidlist.add('ff00::1')
#my_sidlist.add('ff00::2')

print (my_sidlist.get())
print (my_sidlist.to_hex())
print (my_sidlist.len())



if not os.path.exists(map_path):
      print(f"path to {map_path} does not exist")
else:
      try :
            cal.cal_map_update(map_path, ht.u32(MAP_KEY_1), ht.u128(IP_SRC))
            cal.cal_map_update(map_path, ht.u32(MAP_KEY_2), ipv6_addr)
            map_as_array = json.loads(cal.bpftool_map_dump(map_path))
            print(f"updated map:\n{map_as_array}")

      except Exception as e:
            print(e)
            print(map_path)

      try :
            cal.cal_map_update(map_path2, ht.u32(MAP_KEY_2), my_sidlist)
            map_as_array = json.loads(cal.bpftool_map_dump(map_path2))
            print(f"updated map:\n{map_as_array}")

      except Exception as e:
            print(e)
            print(map_path2)
