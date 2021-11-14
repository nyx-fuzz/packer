import sys
import socket
import select
import time
import sys

python_3 = False

def exec_file(path):
  global python_3
  if python_3:
    exec(open(path).read())
  else:
    execfile(path)

def print_usage():
  print("USAGE <file> <tcp/udp/stdout> <port>")

def packet(data=""):
  global mode, python_3
  if mode == "stdout":
    sys.stdout.write(data)
  else:
    ready = select.select([s], [], [], 0)
    if ready[0]:
      try:
        s.recv(4096)
      except:
        print("    cannot recv")
    time.sleep(0.01)
    if python_3:
      s.send(bytes(data, 'latin-1'))
    else:
      s.send(data)
  #print("SEND %d bytes"%(len(data)))
  #print(data)

if len(sys.argv) >= 3:

  if sys.version_info[0] >= 3:
    python_3 = True

  payload_file = sys.argv[1]
  mode = sys.argv[2]

  if mode == "stdout":
    exec_file(sys.argv[1])
  elif (mode == "tcp" or mode == "udp") and len(sys.argv) == 4:
    host = "localhost"
    port = int(sys.argv[3])
    if mode == "tcp":
      s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    elif mode == "udp":
      s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setblocking(0)
    s.settimeout(1)

    connected = False
    for _ in range(100):
      try:
        s.connect((host, port))
        connected = True
        break
      except:
        time.sleep(0.3)
    if not connected:
      print("Could not connect")
      sys.exit(1)
    exec_file(sys.argv[1])
  else:
    print_usage()

else:
  print_usage()
