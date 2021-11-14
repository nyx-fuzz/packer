
import os, sys
from common.color import BOLD, OKGREEN, ENDC

def show_banner(banner_text):
  f = open(os.path.dirname(os.path.realpath(__file__)) + "/../help.txt")
  for line in f:
      print(line.replace("\n", ""))
  f.close()

  print("<< " + BOLD + OKGREEN + sys.argv[0] + ": " + str(banner_text) + " " + ENDC + ">>\n")
