#!/usr/bin/env python

import io
import sys
import getpass
import stem.process

import stem
from stem.control import Controller

if __name__ == '__main__':

  if len(sys.argv) != 2 or sys.argv[1] == "-h" or sys.argv[1] == "--help":
	print ("Usage: %s <target>" % sys.argv[0])
	sys.exit(0)

  # Create the controller
  try:
    controller = Controller.from_port()    
  except stem.SocketError as exc:    
    print("Unable to connect to tor on port 9051: %s" % exc)
    sys.exit(1)

  # Authenticate
  try:
    controller.authenticate()
  except stem.connection.MissingPassword:      
    pw = getpass.getpass("Controller password: ")
    try:      
        controller.authenticate(password = pw)
    except stem.connection.PasswordAuthFailed:
      print("Unable to authenticate, password is incorrect")
      sys.exit(1)
    except stem.connection.AuthenticationFailure as exc:
      print("Unable to authenticate: %s" % exc)
      sys.exit(1)

  print("Tor is running version %s" % controller.get_version())

  # Try getting network information
  try:
    list = controller.get_network_statuses ()
  except stem.ControllerError as exc:
    print("Unable to retrieve network statuses: %s" % exc)

  sorted_list = sorted (list, key=lambda node:node.digest)

  target = sys.argv[1]
  found = 0
  print ("Looking for the HSDirs serving %s" % target)
  
  for node in sorted_list:
    if u"HSDir" in node.flags:
	if node.digest >= target and found < 3:
		print ("HSDIR: %s\nFlags: %s" % (node.digest, node.flags))
		found += 1

  # Exit
          
  controller.close()
