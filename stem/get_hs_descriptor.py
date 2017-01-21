#!/usr/bin/env python

import sys
import stem
import getpass

from stem.control import Controller

if __name__ == '__main__':

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

  if (len(sys.argv) != 2):
    print("Usage: ./get_hs_desriptor.py <onion address>")
    sys.exit()

  # descriptor of duck-duck-go's hidden service (http://3g2upl4pq6kufc4m.onion)
  print(controller.get_hidden_service_descriptor(sys.argv[1]))
