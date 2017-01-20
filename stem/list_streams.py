#!/usr/bin/env python

import io
import sys
import getpass
import stem.process

import stem
from stem.control import Controller

from geoip import geolite2

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

  # Try getting streams
  try:
    streams = controller.get_streams ()
    
  except stem.ControllerError as exc:
      print (exc)
      sys.exit(1)

  for s in streams:
      print (s)
          
  controller.close()
