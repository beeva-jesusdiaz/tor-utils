#!/usr/bin/env python

import io
import sys
import getpass
import stem.process

import stem
from stem.control import Controller

from geoip import geolite2

def getNodesByCountry (list):
  
  exits = {}
  rest = {}
  for entry in list:

    country = geolite2.lookup(entry.address)
    if country is not None:
      country_code = country.country
    else:
      country_code = "Unknown"
  
    # We only want exits
    if u"Exit" in entry.flags:
      if not country_code in exits:
        exits[country_code] = []
      exits[country_code].append(entry)
    else:
      if not country_code in rest:
        rest[country_code] = []
      rest[country_code].append(entry)        
                
  return [exits, rest]

if __name__ == '__main__':

  if len(sys.argv) != 2 or sys.argv[1] == "-h" or sys.argv[1] == "--help":
      print ("Usage: %s <flag>" % sys.argv[0])
      sys.exit(0)

  flag = sys.argv[1]

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

  for node in list:
    if flag in node.flags:
      print (node)

  # Exit
          
  controller.close()
