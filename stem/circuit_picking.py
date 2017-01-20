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

def pickNodeFromList (list, msg):

    print ("%s:" % msg)
    i = 0
    for node in list:
        print ("[%s] %s at %s" % (i, node.fingerprint, node.address))
        i += 1

    while True:

        n = raw_input ()        
        if int(n) < len(list) and n >= 0:
            break
        else:
            print ("Choose a node between 0 and %s" % len(list)-1)

        print ("%s:" % msg)

    return int(n)

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

  # Try getting network information
  try:
    list = controller.get_network_statuses ()
  except stem.ControllerError as exc:
    print("Unable to retrieve network statuses: %s" % exc)

  # Get the nodes seen by our node, by country
  [exits, rest] = getNodesByCountry (list)    

  # Ask the user what country s/he wants
  while True:
    code = raw_input ("Enter node location: ")
    if code in exits.keys():
      break
    else:
      print ("The specified country is not available")
      print ("Available countries: %s" % exits.keys())

  # Create the circuit
  try:

    # Pick nodes for each hop (fixed to 3, and all in the same country, this is just an example...)
    n1 = pickNodeFromList (rest[code], "Pick an entry node")
    n2 = pickNodeFromList (rest[code], "Pick a middle node")
    n3 = pickNodeFromList (exits[code], "Pick an exit node")

    # Try to build the actual circuit
    print ("Trying to build a circuit through: %s -> %s -> %s" % (rest[code][n1].fingerprint, rest[code][n2].fingerprint, exits[code][n3].fingerprint))
    path = [rest[code][n1].fingerprint, rest[code][n2].fingerprint, exits[code][n3].fingerprint]
    circuit = controller.new_circuit(path = path, purpose = 'general', await_build = True)

    # Print all available circuits to check that ours has been built
    print ("Current circuits:")
    circs = controller.get_circuits()
    for circ in circs:
      print (circ)

  # Exit
  except stem.ControllerError as exc:
    print("Unable to open circuit: %s" % exc)
          
  controller.close()
