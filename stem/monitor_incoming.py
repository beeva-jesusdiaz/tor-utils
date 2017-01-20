#!/usr/bin/env python

import sys
import signal
import stem
from stem.control import EventType, Controller

def signal_handler(signal, frame):
    controller.close()
    fd.close()
    sys.exit(0)

def ic_event_handler (event):
  fd.write("%s\n" % event)  
#  if event.status == "NEW":
#    print ("New incoming connection: %s" % event)


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

  filename = "output.log"
  fd = open (filename, 'w')
  signal.signal(signal.SIGINT, signal_handler)

  # Add an event for incoming connections
  try:
    controller.add_event_listener(ic_event_handler, EventType.ORCONN)
  except stem.ProtocolError as exc:
    print (exc)

  while True:
    pass
