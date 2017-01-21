#!/usr/bin/env python
import os
import stem
import sys
import getpass

from stem.control import Controller
from flask import Flask

app = Flask(__name__)


@app.route('/')
def index():
  return "<h1>Hi Grandma!</h1>"

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
    
  # All hidden services have a directory on disk. Lets put ours in tor's data
  # directory.

  hidden_service_dir = os.path.join(controller.get_conf('DataDirectory', '/tmp'), 'hello_world')

  # Create a hidden service where visitors of port 80 get redirected to local
  # port 5000 (this is where Flask runs by default).

  print(" * Creating our hidden service in %s" % hidden_service_dir)
  response = controller.create_ephemeral_hidden_service({80: 5000}, await_publication = True)
  print(" * Our service is available at %s.onion, press ctrl+c to quit" % response.service_id)

  try:
    app.run()
  finally:
    print(" * Shutting down our hidden service")
