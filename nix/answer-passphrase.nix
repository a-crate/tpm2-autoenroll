# A minimal password agent, which is all a VM test needs to stand in for
# plymouth or the console agent. systemd's protocol is: read Socket= out of
# /run/systemd/ask-password/ask.*, then send "+" followed by the password as a
# datagram. This is what a real agent does, so nothing here is a hook into the
# daemon.
#
# It takes a sequence of answers and spends one per *distinct* request, which is
# what lets a test say "answer wrong, then right" and assert that the daemon
# asked twice.
{ pkgs }:

pkgs.writeScriptBin "answer-passphrase" ''
  #!${pkgs.python3}/bin/python3
  import glob
  import os
  import socket
  import sys
  import time

  ANSWERS = sys.argv[1:]
  if not ANSWERS:
      print("usage: answer-passphrase ANSWER [ANSWER...]", file=sys.stderr)
      sys.exit(2)


  def reply_socket(ask_file):
      try:
          with open(ask_file) as fh:
              for line in fh:
                  if line.startswith("Socket="):
                      return line.split("=", 1)[1].strip()
      except FileNotFoundError:
          pass
      return None


  def answer_one(answer, already):
      """Spend one answer on the first request we have not already answered."""
      deadline = time.monotonic() + 60
      while time.monotonic() < deadline:
          for ask_file in sorted(glob.glob("/run/systemd/ask-password/ask.*")):
              if ask_file in already:
                  continue
              path = reply_socket(ask_file)
              if not path or not os.path.exists(path):
                  continue
              sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
              try:
                  sock.connect(path)
                  sock.send(b"+" + answer.encode())
              finally:
                  sock.close()
              already.add(ask_file)
              print("answered " + ask_file)
              return True
          time.sleep(0.1)
      return False


  answered = set()
  for index, answer in enumerate(ANSWERS):
      if not answer_one(answer, answered):
          print(
              f"request {index + 1} of {len(ANSWERS)} did not appear within 60s",
              file=sys.stderr,
          )
          sys.exit(1)
  sys.exit(0)
''
