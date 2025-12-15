#!/usr/bin/python3.12

import os
import sys
import json
from pathlib import Path

import santa

# --------------------------
# Helpers
# --------------------------

def send_json(status_code: int, payload: dict):
  print("Content-Type: application/json")
  print("Access-Control-Allow-Origin: *")
  print("Access-Control-Allow-Methods: GET, POST, OPTIONS")
  print("Access-Control-Allow-Headers: Content-Type")
  print(f"Status: {status_code}")
  print()
  print(json.dumps(payload))
  sys.exit(0)


def read_json_body():
  try:
    length = int(os.environ.get("CONTENT_LENGTH", "0"))
    if length == 0:
      return {}
    raw = sys.stdin.read(length)
    return json.loads(raw)
  except Exception:
    send_json(400, {"error": "Invalid JSON body"})


# --------------------------
# Routing
# --------------------------

method = os.environ.get("REQUEST_METHOD", "GET")
path = os.environ.get("PATH_INFO", "/")

# --------------------------
# Routes
# --------------------------

try:
  if method == "OPTIONS":
    print("Access-Control-Allow-Origin: *")
    print("Access-Control-Allow-Methods: GET, POST, OPTIONS")
    print("Access-Control-Allow-Headers: Content-Type")
    print("Status: 204")
    print()
    sys.exit(0)

  if method == "POST" and path == "/register":
    data = read_json_body()
    if santa.load_assignments():
      send_json(401, {"status": "ok", "message": "Assignments already generated"})
    else:
      santa.register(data["name"], data["password"])
      send_json(200, {"status": "ok", "message": f'{data["name"]} registered'})

  elif path == "/assign":
    if santa.load_assignments():
      send_json(200, {"status": "ok", "message": "Assignments already generated"})
    else:
      santa.generate_assignments()
      send_json(200, {"status": "ok", "message": "Assignments generated"})

  elif method == "POST" and path == "/decrypt":
    data = read_json_body()
    receiver = santa.decrypt_with_password(
      data["password"],
      data["ciphertext_b64"]
    )
    send_json(200, {"status": "ok", "receiver": receiver})

  elif method == "GET" and path == "/clearall":
    santa.clear_files()
    send_json(200, {"status": "ok", "message": "Cleared"})

  elif method == "GET" and path == "/registry":
    send_json(200, santa.load_registry())

  elif method == "GET" and path == "/assignments":
    send_json(200, santa.load_assignments())

  elif method == "GET" and path == "/":
    html = Path("ui4.html").read_text()
    print("Content-Type: text/html")
    print()
    print(html)
    sys.exit(0)

  else:
    send_json(404, {"error": "Not found"})

except KeyError as e:
  send_json(400, {"error": f"Missing field: {e}"})
except Exception as e:
  send_json(500, {"error": str(e)})
