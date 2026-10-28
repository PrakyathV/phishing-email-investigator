import os
import urllib.error
import urllib.request

api_key = os.environ.get("VT_API_KEY")
if not api_key:
    raise SystemExit("VT_API_KEY is not set.")

request = urllib.request.Request(
    "https://www.virustotal.com/api/v3/users/{id}",
    headers={"x-apikey": api_key},
)

# The user endpoint requires an account identifier, so instead
# we will use a known, public URL identifier in the next step.
print("API key loaded securely.")
print("Ready to test a public URL reputation lookup.")
