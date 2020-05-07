#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2017-2020, SCANOSS Ltd. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from pathlib import Path
import json
from json.decoder import JSONDecodeError
import requests
import os
import sys
import uuid

import hashlib
from crc32c import crc32

# List of extensions that are ignored
FILTERED_EXT = ["", "png", "html", "xml", "svg", "yaml", "yml", "txt", "json", "gif", "md", "test", "cfg", "pdf",
                "properties", "jpg", "vim", "sql", "result", "template", 'tiff', 'bmp', 'DS_Store', 'eot', 'otf', 'ttf', 'woff', 'rgb', 'conf', "class", "pyc", "whl", "gz", "zip", "o", "ico"]

FILTERED_DIRS = ["/.git/", "/.svn/", "/.eggs/", "__pycache__", "/node_modules"]


SCANOSS_SCAN_URL = "https://api.scanoss.co.uk/api/scan/direct"
SCANOSS_KEY_FILE = ".scanoss-key"


def print_usage():
  print("USAGE: scanner.py DIR")
  exit(1)


def main():
  # Check for valid directory
  if (len(sys.argv) < 2):
    print_usage()
  scan_dir = sys.argv[1]
  print("Scanning directory: %s" % scan_dir)
  if not scan_dir or not os.path.isdir(scan_dir):
    print("Invalid directory: %s" % scan_dir)
    print_usage()

    # Check for SCANOSS Key
  home = str(Path.home())
  scanoss_keyfile = "%s/%s" % (home, SCANOSS_KEY_FILE)

  if not os.path.isfile(scanoss_keyfile):
    print("Please enter a valid SCANOSS API Key: ")
    api_key = input()
    with open(scanoss_keyfile, "w") as f:
      f.write(api_key)

  # Read key from file
  with open(scanoss_keyfile) as f:
    api_key = f.readline().strip()

  # Perform the scan
  scan_folder(scan_dir, api_key)


def valid_folder(folder):
  for excluded in FILTERED_DIRS:
    if excluded in folder:
      return False
  return True


def scan_folder(dir: str, api_key: str):
  """ Performs a scan of the folder given

  Parameters
  ----------
  dir : str
    The folder containing the files to be scanned
  api_key : str
    A valid SCANOSS API key
  """

  wfp = ''
  # This is a dictionary that is used to perform a lookup of a file name using the corresponding file index
  files_conversion = {}
  # We assign a number to each of the files. This avoids sending the file names to SCANOSS API,
  # thus hiding the names and the structure of the project from SCANOSS API.
  files_index = 0
  for root, sub, files in os.walk(dir):
    if valid_folder(root):
      for file in [f for f in files if os.path.splitext(f)[1][1:] not in FILTERED_EXT]:
        files_index += 1
        path = os.path.join(root, file)
        files_conversion[str(files_index)] = path
        try:
          with open(path) as f:
            contents = f.read()
            wfp += wfp_for_file(files_index, contents.encode())
        except:
          print("Trying to scan a binary file: %s" % path)

  with open('scan_wfp', 'w') as f:
    f.write(wfp)
  print("Saved generated WFP File in 'scan_wfp'")
  headers = {'X-Session': api_key}
  scan_files = {
      'file': ("%s.wfp" % uuid.uuid1().hex, wfp)}

  r = requests.post(SCANOSS_SCAN_URL, files=scan_files,
                    headers=headers)
  if r.status_code >= 400:
    print("ERROR: The SCANOSS API returned the following error: HTTP %d, %s" %
          (r.status_code, r.text))
    exit(1)
  try:
    json_resp = r.json()
  except JSONDecodeError:

    print("The SCANOSS API returned an invalid JSON")
    with open('bad_json.txt','w') as f:
      f.write(r.text)
    exit(1)
  # Decode file names
  decoded_json = {files_conversion[k]: v for (k, v) in json_resp.items()}
  print(json.dumps(decoded_json, indent=4))


"""
Winnowing Algorithm implementation for SCANOSS.

This module implements an adaptation of the original winnowing algorithm by S. Schleimer, D. S. Wilkerson and A. Aiken
as described in their seminal article which can be found here: https://theory.stanford.edu/~aiken/publications/papers/sigmod03.pdf

The winnowing algorithm is configured using two parameters, the gram size and the window size. For SCANOSS the values need to be:
 - GRAM: 30
 - WINDOW: 64

The result of performing the Winnowing algorithm is a string called WFP (Winnowing FingerPrint). A WFP contains optionally
the name of the source component and the results of the Winnowing algorithm for each file.

EXAMPLE output: test-component.wfp
component=f9fc398cec3f9dd52aa76ce5b13e5f75,test-component.zip
file=cae3ae667a54d731ca934e2867b32aaa,948,test/test-file1.c
4=579be9fb
5=9d9eefda,58533be6,6bb11697
6=80188a22,f9bb9220
10=750988e0,b6785a0d
12=600c7ec9
13=595544cc
18=e3cb3b0f
19=e8f7133d
file=cae3ae667a54d731ca934e2867b32aaa,1843,test/test-file2.c
2=58fb3eed
3=f5f7f458
4=aba6add1
8=53762a72,0d274008,6be2454a
10=239c7dfa
12=0b2188c9
15=bd9c4b10,d5c8f9fb
16=eb7309dd,63aebec5
19=316e10eb
[...]

Where component is the MD5 hash and path of the component container (It could be a path to a compressed file or a URL).
file is the MD5 hash, file length and file path being fingerprinted, followed by
a list of WFP fingerprints with their corresponding line numbers.
"""
# Winnowing configuration. DO NOT CHANGE.
GRAM = 30
WINDOW = 64

# ASCII characters
ASCII_0 = 48
ASCII_9 = 57
ASCII_A = 65
ASCII_Z = 90
ASCII_a = 97
ASCII_z = 122
ASCII_LF = 10
ASCII_BACKSLASH = 92

MAX_CRC32 = 4294967296


def normalize(byte):
  """
  This function normalizes a given byte as an ASCII character

  Parameters
  ----------
  byte : int
    The byte to normalize
  """
  if byte < ASCII_0:
    return 0
  if byte > ASCII_z:
    return 0
  if byte <= ASCII_9:
    return byte
  if byte >= ASCII_a:
    return byte
  if ((byte >= 65) and (byte <= 90)):
    return byte + 32

  return 0


def wfp_for_file(file: str, contents: bytes) -> str:
  """ Returns the WFP for a file by executing the winnowing algorithm over its contents.

  Parameters
  ----------
  file: str
    The name of the file
  contents : bytes
    The full contents of the file as a byte array.
  """
  file_md5 = hashlib.md5(
      contents).hexdigest()
  # Print file line
  wfp = 'file={0},{1},{2}\n'.format(file_md5, len(contents), file)

  # Initialize variables
  gram = ""
  window = []
  normalized = 0
  line = 1
  min_hash = MAX_CRC32
  last_hash = MAX_CRC32
  last_line = 0
  output = ""

  # Otherwise recurse src_content and calculate Winnowing hashes
  for byte in contents:

    if byte == ASCII_LF:
      line += 1
      normalized = 0
    else:
      normalized = normalize(byte)

    # Is it a useful byte?
    if normalized:

      # Add byte to gram
      gram += chr(normalized)

      # Do we have a full gram?
      if len(gram) >= GRAM:
        gram_crc32 = crc32(gram.encode('ascii'))
        window.append(gram_crc32)

        # Do we have a full window?
        if len(window) >= WINDOW:

          # Select minimum hash for the current window
          min_hash = min(window)

          # Is the minimum hash a new one?
          if min_hash != last_hash:

            # Hashing the hash will result in a better balanced resulting data set
            # as it will counter the winnowing effect which selects the "minimum"
            # hash in each window
            crc = crc32((min_hash).to_bytes(4, byteorder='little'))
            crc_hex = '{:08x}'.format(crc)

            if last_line != line:
              if output:
                wfp += output + '\n'
              output = "%d=%s" % (line, crc_hex)
            else:
              output += ',' + crc_hex

            last_line = line
            last_hash = min_hash

          # Shift window
          window.pop(0)

        # Shift gram
        gram = gram[1:]

  if output:
    wfp += output + '\n'

  return wfp


if __name__ == "__main__":
  main()
