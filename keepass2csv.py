#!/usr/bin/env python
from __future__ import print_function
import libkeepass
import getpass
import sys
import csv

try:
    filename = sys.argv[1]
    outputfile = sys.argv[2]
except IndexError:
    print('keepass2csv.py <kdbx file name> <output csv file name>')
    sys.exit(1)

try:
    with libkeepass.open(filename, password=getpass.getpass()) as kdb:
        removed_uuids = {uuid.text for uuid in kdb.obj_root.findall('.//DeletedObject/UUID')}
        found = []
        for entry in kdb.obj_root.findall('.//Group/Entry'):
            uuid = entry.find('./UUID').text
            kv = {string.find('./Key').text : string.find('./Value').text for string in entry.findall('./String')}
            if uuid not in removed_uuids:
                found.append({'Title' : kv['Title'], 'Website' : kv['URL'], 'Username' : kv['UserName'], 'Password' : kv['Password']})

        #for kv_entry in { found[k] for k in found.keys() if k not in removed_uuids }:
        #    print(kv_entry)

    with open(outputfile, 'w') as csvfile:
        csv_columns = ['Title', 'Website', 'Username', 'Password']
        writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
        writer.writeheader()
        for data in found:
            writer.writerow(data)
except Exception as e:
    print('Could not export KeePass Database %s:\n%s' % (filename, str(e)), file=sys.stderr)
    sys.exit(2)
