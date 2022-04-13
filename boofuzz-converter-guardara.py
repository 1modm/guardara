#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__license__ = """

Author: https://twitter.com/1_mod_m/
Project site: https://github.com/1modm

Copyright (c) 2022, MM
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:
1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.
3. Neither the name of copyright holders nor the names of its
   contributors may be used to endorse or promote products derived
   from this software without specific prior written permission.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
''AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL COPYRIGHT HOLDERS OR CONTRIBUTORS
BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
"""

import os
import re
import sys
import ast
import json
import uuid
import argparse
import datetime
from termcolor import colored # pip3 install termcolor

#------------------------------------------------------------------------------
# Command line parser using argparse
#------------------------------------------------------------------------------

def cmdline_parser():
    parser = argparse.ArgumentParser(conflict_handler='resolve', add_help=True,
             description='Boofuzz to Guardara converter',
             usage="python3 %(prog)s")

    # Mandatory
    parser.add_argument('fuzzer', type=str, help='boofuzz fuzzer file')

    return parser



#------------------------------------------------------------------------------
# Functions
#------------------------------------------------------------------------------

def split_hex(value):
    hex_list = []
    value = value[2:] if len(value) % 2 == 0 else "0" + value[2:]

    for i in range(0, len(value), 2):
        i_hex = value[i:i+2]
        hex_list.append(int(i_hex, base=16))

    return hex_list


def is_hex(s):
    try:
        n = int(s,16)
        return True
    except ValueError:
        return False

def get_groups(boofuzz_string, seq, block_by):
    data = []
    for line in seq:
        if block_by in line:
            if data:
                # yield is a keyword that is used like return, except the function will return a generator.
                yield data
                data = []
        for b in boofuzz_string:
            if b in line:
                data.append(line)
                break
    if data:
        yield data


def define_block(result_block_name, block_list):

    block_item = {
                "field": "block",
                "title": result_block_name,
                "properties": {
                    "name": result_block_name,
                    "logic": "linear",
                    "test": True,
                    "expose": False
                },
                "children": block_list,
                            "meta": {
                                "uuid": str(uuid.uuid4())
                            },
                            "expanded": True
                }

    return block_item


def define_primitive(primitive, name_primitive, value_primitive, fuzzable_primitive, endian_primitive):

    if 'word' in primitive:
        value_fixed = split_hex(value_primitive)
    elif primitive == 'string':
        value_fixed = list(bytearray(value_primitive,'UTF-8'))
    else:
        value_fixed = [int(value_primitive, base=16)]

    primitive_data = {
        "field": primitive,
        "title": name_primitive,
        "properties": {
            "name": name_primitive,
            "value": value_fixed,
            "format": "binary",
            "endian": endian_primitive,
            "full_range": False,
            "test": fuzzable_primitive,
            "expose": False,
            "custom_library": ""
        },
        "meta": {
            "uuid": str(uuid.uuid4())
        }
    }

    return primitive_data


def define_root(block_item_list):

    root_data = {
        "field": "block",
        "title": "Root",
        "properties": {
            "name": "Root",
            "test": True
        },
        "children": block_item_list,
        "variables": [],
        "meta": {
            "uuid": str(uuid.uuid4()),
            "configuration_property_endian": "big"
        }
    }

    return root_data

#------------------------------------------------------------------------------
# Main of program
#------------------------------------------------------------------------------

def main():

    # Get the command line parser.
    parser = cmdline_parser()

    # Show help if no args
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    # Get results line parser.
    results = parser.parse_args()

    boofuzz_fuzzer_file = results.fuzzer
    base=os.path.basename(boofuzz_fuzzer_file)
    boofuzz_fuzzer_title = os.path.splitext(base)[0]

    boofuzz_valid_primitives = ["s_aligned", "s_bigword", "s_binary", "s_bit", "s_bit_field", "s_bits", "s_block", "s_block_end", "s_block_start", "s_byte", "s_bytes", "s_char", "s_checksum", "s_cstring", "s_delim", "s_double", "s_dunno", "s_dword", "s_float", "s_from_file", "s_get", "s_group", "s_hex_dump", "s_initialize", "s_int", "s_intelword", "s_lego", "s_long", "s_mirror", "s_num_mutations", "s_qword", "s_random", "s_raw", "s_repeat", "s_repeater", "s_short", "s_size", "s_sizer", "s_static", "s_simple", "s_string", "s_switch", "s_unknown", "s_update", "s_word"]

    boofuzz_to_guardara_primitives = ["s_binary", "s_bit", "s_bit_field", "s_block", "s_byte", "s_delim", "s_dword", "s_int", "s_qword", "s_random",  "s_string", "s_switch", "s_word"]

    init_block = "s_initialize"
    boofuzz_block = "s_block"

    # Create output directory for results
    outputdirectory = 'output'
    if not os.path.exists(outputdirectory):
        os.makedirs(outputdirectory)
    datenow = datetime.datetime.now()
    outputdate = datenow.strftime('%Y-%m-%d_%H_%M_%S')
    outputdirectory = f"output/{boofuzz_fuzzer_title}/{outputdate}"
    os.makedirs(outputdirectory)
    print(colored(f"[+] Creating output: {outputdirectory}/", "green"))

    with open(boofuzz_fuzzer_file) as f:
        for i, group in enumerate(get_groups(boofuzz_valid_primitives, f, init_block), start=1):

            block_list = []
            block_item_list = []
            result_block_name = ''
            count_block = 0
            fuzzer_title = 'None'

            # Identify each block
            for line in group:
                lineok = line.strip()
                if lineok.startswith('#'):
                    pass
                elif lineok.startswith('s_initialize'):
                    fuzzer_title = re.search(r'\((.*?)\)',lineok).group(1)
                else:
                    pass

            for b, group_b in enumerate(get_groups(boofuzz_to_guardara_primitives, group, boofuzz_block), start=1):
                for lineb in group_b:
                    result_block_bool = False
                    line_b_ok = lineb.strip()

                    if line_b_ok.startswith('s_block') or line_b_ok.startswith('with s_block'):
                        count_block += 1

                        if count_block > 1:

                            new_block = define_block(result_block_name, block_list)
                            block_item_list.append(new_block)

                            count_block = 1
                            block_list = []

                        result_block = re.search(r'\((.*?)\)',line_b_ok).group(1)
                        result_block_name = ast.literal_eval(result_block)

                    elif line_b_ok.startswith(tuple(boofuzz_to_guardara_primitives)):

                        name_primitive = ''
                        fuzzable_primitive = ''
                        value_primitive = ''
                        endian_primitive = 'big'

                        primitive = re.search(r'(s_.*?)\((.*?)\)',line_b_ok).group(1)
                        values = re.search(r'(s_.*?)\((.*?)\)',line_b_ok).group(2)
                        values_split = values.split(",")

                        # Translate boofuzz primitive to guardara primitive
                        primitive = primitive.replace('s_', '')

                        for value in values_split:
                            value_strip = value.strip()
                            if "=" in value_strip:

                                d = value_strip.split("=")

                                if d[0] == 'name':
                                    name_primitive = ast.literal_eval(d[1])
                                elif d[0] == 'fuzzable':
                                    fuzzable_primitive = ast.literal_eval(d[1])
                                elif d[0] == 'endian':
                                    endian_value = ast.literal_eval(d[1])
                                    if endian_value == ">":
                                        endian_primitive = 'big'
                                    elif endian_value == "<":
                                        endian_primitive = 'little'

                            else:
                                if primitive == 'string':
                                    value_primitive = ast.literal_eval(value_strip.strip())
                                else:
                                    # Fix non hexadecimal values
                                    if is_hex(value_strip.strip()):
                                        value_primitive = value_strip.strip()
                                    else:
                                        value_primitive = '0x00'

                        primitive_data = define_primitive(primitive, name_primitive, value_primitive, fuzzable_primitive, endian_primitive)

                        block_list.append(primitive_data)


            new_block = define_block(result_block_name, block_list)
            block_item_list.append(new_block)

            root_json_data = define_root(block_item_list)

            #print(colored(f"{json.dumps(root_json_data, indent=4)}", "yellow"))
            with open(f"{outputdirectory}/{ast.literal_eval(fuzzer_title)}.json", 'w') as f:
                f.write(json.dumps(root_json_data, indent=4))
            f.close()

    print(colored(f"[+] Generated guardara templates for {boofuzz_fuzzer_title} fuzzer", "green"))


#------------------------------------------------------------------------------
# Main
#------------------------------------------------------------------------------

if __name__ == '__main__':
    main()
