#!/usr/bin/env python

import sys
import helpers

if __name__ == '__main__':
    dissector_name, fpath, offset = helpers.handle_argv_common_utility()

    # if user says analyze with "pe32", try to get module 'finter.pe32' .analyze
    if dissector_name:
        analyze = helpers.lookup_analyze_function(dissector_name, ['print', 'exit'])
    else:
        analyze = helpers.find_dissector(fpath, offset, ['print', 'exit'])

    if not analyze:
        raise Exception('no dissector found')

    with open(fpath, 'rb') as fp:
        fp.seek(offset)
        analyze(fp)

