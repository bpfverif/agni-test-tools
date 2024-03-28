"""
Program Description:
"""

import os
import sys
import shutil


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 add_bpf_reg_trace.py <kernel_directory_path>")
        sys.exit(0)

    kernel_directory_path = sys.argv[1]  # test that kernel path exists
    bpf_trace_path = "./kernel_prep_files/bpf_state.h"

    if kernel_directory_path[-1] != '/':
        kernel_directory_path += '/'

    verifier_source_path = kernel_directory_path + "kernel/bpf/verifier.c"

    shutil.copyfile(bpf_trace_path, kernel_directory_path +
                    "include/trace/events/bpf_state.h")

    verifier_source = open(verifier_source_path, "r")
    verifier_source_lines = verifier_source.readlines()

    for idx, line in enumerate(verifier_source_lines):
        if line[0] != "#":
            continue

        verifier_source_lines.insert(
            idx, "#include <trace/events/bpf_state.h>\n"
        )
        verifier_source_lines.insert(
            idx, "#define CREATE_TRACE_POINTS\n"
        )

        break

    do_check_start_line = -1
    for idx, line in enumerate(verifier_source_lines):
        if "int do_check(" in line:
            do_check_start_line = idx
            break

    idx = do_check_start_line + 2
    num_open_braces = 1

    while num_open_braces > 0:
        num_open_braces += verifier_source_lines[idx].count("{")
        num_open_braces -= verifier_source_lines[idx].count("}")
        idx += 1

    while "return" not in verifier_source_lines[idx]:
        idx -= 1

    do_check_end_line = idx

    verifier_source_lines.insert(do_check_end_line, "trace_bpf_state(regs);\n")

    verifier_source.close()
    os.remove(verifier_source_path)

    verifier_source = open(verifier_source_path, "w")
    verifier_source.writelines(verifier_source_lines)
    verifier_source.close()


if __name__ == "__main__":
    main()
