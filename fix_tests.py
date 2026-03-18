#!/usr/bin/env python3
"""
Fix test compilation errors after timer wheel refactor.

Transforms:
1. process_ipv4(frame, now, &nh, ...) -> process_ipv4(frame, now, 0, &mut wheel, &nh, ...)
2. poll_send(now, mac, &nh, ...) -> poll_send(now, 0, &mut wheel, mac, &nh, ...)
3. connect(..., now, free, tx) -> connect(..., now, 0, &mut wheel, free, tx)
4. connect_with_config(..., now, config, free, tx) -> connect_with_config(..., now, 0, &mut wheel, config, free, tx)
5. initiate_close(key) -> initiate_close(key, 0, &mut wheel)
6. poll_timers(now, mac, &nh, ...) -> poll_timers(now, 0, &mut wheel, mac, &nh, ...) [trait method - won't conflict, but fix anyway]
7. Replace deadline field accesses
"""

import re
import sys
import os

def fix_process_ipv4_calls(content):
    """Insert '0, &mut wheel,' after the 'now' argument in process_ipv4 calls."""
    # Pattern: .process_ipv4(\n  frame,\n  now_expr,\n  &nh,
    # We need to insert "0,\n        &mut wheel," after the now line

    # Match process_ipv4 call with the now argument followed by &nh or &neighbor
    pattern = re.compile(
        r'(\.process_ipv4\(\s*\n'        # .process_ipv4(\n
        r'(\s*)'                           # capture indentation
        r'[^,]+,\s*\n'                    # frame arg,\n
        r'\s*[^,]+,)\s*\n'               # now arg,\n  (capture group 1 ends)
        r'(\s*&)'                         # &nh (capture group 3)
    )

    def replacer(m):
        indent = m.group(2)
        return f'{m.group(1)}\n{indent}0,\n{indent}&mut wheel,\n{m.group(3)}'

    return pattern.sub(replacer, content)


def fix_poll_send_calls(content):
    """Insert '0, &mut wheel,' after the 'now' argument in poll_send calls."""
    # Pattern: .poll_send(\n  now,\n  mac,
    # Insert after now line
    pattern = re.compile(
        r'(\.poll_send\(\s*\n'             # .poll_send(\n
        r'(\s*)'                            # capture indentation
        r'[^,]+,)\s*\n'                    # now arg,\n (end group 1)
        r'(\s*)'                            # next line indent (group 3)
        r'((?:nh\.local_mac|src_mac|handler\.|local_mac))'  # mac arg start (group 4)
    )

    def replacer(m):
        indent = m.group(2)
        return f'{m.group(1)}\n{indent}0,\n{indent}&mut wheel,\n{m.group(3)}{m.group(4)}'

    return pattern.sub(replacer, content)


def fix_poll_send_single_line(content):
    """Fix single-line poll_send calls like handler.poll_send(now, mac, ...)."""
    # Some tests may have single-line calls
    # Actually looking at the code, they're all multiline. Skip this.
    return content


def fix_connect_calls(content):
    """Insert '0, &mut wheel,' after 'now' in connect() calls.
    connect(..., now, free, tx) -> connect(..., now, 0, &mut wheel, free, tx)
    """
    # Pattern: .connect(\n  ...multiple args...\n  now,\n  &mut free/free,
    # The now arg is coarsetime::Instant::now(), followed by free_frames
    pattern = re.compile(
        r'(\.connect\(\s*\n'               # .connect(\n
        r'(?:\s*[^,]+,\s*\n)*?'            # multiple args
        r'(\s*)'                            # indent (group 2)
        r'(coarsetime::Instant::now\(\)|now),)\s*\n'  # now arg, (group 3 is now expr)
        r'(\s*&mut (?:free|tx))'           # free_frames (group 4)
    )

    def replacer(m):
        indent = m.group(2)
        return f'{m.group(1)}\n{indent}0,\n{indent}&mut wheel,\n{m.group(4)}'

    return pattern.sub(replacer, content)


def fix_connect_with_config_calls(content):
    """Insert '0, &mut wheel,' after 'now' in connect_with_config() calls.
    connect_with_config(..., now, config, free, tx) -> connect_with_config(..., now, 0, &mut wheel, config, free, tx)
    """
    pattern = re.compile(
        r'(\.connect_with_config\(\s*\n'
        r'(?:\s*[^,]+,\s*\n)*?'
        r'(\s*)'                            # indent (group 2)
        r'(coarsetime::Instant::now\(\)|now),)\s*\n'
        r'(\s*config)'                      # config arg (group 4)
    )

    def replacer(m):
        indent = m.group(2)
        return f'{m.group(1)}\n{indent}0,\n{indent}&mut wheel,\n{m.group(4)}'

    return pattern.sub(replacer, content)


def fix_initiate_close_calls(content):
    """initiate_close(key) -> initiate_close(key, 0, &mut wheel)"""
    # Pattern: .initiate_close(expr);
    # But NOT .initiate_close(expr, 0, &mut wheel); (already fixed)
    pattern = re.compile(
        r'\.initiate_close\(([^,\)]+)\);'
    )

    def replacer(m):
        key_arg = m.group(1)
        return f'.initiate_close({key_arg}, 0, &mut wheel);'

    return pattern.sub(replacer, content)


def add_wheel_to_test_functions(content):
    """Add 'let mut wheel = new_wheel();' after the last BasicFrameBuffer::new line in each test function."""
    # Find patterns like:
    #     let mut tx = BasicFrameBuffer::new(N);
    # and add wheel after (if not already present)

    lines = content.split('\n')
    result = []
    i = 0
    while i < len(lines):
        result.append(lines[i])
        # Check if this line creates the last BasicFrameBuffer (tx pattern)
        if 'let mut tx = BasicFrameBuffer::new(' in lines[i] and 'wheel' not in (lines[i+1] if i+1 < len(lines) else ''):
            # Get indentation
            indent = len(lines[i]) - len(lines[i].lstrip())
            indent_str = lines[i][:indent]
            result.append(f'{indent_str}let mut wheel = new_wheel();')
        i += 1

    return '\n'.join(result)


def process_file(filepath):
    with open(filepath, 'r') as f:
        content = f.read()

    original = content

    # Add wheel variable to test functions
    content = add_wheel_to_test_functions(content)

    # Fix method calls
    content = fix_process_ipv4_calls(content)
    content = fix_poll_send_calls(content)
    content = fix_connect_calls(content)
    content = fix_connect_with_config_calls(content)
    content = fix_initiate_close_calls(content)

    if content != original:
        with open(filepath, 'w') as f:
            f.write(content)
        print(f"  Modified: {filepath}")
    else:
        print(f"  Unchanged: {filepath}")


def main():
    base = "/workspace/csaide/voidnet/.worktrees/timer-wheel/src/net/handler/tcp/tests"
    test_files = [
        "handler.rs", "handshake.rs", "data_transfer.rs", "delayed_ack.rs",
        "retransmission.rs", "timers.rs", "keepalive.rs", "persist.rs",
        "teardown.rs", "edge_cases.rs", "ecn.rs", "nagle.rs", "sack.rs",
        "timestamps.rs", "validate.rs", "listener.rs", "congestion_tests.rs",
    ]

    for f in test_files:
        path = os.path.join(base, f)
        if os.path.exists(path):
            process_file(path)
        else:
            print(f"  Missing: {path}")


if __name__ == '__main__':
    main()
