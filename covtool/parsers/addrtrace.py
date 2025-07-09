def parse_addrtrace(bv, filepath):
    """parse newline-separated hex addresses"""
    coverage = {}

    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            # parse hex address (with or without 0x)
            try:
                if line.startswith("0x") or line.startswith("0X"):
                    addr = int(line, 16)
                else:
                    addr = int(line, 16)
            except ValueError:
                continue

            # increment hitcount for this address
            coverage[addr] = coverage.get(addr, 0) + 1

    return coverage
