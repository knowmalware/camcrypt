import sys

try:
    import argparse
except ImportError:
    print >> sys.stderr, "Missing argparse."
    sys.exit(1)

import camcrypt

def _get_parser(description):
    """Build an ArgumentParser with common arguments for both operations."""
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('key', help="Camellia key.")
    parser.add_argument('input_file', nargs='*',
                        help="File(s) to read as input data. If none are "
                        "provided, assume STDIN.")
    parser.add_argument('-o', '--output_file',
                        help="Output file. If not provided, assume STDOUT.")
    parser.add_argument('-l', '--keylen', type=int, default=128,
                        help="Length of 'key' in bits, must be in one of %s "
                        "(default 128)." % camcrypt.ACCEPTABLE_KEY_LENGTHS)
    parser.add_argument('-H', '--hexkey', action='store_true',
                        help="Treat 'key' as a hex string rather than binary.")

    return parser

def _get_crypto(keylen, hexkey, key):
    """Return a camcrypt.CamCrypt object based on keylen, hexkey, and key."""
    if keylen not in camcrypt.ACCEPTABLE_KEY_LENGTHS:
        raise ValueError("key length must be one of 128, 192, or 256")

    if hexkey:
        key = key.decode('hex')

    return camcrypt.CamCrypt(keylen=keylen, key=key)

def _get_data(filenames):
    """Read data from file(s) or STDIN.

    Args:
        filenames (list): List of files to read to get data. If empty or
            None, read from STDIN.
    """
    if filenames:
        data = ""
        for filename in filenames:
            with open(filename, "rb") as f:
                data += f.read()
    else:
        data = sys.stdin.read()

    return data

def _print_results(filename, data):
    """Print data to a file or STDOUT.

    Args:
        filename (str or None): If None, print to STDOUT; otherwise, print
            to the file with this name.
        data (str): Data to print.
    """
    if filename:
        with open(filename, 'wb') as f:
            f.write(data)
    else:
        print data

def cli_encrypt():
    description = "Encrypt data from one or more files or STDIN."
    parser = _get_parser(description)
    args = parser.parse_args()

    try:
        crypto = _get_crypto(args.keylen, args.hexkey, args.key)
    except ValueError as e:
        parser.error(e.message)
    data = _get_data(args.input_file)

    e_data = crypto.encrypt(data)

    _print_results(args.output_file, e_data)

def cli_decrypt():
    description = "Decrypt data from one or more files or STDIN."
    parser = _get_parser(description)
    parser.add_argument('-s', '--strip-nulls', action='store_true',
                        help="Remove trailing nulls, if any, from output.")
    args = parser.parse_args()

    try:
        crypto = _get_crypto(args.keylen, args.hexkey, args.key)
    except ValueError as e:
        parser.error(e.message)
    data = _get_data(args.input_file)

    d_data = crypto.decrypt(data)
    if args.strip_nulls:
        d_data = d_data.rstrip('\x00')

    _print_results(args.output_file, d_data)
