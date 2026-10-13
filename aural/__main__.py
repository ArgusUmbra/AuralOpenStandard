import argparse
import json
import sys
from .core import AuralError, package, verify, extract

def main():
    parser = argparse.ArgumentParser(prog='aural', description='AURAL Draft 0.2 reference CLI')
    commands = parser.add_subparsers(dest='command', required=True)
    pack = commands.add_parser('pack', help='Package an original WAV')
    pack.add_argument('wav')
    pack.add_argument('output')
    pack.add_argument('--title', default='')
    pack.add_argument('--recorded-at', default=None,
                      help='RFC 3339 timestamp with offset; source-declared, not authenticated')
    v = commands.add_parser('verify', help='Check package and payload integrity')
    v.add_argument('aural')
    ex = commands.add_parser('extract', help='Extract the original WAV after verification')
    ex.add_argument('aural')
    ex.add_argument('output')
    args = parser.parse_args()
    try:
        if args.command == 'pack':
            result = package(args.wav, args.output, args.title, args.recorded_at)
        elif args.command == 'verify':
            result = verify(args.aural)
        else:
            result = {'extracted': str(extract(args.aural, args.output))}
        print(json.dumps(result, indent=2))
    except AuralError as exc:
        print(f'AURAL ERROR: {exc}', file=sys.stderr)
        return 1
    return 0

if __name__ == '__main__':
    sys.exit(main())
