"""Explicit future-use CLI; no experiment runner or example corpus is bundled."""
import argparse
import json
from pathlib import Path
from .api import validate_batch
from .export import export_results


def main():
    parser=argparse.ArgumentParser(description='CPC2 local admission utility; invocation is not scientific validation')
    parser.add_argument('--profile',type=Path,required=True)
    parser.add_argument('--keys',type=Path,required=True,help='externally supplied synthetic fixture registry')
    parser.add_argument('--validation-time',required=True)
    parser.add_argument('--input',type=Path,nargs='+',required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists():
        parser.error('output directory already exists; results will not be overwritten')
    profile=json.loads(args.profile.read_text(encoding='utf-8'))
    keys=json.loads(args.keys.read_text(encoding='utf-8'))
    results=validate_batch((p.read_bytes() for p in args.input),profile,keys,args.validation_time)
    summary=export_results(results,args.output)
    print(json.dumps(summary,sort_keys=True))
    return 2 if summary['counts']['NOT_EVALUATED_CONFIG'] else 0

if __name__=='__main__':
    raise SystemExit(main())
