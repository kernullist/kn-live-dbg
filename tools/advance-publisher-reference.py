"""Retain an independently verified publisher release and its previous observation."""
import argparse
import os
import sys

from image_approval_policy import DECODE, read_document
from owned_module_benchmark import encoded, publish_new, sha
import publisher_history as history
from retained_corpus import MAX_DOCUMENT, OutputCollision
from saved_etl_comparison import digest, local_path, outputs_safe, write_result


def main(argv):
    # Check all supplied filenames before argparse can print help or diagnostics.
    try:
        if not outputs_safe(argv):
            return 2
    except (OSError, ValueError):
        return 2
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    entry = parser.add_mutually_exclusive_group(required=True)
    entry.add_argument("--reference", help="exact current v1, v2 or v3 TUF reference")
    entry.add_argument("--verify-history", help="recheck a retained publisher history and reproduce its receipt")
    parser.add_argument("--trusted-root-sha256", required=True, help="independently provisioned original TUF root digest")
    parser.add_argument("--verification-time", required=True, help="observation time in UTC, YYYYMMDDTHHMMSSZ")
    parser.add_argument("--previous", help="successful publisher history file from the previous observation")
    parser.add_argument("--previous-checkpoint-sha256", help="independently retained checkpoint from that observation")
    parser.add_argument("--minimum-root-version", help="lowest accepted terminal root version for the current release")
    parser.add_argument("--out", help="new publisher history file for --reference")
    args = parser.parse_args(argv)
    if (args.reference is not None) != (args.out is not None) or (args.verify_history is not None and args.previous is not None):
        parser.error("--reference requires --out and --verify-history takes neither --out nor --previous")
    if args.reference is not None and (args.previous is None) != (args.previous_checkpoint_sha256 is None):
        parser.error("--previous and --previous-checkpoint-sha256 are required together")
    receipt = dict(schema="kn.publisher_history_result.v1", status="rejected")
    try:
        import publisher_truth
        root = digest(args.trusted_root_sha256)
        instant = history.verification_time(args.verification_time)
        minimum = publisher_truth.root_version_floor(args.minimum_root_version)
        if args.previous_checkpoint_sha256 is not None:
            digest(args.previous_checkpoint_sha256)
        if args.verify_history is not None:
            frame = read_document(args.verify_history, history.MAX_REFERENCE)
            if not frame.startswith(history.MAGIC):
                raise ValueError("expected a publisher history file")
        else:
            destination = local_path(args.out)
            if os.path.lexists(destination):
                raise FileExistsError
            previous = None
            if args.previous is not None:
                _, previous = history.unpack(read_document(args.previous, history.MAX_REFERENCE))
            current = history.Observation(args.verification_time, read_document(args.reference, MAX_DOCUMENT))
            frame = history.pack(previous, current)
        _, proof = publisher_truth.check_reference(frame, DECODE, root, instant, minimum, args.previous_checkpoint_sha256)
        receipt.update(trusted_root_sha256=root, publisher_proof=proof)
        if proof["status"] != "verified":
            return write_result(encoded(receipt)) or 1
        file_pin = sha(frame) if args.verify_history is not None else publish_new(destination, lambda stream: stream.write(frame))
        receipt.update(status="verified", publisher_reference_sha256=file_pin,
                       checkpoint_sha256=proof["publisher_history"]["checkpoint_sha256"])
    except OutputCollision:
        return 2
    except FileExistsError:
        print("output already exists", file=sys.stderr)
        return 2
    except OSError:
        print("could not read the selected inputs or publish the history file", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return write_result(encoded(receipt))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
