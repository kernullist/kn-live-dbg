"""Provision one native image approval from a locally retained, signed publisher policy."""
import argparse
import os
import sys

from image_approval_policy import (Denied, IMAGE_LIMIT, authority_parameters, filetime, parse_manifest, parse_policy, record_projection,
                                   record_windows, select_approval)
from owned_module_benchmark import encoded, publish_new
from retained_corpus import OutputCollision
from saved_etl_comparison import local_path, outputs_safe, write_result


PATH_OPTIONS = ("--publisher-reference", "--policy", "--manifest", "--reference", "--catalog", "--out")


def provision(args, receipt, publisher):
    parameters = authority_parameters(args, publisher)
    destination = local_path(args.out)
    if os.path.lexists(destination):
        raise FileExistsError
    projected, signature_policy = select_approval(args, receipt, publisher, parameters)
    if signature_policy is not None:
        from windows_pe_trust import verify_reference
        signature = verify_reference(args.reference, projected["approvals"][0]["image_sha256"],
                                     IMAGE_LIMIT, args.catalog, signature_policy)
        record_windows(receipt, signature, projected)
    policy_data = encoded(projected)
    pin = publish_new(destination, lambda stream: stream.write(policy_data))
    record_projection(receipt, projected, pin)


def selected_paths(argv):
    for index, arg in enumerate(argv):
        flag, equals, value = arg.partition("=")
        if flag in PATH_OPTIONS and (equals or index + 1 < len(argv)):
            yield os.fspath(local_path(value if equals else argv[index + 1]))


def main(argv):
    try:
        if not outputs_safe(selected_paths(argv)):
            return 2
    except (ValueError, OSError):
        return 2
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for flag, help_text in (
            ("--publisher-reference", "retained TUF release metadata, root updates and delegated roles"),
            ("--trusted-root-sha256", "independently provisioned SHA-256 of the publisher's initial root metadata"),
            ("--verification-time", "UTC instant in YYYYMMDDTHHMMSSZ form"),
            ("--policy-target", "exact target path authorized by the TUF publisher"),
            ("--policy", "publisher's exact native image approval policy file"),
            ("--manifest", "exact native image change manifest"),
            ("--reference", "complete retained PE reference bytes"),
            ("--out", "new filename for the selected native policy")):
        parser.add_argument(flag, required=True, help=help_text)
    parser.add_argument("--minimum-root-version", help="lowest terminal version accepted from this publisher's retained root history")
    parser.add_argument("--previous-checkpoint-sha256", help="independently retained checkpoint of the previous publisher observation")
    parser.add_argument("--catalog", help="exact retained Windows catalog required by the signed catalog row")
    parser.add_argument("--require-windows-publisher", action="store_true",
                        help="require a signed v2 policy and a matching Windows PE publisher")
    args = parser.parse_args(argv)
    receipt = dict(schema="kn.image_approval_provision.v1", status="rejected", native_policy_sha256=None)
    try:
        import publisher_truth
        provision(args, receipt, publisher_truth)
    except Denied as exc:
        receipt["reason"] = str(exc)
        return write_result(encoded(receipt)) or 1
    except OutputCollision:
        return 2
    except FileExistsError:
        print("output already exists", file=sys.stderr)
        return 2
    except OSError:
        print("could not read inputs or publish the selected policy", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return write_result(encoded(receipt))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
