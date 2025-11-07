import argparse
import concurrent.futures as cf
import sys
import time
from datetime import datetime, timedelta, timezone

import boto3
from botocore.exceptions import ClientError

def parse_args():
    p = argparse.ArgumentParser(description="Delete old CloudWatch log streams.")
    p.add_argument("--region", help="AWS region (e.g., eu-west-2). Defaults to env/CLI config.")
    p.add_argument("--profile", help="AWS profile name to use.")
    p.add_argument("--older-than-days", type=int, default=365,
                   help="Delete streams older than this many days (default: 365).")
    p.add_argument("--log-group-prefix", help="Only scan log groups that start with this prefix.")
    p.add_argument("--include", help="Substring filter to include log groups (applied after prefix).")
    p.add_argument("--exclude", help="Substring filter to exclude log groups.")
    p.add_argument("--max-workers", type=int, default=8, help="Parallel workers for deletions.")
    p.add_argument("--dry-run", action="store_true", help="Do not delete; just print what would be deleted.")
    return p.parse_args()

def session_from_args(args):
    if args.profile:
        return boto3.Session(profile_name=args.profile, region_name=args.region)
    return boto3.Session(region_name=args.region)

def human(ts_ms):
    if ts_ms is None:
        return "None"
    return datetime.fromtimestamp(ts_ms/1000, tz=timezone.utc).isoformat()

def cutoff_epoch_ms(days):
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    return int(cutoff.timestamp() * 1000)

def should_consider_group(name, args):
    if args.log_group_prefix and not name.startswith(args.log_group_prefix):
        return False
    if args.include and args.include not in name:
        return False
    if args.exclude and args.exclude in name:
        return False
    return True

def candidate_age_ms(ls):
    """
    Determine the 'age' by the most recent meaningful activity:
    prefer lastEventTimestamp, then lastIngestionTime, else creationTime.
    If all missing, treat as very old.
    """
    last_event = ls.get("lastEventTimestamp")
    last_ingest = ls.get("lastIngestionTime")
    creation = ls.get("creationTime")
    latest = max([t for t in [last_event, last_ingest, creation] if t is not None], default=0)
    return latest

def list_log_groups(client, prefix=None):
    paginator = client.get_paginator("describe_log_groups")
    kwargs = {}
    if prefix:
        kwargs["logGroupNamePrefix"] = prefix
    for page in paginator.paginate(**kwargs):
        for lg in page.get("logGroups", []):
            yield lg["logGroupName"]

def list_log_streams(client, group):
    paginator = client.get_paginator("describe_log_streams")
    # OrderBy doesn't matter for full scan; choosing LastEventTime helps surface newest first
    for page in paginator.paginate(logGroupName=group, orderBy="LastEventTime", descending=True):
        for ls in page.get("logStreams", []):
            yield ls

def delete_stream(client, group, stream, dry_run=False, attempt=1):
    name = stream["logStreamName"]
    if dry_run:
        print(f"[DRY-RUN] Would delete: group='{group}' stream='{name}' "
              f"(lastEvent={human(stream.get('lastEventTimestamp'))}, "
              f"lastIngest={human(stream.get('lastIngestionTime'))}, "
              f"created={human(stream.get('creationTime'))})")
        return True

    try:
        client.delete_log_stream(logGroupName=group, logStreamName=name)
        print(f"Deleted: group='{group}' stream='{name}'")
        return True
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code")
        # Simple backoff for throttling
        if code in ("ThrottlingException", "Throttling") and attempt <= 5:
            time.sleep(2 ** attempt / 2)
            return delete_stream(client, group, stream, dry_run, attempt + 1)
        # Stream may already be gone due to race
        if code == "ResourceNotFoundException":
            print(f"Already gone: group='{group}' stream='{name}'")
            return True
        print(f"FAILED to delete: group='{group}' stream='{name}' error={code}", file=sys.stderr)
        return False

def main():
    args = parse_args()
    sess = session_from_args(args)
    logs = sess.client("logs")
    cutoff_ms = cutoff_epoch_ms(args.older_than_days)

    groups = [g for g in list_log_groups(logs, prefix=args.log_group_prefix) if should_consider_group(g, args)]
    if not groups:
        print("No log groups matched.")
        return

    to_delete = []  # (group, logStreamDict)
    for g in groups:
        for ls in list_log_streams(logs, g):
            latest_activity = candidate_age_ms(ls)
            if latest_activity == 0 or latest_activity < cutoff_ms:
                to_delete.append((g, ls))

    print(f"Matched {len(groups)} log group(s). Streams to delete: {len(to_delete)} "
          f"(older than {args.older_than_days} days; cutoff={datetime.fromtimestamp(cutoff_ms/1000, tz=timezone.utc).isoformat()})")

    # Delete in parallel
    if to_delete:
        with cf.ThreadPoolExecutor(max_workers=args.max_workers) as ex:
            futures = [ex.submit(delete_stream, logs, g, ls, args.dry_run) for g, ls in to_delete]
            # drain results
            _ = [f.result() for f in futures]

if __name__ == "__main__":
    main()
