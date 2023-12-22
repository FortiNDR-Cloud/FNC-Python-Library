import time
import unittest
from datetime import datetime, timezone, timedelta
from unittest import TestCase

from metastream import fetch_events_by_day, fetch_events, fetch_detections, fetch_detections_by_day
from metastream.errors import InputError, ServerError
from metastream.metastream import _validate_start_date, _prefix_to_datetime
from metastream.s3_client import Context


class Args:
    def __init__(self):
        self.name = 'unittest'
        self.env = 'uat'
        self.event_type = 'suricata'
        self.account_code = 'git'
        self.start_date = datetime.now(timezone.utc).replace(
            hour=0, minute=0, second=0, microsecond=0)
        self.limit = 100
        self.api_token = ''
        self.access_key = ""
        self.secret_key = ""
        self.version = ''
        self.tic = 0
        self.toc = 0
        self.total = 0
        self.context = Context()

    def events_by_day_args(self):
        return dict(name=self.name, env=self.env, event_type=self.event_type, day=self.start_date, access_key=self.access_key,
                    secret_key=self.secret_key, account_code=self.account_code, api_token=self.api_token,
                    limit=self.limit, context=self.context)

    def events_args(self):
        return dict(name=self.name, env=self.env, event_types=[self.event_type], start_date=self.start_date, access_key=self.access_key,
                    secret_key=self.secret_key, account_code=self.account_code, api_token=self.api_token,
                    limit=self.limit, context=self.context)

    def display_args(self):
        return dict(version=self.version, account_code=self.account_code, event_type=self.event_type,
                    start_date=self.start_date, total=self.total, env=self.env, limit=self.limit,
                    tic=self.tic, toc=self.toc, context=self.context)

    def detections_args(self):
        return dict(name=self.name, account_code=self.account_code, start_date=self.start_date, access_key=self.access_key,
                    secret_key=self.secret_key, limit=self.limit, env=self.env, context=self.context)

    def detections_by_day_args(self):
        return dict(name=self.name, account_code=self.account_code, day=self.start_date.date(), access_key=self.access_key,
                    secret_key=self.secret_key, limit=self.limit, env=self.env, context=self.context)


def _display_results(version, account_code, event_type, start_date, total, env, limit, tic, toc, context: Context):
    print()
    print('|| version || account_code || event_type || timestamp || total events || total time || API calls || file downloads ||')
    print(f'|{version}|{account_code}|{event_type}|{start_date}|{total}|{toc - tic:.5}s|{context.api_calls}|{context.file_downloads}|')
    print()
    print(version)
    print(f'environment: {env}')
    print(f'start_date: {start_date}')
    print(f'account_code: {account_code}')
    print(f'event_type: {event_type}')
    print(f'total events: {total}')
    print(f'Elapsed time: {toc - tic:.3}s')
    print(f'API calls: {context.api_calls}')
    print(f'File downloads: {context.file_downloads}')
    print()


class Test(TestCase):

    def test_fetch_events_by_day(self):
        args = Args()
        args.start_date = args.start_date - timedelta(days=2)
        args.tic = time.perf_counter()
        for events in fetch_events_by_day(**args.events_by_day_args()):
            args.total += len(events)
            print(f'num events: {len(events)}; total events: {args.total}')
            for event in events:
                event_date = datetime.strptime(
                    event.get('timestamp'), '%Y-%m-%dT%H:%M:%S.%f%z').date()
                arg_date = args.start_date.date()
                self.assertLessEqual(arg_date - event_date, timedelta(days=1))
        args.toc = time.perf_counter()
        args.version = "fetch_events_by_day()"
        _display_results(**args.display_args())
        if args.limit:
            self.assertEqual(args.limit, args.total)

    def test_fetch_events(self):
        args = Args()
        args.limit = 10
        args.version = "fetch_events()"
        args.tic = time.perf_counter()
        for events in fetch_events(**args.events_args()):
            args.total += len(events)
            print(f'num events: {len(events)}; total events: {args.total}')
            for event in events:
                event_dt = datetime.strptime(
                    event.get('timestamp'), '%Y-%m-%dT%H:%M:%S.%f%z')
                self.assertTrue(
                    timedelta(days=-1) <= (args.start_date - event_dt) <= timedelta(days=1))
        args.toc = time.perf_counter()
        _display_results(**args.display_args())
        if args.limit:
            self.assertEqual(args.limit, args.total)

    def test_fetch_detections(self):
        args = Args()
        args.env = "uat"
        args.limit = 0
        args.version = "fetch_detections()"
        args.tic = time.perf_counter()
        for events in fetch_detections(**args.detections_args()):
            args.total += len(events)
            print(f'num events: {len(events)}; total events: {args.total}')
            for event in events:
                event_dt = datetime.strptime(
                    event.get('timestamp'), '%Y-%m-%dT%H:%M:%S.%f%z')
                self.assertTrue(
                    timedelta(days=-1) <= (args.start_date - event_dt) <= timedelta(days=1))
        args.toc = time.perf_counter()
        _display_results(**args.display_args())
        if args.limit:
            self.assertEqual(args.limit, args.total)

    def test_fetch_detections_by_day(self):
        args = Args()
        args.env = "uat"
        args.start_date = args.start_date - timedelta(days=2)
        args.tic = time.perf_counter()
        for events in fetch_detections_by_day(**args.detections_by_day_args()):
            args.total += len(events)
            print(f'num events: {len(events)}; total events: {args.total}')
            for event in events:
                event_date = datetime.strptime(
                    event.get('timestamp'), '%Y-%m-%dT%H:%M:%S.%f%z').date()
                arg_date = args.start_date.date()
                self.assertLessEqual(arg_date - event_date, timedelta(days=1))
        args.toc = time.perf_counter()
        args.version = "fetch_events_by_day()"
        _display_results(**args.display_args())
        if args.limit:
            self.assertEqual(args.limit, args.total)

    @unittest.skip("this test is designed to run forever")
    def test_continuous_fetch_events(self):
        args = Args()
        args.limit = 0
        args.account_code = 'YeqUvMQNgEa'
        args.env = 'uat'
        args.start_date = datetime.now(tz=timezone.utc) - timedelta(minutes=2)
        args.version = "continuous fetch events"
        duplicates = set()
        while True:
            print(f'start_date: {args.start_date}')
            for events in fetch_events(**args.events_args()):
                args.total += len(events)
                print(f'num events: {len(events)}; total events: {args.total}')
                for event in events:
                    self.assertFalse(event.get('uuid') in duplicates)
                    duplicates.add(event.get('uuid'))
            args.start_date = args.context.checkpoint
            time.sleep(10)

    def test__validate_start_date(self):
        now = datetime.now(timezone.utc)
        start_of_day = now.replace(hour=0, minute=0, second=0, microsecond=0)
        day_ago = now - timedelta(hours=24)
        gt_day_ago = day_ago - timedelta(seconds=1)
        future = now + timedelta(seconds=1)

        self.assertIsNone(_validate_start_date(start_of_day, now))
        self.assertIsNone(_validate_start_date(day_ago, now))
        self.assertIsNone(_validate_start_date(now, now))

        with self.assertRaises(InputError):
            _validate_start_date(future, now)
        with self.assertRaises(InputError):
            _validate_start_date(gt_day_ago, now)

    def test__prefix_to_datetime(self):
        self.assertIsInstance(_prefix_to_datetime(
            "a/b/date_partition=20221212/"), datetime)
        self.assertIsInstance(_prefix_to_datetime("20221212"), datetime)
        self.assertIsInstance(_prefix_to_datetime("20221212//"), datetime)
        self.assertIsInstance(_prefix_to_datetime("////20221212/"), datetime)
        with self.assertRaises(ServerError) as e:
            _prefix_to_datetime("/hello/")
        self.assertEqual(e.exception.code, 0)
        self.assertTrue("unknown format" in e.exception.message)
