import io
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timezone, tzinfo
from zoneinfo import ZoneInfo

import run
import status


class BuildTimezoneTest(unittest.TestCase):
    def test_known_name(self):
        self.assertEqual(ZoneInfo('Asia/Tokyo'), run.build_timezone('Asia/Tokyo'))

    def test_unknown_name(self):
        self.assertIsNone(run.build_timezone('Europe/Moskow'))

    def test_malformed_names_do_not_raise(self):
        # ZoneInfo raises ValueError (not ZoneInfoNotFoundError) for path-like keys
        for name in ('../../etc/passwd', '/etc/localtime', 'UTC/../UTC'):
            self.assertIsNone(run.build_timezone(name), name)


class ResolveTimezoneTest(unittest.TestCase):
    def test_missing_key_means_machine_timezone(self):
        self.assertIsNone(run.resolve_timezone({}))

    def test_empty_value_means_machine_timezone(self):
        self.assertIsNone(run.resolve_timezone({'timezone': '   '}))
        self.assertIsNone(run.resolve_timezone({'timezone': None}))

    def test_valid_name_is_resolved(self):
        self.assertEqual(ZoneInfo('Europe/Moscow'), run.resolve_timezone({'timezone': 'Europe/Moscow'}))

    def test_surrounding_whitespace_is_ignored(self):
        self.assertEqual(ZoneInfo('Europe/Moscow'), run.resolve_timezone({'timezone': ' Europe/Moscow '}))

    def test_unknown_name_exits_loudly(self):
        stdout = io.StringIO()

        with redirect_stdout(stdout):
            with self.assertRaises(SystemExit) as ctx:
                run.resolve_timezone({'timezone': 'Europe/Moskow'})

        self.assertNotEqual(0, ctx.exception.code)
        self.assertIn("Invalid timezone: 'Europe/Moskow'", stdout.getvalue())

    def test_non_string_value_exits_loudly(self):
        with redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit):
                run.resolve_timezone({'timezone': 123})


class HumanTimeTest(unittest.TestCase):
    """status.py renders stored UTC epochs; the timezone only affects the rendering."""

    MOMENT = 1700000000  # 2023-11-14 22:13:20 UTC

    def test_renders_in_the_given_timezone_with_zone_name(self):
        self.assertEqual('2023-11-15 07:13:20 JST', status.human_time(self.MOMENT, ZoneInfo('Asia/Tokyo')))

    def test_same_instant_differs_only_by_offset(self):
        self.assertEqual('2023-11-14 22:13:20 UTC', status.human_time(self.MOMENT, timezone.utc))

    def test_without_timezone_falls_back_to_the_machine_zone(self):
        expected = datetime.fromtimestamp(self.MOMENT).astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')

        self.assertEqual(expected, status.human_time(self.MOMENT))

    def test_placeholders_are_unchanged(self):
        self.assertEqual('never', status.human_time(None, ZoneInfo('Asia/Tokyo')))
        self.assertEqual('never', status.human_time(0))

    def test_out_of_range_timestamp_is_reported_as_invalid(self):
        self.assertIn('invalid', status.human_time(10 ** 20, ZoneInfo('Asia/Tokyo')))


class ShouldRunTimezoneTest(unittest.TestCase):
    """Europe/Moscow is UTC+3 year-round, so its hour never equals the UTC hour.

    Schedules match on the hour rather than the exact minute, so a minute rolling
    over between building the schedule and evaluating it cannot make these flaky.
    """

    @staticmethod
    def _hourly_schedule_for_now_in(tz: tzinfo) -> str:
        return f"* {datetime.now(tz=tz).hour} * * *"

    def test_schedule_matches_in_the_configured_timezone(self):
        moscow = ZoneInfo('Europe/Moscow')

        self.assertTrue(run.should_run(self._hourly_schedule_for_now_in(moscow), moscow))

    def test_same_schedule_does_not_match_in_another_timezone(self):
        moscow = ZoneInfo('Europe/Moscow')

        self.assertFalse(run.should_run(self._hourly_schedule_for_now_in(moscow), timezone.utc))

    def test_every_minute_schedule_matches_regardless_of_timezone(self):
        self.assertTrue(run.should_run('* * * * *', ZoneInfo('Europe/Moscow')))
        self.assertTrue(run.should_run('* * * * *', None))


class ShouldSendSummaryTimezoneTest(unittest.TestCase):
    @staticmethod
    def _schedule_for_now_in(tz_name: str) -> str:
        return f"* {datetime.now(tz=ZoneInfo(tz_name)).hour} * * *"

    def test_summary_schedule_follows_the_configured_timezone(self):
        config = {'timezone': 'Asia/Tokyo', 'summary_schedule': self._schedule_for_now_in('Asia/Tokyo')}

        self.assertTrue(run.should_send_summary(config))

    def test_summary_schedule_does_not_fire_on_another_timezones_hour(self):
        # Asia/Tokyo is UTC+9 and Europe/Moscow UTC+3, so their hours never coincide
        config = {'timezone': 'Europe/Moscow', 'summary_schedule': self._schedule_for_now_in('Asia/Tokyo')}

        self.assertFalse(run.should_send_summary(config))

    def test_missing_or_empty_schedule_is_ignored(self):
        self.assertFalse(run.should_send_summary({'timezone': 'Asia/Tokyo'}))
        self.assertFalse(run.should_send_summary({'summary_schedule': ''}))

    def test_invalid_cron_is_reported_without_raising(self):
        stdout = io.StringIO()

        with redirect_stdout(stdout):
            self.assertFalse(run.should_send_summary({'summary_schedule': '2 * * * '}))

        self.assertIn('Invalid summary_schedule', stdout.getvalue())


class CheckConfigTimezoneTest(unittest.TestCase):
    @staticmethod
    def _run_check_config(config: dict) -> str:
        config = {'sites': {}, 'commands': {}, **config}
        stdout = io.StringIO()

        with redirect_stdout(stdout):
            run.check_config(config)

        return stdout.getvalue()

    def test_missing_timezone_is_reported_as_a_warning(self):
        output = self._run_check_config({})

        self.assertIn('timezone: not found, the machine timezone is used', output)
        self.assertIn(f"\033[{run.Color.WARNING.value}m  timezone: not found", output)

    def test_valid_timezone_is_reported_as_success(self):
        output = self._run_check_config({'timezone': 'Europe/Moscow'})

        self.assertIn(f"\033[{run.Color.SUCCESS.value}m  timezone: Europe/Moscow", output)

    def test_unknown_timezone_is_reported_with_suggestions_and_a_hint(self):
        output = self._run_check_config({'timezone': 'Europe/Moskow'})

        self.assertIn(f"\033[{run.Color.ERROR.value}m  timezone: unknown timezone: 'Europe/Moskow'", output)
        self.assertIn('did you mean:', output)
        self.assertIn('Europe/Moscow', output)
        self.assertIn('full list:', output)


if __name__ == '__main__':
    unittest.main()
