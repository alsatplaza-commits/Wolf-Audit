# P2.1 Windows read-only process sensor

This sensor is separate from the default scan. `inspect_process` does nothing unless `enabled` is the boolean `True`. On any host other than Windows the opt-in result is `NOT_EXECUTED` with reason `windows_sensor_unsupported_platform`. That result is not `PASS`, `REVIEWED`, or `APPROVED`.

The Windows implementation requests only `PROCESS_QUERY_LIMITED_INFORMATION` (`0x1000`). It records whether the process is running or has exited. Access denied and an unknown process stay `NOT_EXECUTED`. A failed exit query after the handle was opened is `INCOMPLETE` with reason `process_exit_race`.

The result object does not contain memory bytes, a dump, a command line, an environment, or an image path. The numeric exit code is not stored. The default repository scan still calls `runtime_inspection()`, which remains `NOT_EXECUTED`, and native source files remain `INCOMPLETE`.

Live coverage is the test process started by `tests/test_p21_windows_sensor.py` on a Windows runner. Ubuntu runs the same tests and cannot produce a Windows runtime pass. Independent human approval remains HOLD.
