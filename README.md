# Riak Kernel Logger Support
This repository contains configuration and operational support elements for logging with the
[OTP Kernel Logger](https://www.erlang.org/doc/apps/kernel/logger_chapter).

## [Configuration](https://www.erlang.org/doc/apps/kernel/logger_chapter#configuration)
Sample configuration using this application's features can be found in the
[`logger.config`](priv/logger.config) file.

Complete documentation of configuration options is available in the
[EDoc Documentation](doc/index.html).

## [Filters](https://www.erlang.org/doc/apps/kernel/logger_chapter#filters)
Logger filters are defined in the [`riak_logger`](src/riak_logger.erl) module.

## [Formatters](https://www.erlang.org/doc/apps/kernel/logger_chapter#formatters)

### JSON Formatter
A JSON log formatter is defined in the
[`riak_log_json_formatter`](src/riak_log_json_formatter.erl) module

The JSON formatter generates a one-line JSON object per log event.

Using the default configuration, events generated with the logging
[macros](https://www.erlang.org/doc/apps/kernel/logger#module-macros)
will generally output the following JSON fields:

```json
{
   "file" : "<application>/src/<module>.erl",
   "gl" : "<originating Erlang group leader pid>",
   "level" : "INFO",
   "line" : <integer line number in file>,
   "message" : "<formatted log message>",
   "mfa" : "<module>:<function>/<arity>",
   "ospid" : <integer OS process ID of the ERTS VM>,
   "proc" : "<originating Erlang process pid>",
   "timestamp" : "2025-01-27T17:47:11.554Z"
}
```

The formatter is highly configurable (see the application documentation),
but the default configuration is likely suitable for most use cases.
As such, it can generally be configured with a standard log file writer
as follows in `advanced.config`:

```erlang
%% /etc/riak/advanced.config
[
    {kernel, [
        {logger, [
            %% Records ALL events to JSON log
            {handler, json_log, logger_std_h, #{
                level => all,
                config => #{
                    compress_on_rotate => false,
                    file => "{{platform_log_dir}}/json/riak-log.json",
                    file_check => 100,
                    max_no_bytes => 1048576,
                    max_no_files => 10
                },
                filter_default => log,
                filters => [],
                formatter => {riak_log_json_formatter, #{
                    %% Defaults should be suitable for most use cases.
                }}
            }}
        ]}
    ]}
]
```

## Bugs
What??? No way ...

Yeah, you should probably file an issue.
