%% -------------------------------------------------------------------
%%
%% This file is provided to you under the Apache License,
%% Version 2.0 (the "License"); you may not use this file
%% except in compliance with the License.  You may obtain
%% a copy of the License at
%%
%%   http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing,
%% software distributed under the License is distributed on an
%% "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
%% KIND, either express or implied.  See the License for the
%% specific language governing permissions and limitations
%% under the License.
%%
%% -------------------------------------------------------------------
%% Portions informed by OTP module logger_filters,
%% Copyright Ericsson AB 2017-2018, though no code is duplicated.
%%
%% @doc Riak kernel logger configuration functions
%% 
%% These functions should be two arity, and pass some form of configuration
%% map, and a function for extracting the values of string-based keys from
%% that map (e.g. cuttlefish:conf_get/2).
%% 
%% The configuration can be ignored if preferred - and a statically defined
%% logging config be returned

-module(riak_logger_config).

-export([o34std_generator/2, o32std_generator/2]).

-type config_map() :: any().
-type config_fetch_fun() :: fun((string(), config_map()) -> any()).
-type standard_handler() ::
    {handler, atom(), logger_std_h, map()}.


-define(CSPEC(F),
    -spec F(config_map(), config_fetch_fun()) -> list(standard_handler())
).

%% ===================================================================
%% Riak Cuttlefish configuration parser
%% ===================================================================

?CSPEC(o32std_generator).
o32std_generator(Conf, ConfFetchFun) ->
    LogFile = ConfFetchFun("logger.file", Conf),
    MaxNumBytes = ConfFetchFun("logger.max_file_size", Conf),
    MaxNumFiles = ConfFetchFun("logger.max_files", Conf),
    DefaultFormatStr = ConfFetchFun("logger.format", Conf),
    {ok, DefaultFormatTerm} = parse_logformat(DefaultFormatStr),
    ConfigMap0 =
        #{
            config =>
                #{
                    file => LogFile,
                    max_no_bytes => MaxNumBytes,
                    max_no_files => MaxNumFiles
                },
            formatter =>
                {logger_formatter, #{template => DefaultFormatTerm}}
        },

    [{handler, default, logger_std_h, ConfigMap0}].

?CSPEC(o34std_generator).
o34std_generator(Conf, ConfFetchFun) ->
    ConsoleFile = ConfFetchFun("logger.file", Conf),
    ErrorFile = ConfFetchFun("error.file", Conf),
    CrashFile = ConfFetchFun("crash.file", Conf),
    ReportFile = ConfFetchFun("report.file", Conf),
    BackendFile = ConfFetchFun("backend.file", Conf),
    TictacaaeFile = ConfFetchFun("tictacaae.file", Conf),
    MetricFile = ConfFetchFun("metric.file", Conf),
    DefaultFormatStr = ConfFetchFun("logger.format", Conf),
    {ok, StdTemplate} = parse_logformat(DefaultFormatStr),
    LeveledTemplate =
        [time, " [", level, "] ", msg, "\n"],
    
    CheckPolicyFun =
        fun(PolicyConfName, PolicyType) ->
            case ConfFetchFun(PolicyConfName, Conf) of
                BP when BP =/= local ->
                    [PolicyType];
                _ ->
                    []
            end
        end,

    P0 = CheckPolicyFun("backend.policy", backend),
    P1 = CheckPolicyFun("tictacaae.policy", tictacaae),
    P2 = CheckPolicyFun("metric.policy", metric),
    FilteredTypes = P0 ++ P1 ++ P2,

    DefaultCfgMap =
      #{
        file_check => 100,
        max_no_bytes => ConfFetchFun("logger.max_file_size", Conf),
        max_no_files => ConfFetchFun("logger.max_files", Conf)
      },

    StandardHandler =
        {
            handler, default, logger_std_h,
            #{
                level => all,
                config => maps:put(file, ConsoleFile, DefaultCfgMap),
                filter_default => log,
                filters => 
                    case FilteredTypes of
                        [] ->
                            [
                                {
                                    default_filter,
                                    {fun riak_logger:filter_ces/2, stop}
                                }
                            ];
                        _ ->
                            [
                                {
                                    type_filter,
                                    {
                                        fun riak_logger:filter_t/2,
                                        {stop, FilteredTypes}
                                    }
                                },
                                {
                                    default_filter,
                                    {fun riak_logger:filter_ces/2, stop}}
                            ]
                    end,
                formatter =>
                    {logger_formatter,
                        #{
                            legacy_header => false,
                            single_line => true,
                            time_designator => $\s,
                            template => StdTemplate
                        }
                    }
            }
        },
    
    ErrorHandler =
        %% Records all events at 'error' level or higher
        {
            handler, error_log, logger_std_h,
            #{
                level => error,
                config => maps:put(file, ErrorFile, DefaultCfgMap),
                filter_default => log,
                filters => [],
                formatter =>
                    {logger_formatter,
                        #{
                            legacy_header => false,
                            single_line => true,
                            time_designator => $\s,
                            template => StdTemplate
                        }
                    }
                }
        },

    CrashHandler =
        %% Records process crashes
        {
            handler, crash_log, logger_std_h,
            #{
                level => all,
                config => maps:put(file, CrashFile, DefaultCfgMap),
                filter_default => stop,
                filters =>
                    [{crash_filter, {fun riak_logger:filter_ce/2, log}}],
                formatter =>
                    {
                        logger_formatter,
                        #{
                            legacy_header => false,
                            single_line => false,
                            time_designator => $\s,
                            template => StdTemplate
                        }
                    }
            }
        },

    ReportHandler =
        %% Records progress and SASL reports
        {
            handler, report_log, logger_std_h,
            #{
                level => info,
                config => maps:put(file, ReportFile, DefaultCfgMap),
                filter_default => stop,
                filters =>
                    [{report_filter, {fun riak_logger:filter_ps/2, log}}],
                formatter =>
                    {
                        logger_formatter,
                        #{
                            legacy_header => false,
                            single_line => false,
                            time_designator => $\s,
                            template =>  StdTemplate
                        }
                    }
            }
        },
    
    BackendHandler =
        case ConfFetchFun("backend.policy", Conf) of
            divert ->
                {
                    handler, backend_log, logger_std_h,
                    #{
                        level => all,
                        config => maps:put(file, BackendFile, DefaultCfgMap),
                        filter_default => stop,
                        filters =>
                            [
                                {
                                    type_filter,
                                    {
                                        fun riak_logger:filter_t/2,
                                        {log, [backend]}
                                    }
                                }
                            ],
                        formatter =>
                            {
                                logger_formatter,
                                #{
                                    legacy_header => false,
                                    single_line => true,
                                    time_designator => $\s,
                                    template => LeveledTemplate
                                }
                            }
                    }
                };
            _ ->
                none
        end,

    TictacaaeHandler =
        case ConfFetchFun("tictacaae.policy", Conf) of
            divert ->
                {
                    handler, tictacaae_log, logger_std_h,
                    #{
                        level => all,
                        config => maps:put(file, TictacaaeFile, DefaultCfgMap),
                        filter_default => stop,
                        filters =>
                            [
                                {
                                    type_filter,
                                    {
                                        fun riak_logger:filter_t/2,
                                        {log, [tictacaae]}
                                    }
                                }
                            ],
                        formatter =>
                            {
                                logger_formatter,
                                #{
                                    legacy_header => false,
                                    single_line => true,
                                    time_designator => $\s,
                                    template => LeveledTemplate
                                }
                            }
                        }
                };
            _ ->
                none
      end,
    
    MetricHandler =
        case ConfFetchFun("metric.policy", Conf) of
            divert ->
                {
                    handler, metric_log, logger_std_h,
                    #{
                        level => all,
                        config => maps:put(file, MetricFile, DefaultCfgMap),
                        filter_default => stop,
                        filters =>
                            [
                                {
                                    type_filter,
                                    {
                                        fun riak_logger:filter_t/2,
                                        {log, [metric]}
                                    }
                                }
                            ],
                        formatter =>
                            {
                                logger_formatter,
                                #{
                                    legacy_header => false,
                                    single_line => true,
                                    time_designator => $\s,
                                    template => StdTemplate
                                }
                            }
                    }
                };
            _ ->
                none
        end,
    lists:filter(
    fun(H) -> H =/= none end,
        [
            StandardHandler, ErrorHandler, CrashHandler, ReportHandler,
            BackendHandler, TictacaaeHandler, MetricHandler
        ]
    ).


%% ===================================================================
%% InternalFunctions
%% ===================================================================
%% 
-spec parse_logformat(string()) -> {ok, list(term())}|{error, term()}.
parse_logformat(LogFormatStr) ->
    {ok, LogTokens, _} = erl_scan:string(LogFormatStr),
    case erl_parse:parse_term(LogTokens) of
        {ok, LogFormatTerm} when erlang:is_list(LogFormatTerm) ->
            {ok, LogFormatTerm};
        UnexpectedResult ->
            {error, UnexpectedResult}
    end.


%% ===================================================================
%% Tests
%% ===================================================================

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

-define(STD_FORMAT, 
    "[time,\" "
    "[\",level,\"] \",pid,\"@\",mfa,\":\",line,\" \",msg,\"\\n\"]."
).

o32_handler_test() ->
    StdConfig =
        #{
            "logger.file" => "$(platform_log_dir)/console.log",
            "logger.max_file_size" => 1000000,
            "logger.max_files" => 10,
            "logger.format" => ?STD_FORMAT
        },
    HandlerList =
        o32std_generator(StdConfig, fun maps:get/2),
    true = erlang:is_list(HandlerList),
    true = 1 == erlang:length(HandlerList),
    
    ExpectedConfig =
        {
            handler,
            default,
            logger_std_h,
            #{
                config =>
                    #{
                        file => "$(platform_log_dir)/console.log",
                        max_no_bytes => 1000000,
                        max_no_files => 10
                    },
                formatter =>
                    {
                        logger_formatter,
                        #{
                            template =>
                                [
                                    time,
                                    " [",level,"] ",
                                    pid,
                                    "@",
                                    mfa,
                                    ":",
                                    line,
                                    " ",
                                    msg,
                                    "\n"
                                ]
                        }
                    }
                }
        },
    [Handler] = HandlerList,
    ?assertMatch(ExpectedConfig, Handler).

wday_handler_test() ->
    StdConfig =
        #{
            "logger.file" => "$(platform_log_dir)/console.log",
            "error.file" => "$(platform_log_dir)/error.log",
            "crash.file" => "$(platform_log_dir)/crash.log",
            "report.file" => "$(platform_log_dir)/report.log",
            "backend.file" => "$(platform_log_dir)/backend.log",
            "tictacaae.file" => "$(platform_log_dir)/tictacaae.log",
            "metric.file" => "$(platform_log_dir)/metric.log",
            "logger.max_file_size" => 1000000,
            "logger.max_files" => 10,
            "logger.format" => ?STD_FORMAT,
            "backend.policy" => local,
            "tictacaae.policy" => local,
            "metric.policy" => local
        },
    
    HandlerList =
        o34std_generator(StdConfig, fun maps:get/2),
    true = erlang:is_list(HandlerList),
    true = 4 == erlang:length(HandlerList),
    
    {handler,crash_log,logger_std_h, CLC} =
        lists:keyfind(crash_log, 2, HandlerList),
    ?assertMatch(stop, maps:get(filter_default, CLC)),
    [{crash_filter, {_FilterFunC, Action}}] = maps:get(filters, CLC),
    ?assertMatch(log, Action).

nhs_handler_test() ->
    StdConfig =
        #{
            "logger.file" => "$(platform_log_dir)/console.log",
            "error.file" => "$(platform_log_dir)/error.log",
            "crash.file" => "$(platform_log_dir)/crash.log",
            "report.file" => "$(platform_log_dir)/report.log",
            "backend.file" => "$(platform_log_dir)/backend.log",
            "tictacaae.file" => "$(platform_log_dir)/tictacaae.log",
            "metric.file" => "$(platform_log_dir)/metric.log",
            "logger.max_file_size" => 1000000,
            "logger.max_files" => 10,
            "logger.format" => ?STD_FORMAT,
            "backend.policy" => divert,
            "tictacaae.policy" => divert,
            "metric.policy" => divert
        },
    
    HandlerList =
        o34std_generator(StdConfig, fun maps:get/2),
    true = erlang:is_list(HandlerList),
    true = 7 == erlang:length(HandlerList),

    {handler,backend_log,logger_std_h, BLC} =
        lists:keyfind(backend_log, 2, HandlerList),
    ?assertMatch(stop, maps:get(filter_default, BLC)),
    [{type_filter, {FilterFunT, {log, BackendMatchList}}}] =
        maps:get(filters, BLC),
    ?assertMatch([backend], BackendMatchList),

    {handler,tictacaae_log,logger_std_h, TLC} =
        lists:keyfind(tictacaae_log, 2, HandlerList),
    ?assertMatch(stop, maps:get(filter_default, TLC)),
    [{type_filter, {FilterFunT, {log, TictacMatchList}}}] =
        maps:get(filters, TLC),
    ?assertMatch([tictacaae], TictacMatchList)
    .
    

-endif.