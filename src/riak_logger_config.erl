%% -*- mode: erlang; erlang-indent-level: 4; indent-tabs-mode: nil -*-
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

-module(riak_logger_config).

-export([handler_config/2]).

-include("riak_logger_config.hrl").

-type additional_handlers() ::
    crash | error | report | backend | background | json.

-spec handler_config(
    config_map(), config_fetch_fun()) ->
        {ok, list(standard_handler())} | {error, term()}.
handler_config(Conf, ConfFetchFun) ->
    case parse_inputs(ConfFetchFun, Conf) of
        {error, Term} ->
            {error, Term};
        {
            ok, 
            {
                DefaultFormatTerm,
                DefaultFilter,
                NonStandardFilters,
                MaxNumBytes,
                MaxNumFiles
            }
        } ->
            AdditionalHandlers =
                conf_getatomlist(
                    ?ADDITIONAL_HANDLERS_CFGKEY,
                    ConfFetchFun,
                    Conf
                ),
            DomainFilters =
                lists:map(
                    fun(F) ->
                        case F of
                            backend ->
                                {
                                    backend_filter,
                                    {
                                        fun logger_filters:domain/2,
                                        {stop, sub, [backend]}
                                    }
                                };
                            background ->
                                {
                                    background_filter,
                                    {
                                    fun logger_filters:domain/2,
                                    {stop, sub, [background]}
                                    }
                                }
                        end
                    end,
                    NonStandardFilters
                ),
            DefaultHandler =
                console_handler(
                    conf_getlist(?FILE_CONSOLE_CFGKEY, ConfFetchFun, Conf),
                    MaxNumBytes,
                    MaxNumFiles,
                    DefaultFormatTerm,
                    DomainFilters ++ DefaultFilter
                ),
            OtherHandlers =
                lists:map(
                    fun(H)
                        when 
                            H == crash; H == error; H == report;
                            H == background; H == backend;
                            H == json ->
                        get_handler(
                            H,
                            ConfFetchFun,
                            Conf,
                            MaxNumBytes,
                            MaxNumFiles,
                            DefaultFormatTerm
                        )
                    end,
                AdditionalHandlers
                ),
            {ok, [DefaultHandler] ++ OtherHandlers}
    end.

-spec conf_getint(string(), config_fetch_fun(), config_map()) -> integer().
conf_getint(Key, ConfFetchFun, Conf) ->
    case ConfFetchFun(Key, Conf) of
        I when erlang:is_integer(I) ->
            I
    end.

-spec conf_getlist(string(), config_fetch_fun(), config_map()) -> list().
conf_getlist(Key, ConfFetchFun, Conf) ->
    case ConfFetchFun(Key, Conf) of
        L when erlang:is_list(L) ->
            L
    end.

-spec conf_getatomlist(
    string(), config_fetch_fun(), config_map()) -> list(atom()).
conf_getatomlist(Key, ConfFetchFun, Conf) ->
    case ConfFetchFun(Key, Conf) of
        AL when erlang:is_list(AL) ->
            AL
    end.

-spec parse_inputs(config_fetch_fun(), config_map()) ->
    {
        ok,
        {
            list(term()), 
            list(tuple()),
            list(atom()),
            pos_integer(),
            pos_integer()
        }
    } | {error, term()}.
parse_inputs(ConfFetchFun, Conf) ->
    ConfigFormat = conf_getlist(?DEFAULT_FORMAT_CFGKEY, ConfFetchFun, Conf),
    case parse_logformat(ConfigFormat) of
        {ok, DefaultFormatTerm} ->
            DefaultFilters =
                conf_getatomlist(?DEFAULT_FILTERS_CFGKEY, ConfFetchFun, Conf),
            NonStandardFilters = DefaultFilters -- ?STANDARD_FILTERS,
            StandardFilters = DefaultFilters -- NonStandardFilters,
            DefaultFilter =
                case lists:usort(StandardFilters) of
                    [crash] ->
                        [{default_filter, {fun riak_logger:filter_c/2, stop}}];
                    [crash, error] ->
                        [{default_filter, {fun riak_logger:filter_ce/2, stop}}];
                    [crash, error, progress] ->
                        [{default_filter, {fun riak_logger:filter_cep/2, stop}}];
                    [crash, error, progress, sasl] ->
                        [{default_filter, {fun riak_logger:filter_ceps/2, stop}}];
                    [crash, error, progress, report, sasl] ->
                        [{default_filter, {fun riak_logger:filter_ceprs/2, stop}}];
                    [crash, error, sasl] ->
                        [{default_filter, {fun riak_logger:filter_ces/2, stop}}];
                    [] ->
                        [];
                    UnsupportedCombination ->
                        format_error(
                            <<"Unsupported filter combination ~0p">>,
                            [UnsupportedCombination]
                        )
                end,
            case {
                    DefaultFilter,
                    conf_getint(?MAX_FILESIZE_CFGKEY, ConfFetchFun, Conf),
                    conf_getint(?MAX_FILECOUNT_CFGKEY, ConfFetchFun, Conf)
                } of
                {{error, Term}, _, _} ->
                    {error, Term};
                {Filter, MaxNumBytes, MaxNumFiles}
                        when
                            erlang:is_integer(MaxNumBytes), MaxNumBytes > 0,
                            erlang:is_integer(MaxNumFiles), MaxNumFiles > 0 ->
                    {
                        ok, 
                        {
                            DefaultFormatTerm,
                            Filter,
                            NonStandardFilters,
                            MaxNumBytes,
                            MaxNumFiles
                        }
                    };
                {_Filter, MaxNumBytes, MaxNumFiles} ->
                    format_error(
                        <<"Invalid file size ~0p or count ~0p">>,
                        [MaxNumBytes, MaxNumFiles]
                    )
            end;
        {error, UnexpectedResult} ->
            format_error(
                <<"Parsing error of format string ~0p">>,
                [UnexpectedResult]
            )
    end.

-spec get_handler(
    additional_handlers(),
    config_fetch_fun(),
    config_map(),
    pos_integer(),
    pos_integer(),
    list(term())
)
    -> standard_handler().
get_handler(crash, ConfFun, Conf, MaxNumBytes, MaxNumFiles, FormatTerm) ->
    crash_handler(
        conf_getlist(?FILE_CRASH_CFGKEY, ConfFun, Conf),
        MaxNumBytes,
        MaxNumFiles,
        FormatTerm
    );
get_handler(error, ConfFun, Conf, MaxNumBytes, MaxNumFiles, FormatTerm) ->
    error_handler(
        conf_getlist(?FILE_ERROR_CFGKEY, ConfFun, Conf),
        MaxNumBytes,
        MaxNumFiles,
        FormatTerm
    );
get_handler(report, ConfFun, Conf, MaxNumBytes, MaxNumFiles, FormatTerm) ->
    report_handler(
        conf_getlist(?FILE_REPORT_CFGKEY, ConfFun, Conf),
        MaxNumBytes,
        MaxNumFiles,
        FormatTerm
    );
get_handler(backend, ConfFun, Conf, MaxNumBytes, MaxNumFiles, FormatTerm) ->
    domain_handler(
        conf_getlist(?FILE_BACKEND_CFGKEY, ConfFun, Conf),
        MaxNumBytes,
        MaxNumFiles,
        FormatTerm,
        backend
    );
get_handler(background, ConfFun, Conf, MaxNumBytes, MaxNumFiles, FormatTerm) ->
    domain_handler(
        conf_getlist(?FILE_BACKGROUND_CFGKEY, ConfFun, Conf),
        MaxNumBytes,
        MaxNumFiles,
        FormatTerm,
        background
    );
get_handler(json, ConfFun, Conf, MaxNumBytes, MaxNumFiles, _FormatTerm) ->
    json_handler(
        conf_getlist(?FILE_JSON_CFGKEY, ConfFun, Conf),
        MaxNumBytes,
        MaxNumFiles
    ).

-spec standard_config(
    string(), pos_integer(), pos_integer()) -> #{atom() => any()}.
standard_config(File, MaxNumBytes, MaxNumFiles) ->
    #{
        file => File,
        file_check => 100,
        max_no_bytes => MaxNumBytes,
        max_no_files => MaxNumFiles
    }.

-spec standard_formatter(boolean(), list(term())) -> #{atom() => any()}.
standard_formatter(SingleLine, FormatTerm) ->
    #{
        legacy_header => false,
        single_line => SingleLine,
        time_designator => $\s,
        template => FormatTerm
    }.

-spec format_error(binary(), list()) -> {error, string()}.
format_error(Text, Subs) ->
    {
        error,
        lists:flatten(io_lib:format(Text, Subs))
    }.

console_handler(File, MaxNumBytes, MaxNumFiles, FormatTerm, Filters) ->
    {
        handler,
        default,
        logger_std_h,
        #{
            level => all,
            config =>
                standard_config(File, MaxNumBytes, MaxNumFiles),
            filter_default => log,
            filters => Filters,
            formatter =>
                {
                    logger_formatter,
                    standard_formatter(true, FormatTerm)
                }
        }
    }.

error_handler(File, MaxNumBytes, MaxNumFiles, FormatTerm) ->
    %% Records all events at 'error' level or higher
    {
        handler,
        error_log,
        logger_std_h,
        #{
            level => error,
            config =>
                standard_config(File, MaxNumBytes, MaxNumFiles),
            filter_default => log,
            filters => [],
            formatter =>
                {
                    logger_formatter,
                    standard_formatter(true, FormatTerm)
                }
        }
    }.

crash_handler(File, MaxNumBytes, MaxNumFiles, FormatTerm) ->
    %% Records process crashes
    {
        handler,
        crash_log,
        logger_std_h,
        #{
            level => all,
            config =>
                standard_config(File, MaxNumBytes, MaxNumFiles),
            filter_default => stop,
            filters => 
                [
                    {crash_filter, {fun riak_logger:filter_ce/2, log}}
                ],
        formatter =>
            {
                logger_formatter,
                standard_formatter(false, FormatTerm)
            }
        }
    }.

report_handler(File, MaxNumBytes, MaxNumFiles, FormatTerm) ->
    %% Records progress and SASL reports
    {
        handler,
        report_log,
        logger_std_h,
        #{
            level => info,
            config =>
                standard_config(File, MaxNumBytes, MaxNumFiles),
            filter_default => stop,
            filters =>
                [
                    {
                        report_filter,
                        {fun riak_logger:filter_ps/2, log}
                    }
                ],
            formatter =>
                {
                    logger_formatter,
                    standard_formatter(false, FormatTerm)
                }
        }
    }.

domain_handler(File, MaxNumBytes, MaxNumFiles, FormatTerm, Domain) ->
    {
        handler,
        Domain,
        logger_std_h,
        #{
            level => all,
            config =>
                standard_config(File, MaxNumBytes, MaxNumFiles),
            filter_default => stop,
            filters => 
                [
                    {
                        domain_filter,
                        {fun logger_filters:domain/2, {log, sub, [Domain]}}
                    }
                ],
            formatter =>
                {
                    logger_formatter,
                    standard_formatter(true, FormatTerm)
                }
        }
    }.

json_handler(File, MaxNumBytes, MaxNumFiles) ->
    {
        handler,
        json_log,
        logger_std_h,
        #{
            level => all,
            config =>
                #{
                    compress_on_rotate => false,
                    file => File,
                    file_check => 100,
                    max_no_bytes => MaxNumBytes,
                    max_no_files => MaxNumFiles
                },
            filter_default => log,
            filters => [],
            formatter => 
                {
                    riak_log_json_formatter, #{}
                %% Defaults should be suitable for most use cases.
                }
        }
    }.


%% ===================================================================
%% Config Functions - to be used in riak_logger_config-* modules
%% ===================================================================

-spec parse_logformat(list()) -> {ok, list(term())}|{error, term()}.
parse_logformat(LogFormatStr) ->
    {ok, LogTokens, _} = erl_scan:string(LogFormatStr),
    case erl_parse:parse_term(LogTokens) of
        {ok, LogFormatTerm} when erlang:is_list(LogFormatTerm) ->
            {ok, LogFormatTerm};
        UnexpectedResult ->
            {error, UnexpectedResult}
    end.

%% ===================================================================
%% Unit tests
%% ===================================================================

-ifdef(TEST).

-include_lib("eunit/include/eunit.hrl").

standard_template() ->
    [time," [",level,"] ",pid,"@",mfa,":",line," ",msg,"\n"].

simple_config_test() ->
    ConfFetchFun = fun(Key, Map) -> maps:get(Key, Map) end,
    Conf =
        #{
            ?FILE_CONSOLE_CFGKEY => "/var/log/riak/console.log",
            ?MAX_FILECOUNT_CFGKEY => 10,
            ?MAX_FILESIZE_CFGKEY => 1024 * 1024,
            ?DEFAULT_FORMAT_CFGKEY => 
                "[time,\" [\",level,\"] \",pid,\"@\",mfa,"
                "\":\",line,\" \",msg,\"\\n\"].",
            ?DEFAULT_FILTERS_CFGKEY => [],
            ?ADDITIONAL_HANDLERS_CFGKEY => []
        },
    {ok, SimpleConfig} = handler_config(Conf, ConfFetchFun),

    ExpectedConfig =
        [
            {
                handler,
                default,
                logger_std_h,
                #{
                    config => 
                        #{
                            file => "/var/log/riak/console.log",
                            file_check => 100,
                            max_no_bytes => 1048576,
                            max_no_files => 10
                        },
                    level => all,
                    filters => [],
                    filter_default => log,
                    formatter => 
                        {
                            logger_formatter,
                            #{
                                legacy_header => false,
                                single_line => true,
                                template => standard_template(),
                                time_designator => $\s
                            }
                        }
                }
            }
        ],

    ?assertMatch(ExpectedConfig, SimpleConfig).

error_config_test() ->
    ConfFetchFun = fun(Key, Map) -> maps:get(Key, Map) end,
    Conf1 =
        #{
            ?FILE_CONSOLE_CFGKEY => "/var/log/riak/console.log",
            ?MAX_FILECOUNT_CFGKEY => 10,
            ?MAX_FILESIZE_CFGKEY => 0,
            ?DEFAULT_FORMAT_CFGKEY => 
                "[time,\" [\",level,\"] \",pid,\"@\",mfa,"
                "\":\",line,\" \",msg,\"\\n\"].",
            ?DEFAULT_FILTERS_CFGKEY => [],
            ?ADDITIONAL_HANDLERS_CFGKEY => []
        },
    ?assertMatch(
        {error, "Invalid file size 0 or count 10"},
        handler_config(Conf1, ConfFetchFun)
    ).

classic_config_test() ->
    ConfFetchFun = fun(Key, Map) -> maps:get(Key, Map) end,
    Conf1 =
        #{
            ?FILE_CONSOLE_CFGKEY => "/var/log/riak/console.log",
            ?FILE_CRASH_CFGKEY => "/var/log/riak/crash.log",
            ?FILE_ERROR_CFGKEY => "/var/log/riak/error.log",
            ?FILE_REPORT_CFGKEY => "/var/log/riak/report.log",
            ?MAX_FILECOUNT_CFGKEY => 10,
            ?MAX_FILESIZE_CFGKEY => 1024 * 1024,
            ?DEFAULT_FORMAT_CFGKEY => 
                "[time,\" [\",level,\"] \",pid,\"@\",mfa,"
                "\":\",line,\" \",msg,\"\\n\"].",
            ?DEFAULT_FILTERS_CFGKEY => [crash, error, sasl],
            ?ADDITIONAL_HANDLERS_CFGKEY => [crash, error, report]
        },
    {ok, ClassicConfig} = handler_config(Conf1, ConfFetchFun),

    ExpectedConfig = expected_classic_config(),
        
    ?assertMatch(ExpectedConfig, ClassicConfig).

expected_classic_config() ->
    [
        {
            handler,
            default,
            logger_std_h,
            #{
                config =>
                    #{
                        file => "/var/log/riak/console.log",
                        file_check => 100,
                        max_no_bytes => 1048576,
                        max_no_files => 10
                    },
                level => all,
                filters => [{default_filter,{fun riak_logger:filter_ces/2,stop}}],
                filter_default => log,
                formatter => 
                    {
                        logger_formatter,
                        #{
                            single_line => true,
                            legacy_header => false,
                            template => standard_template(),
                            time_designator => $\s
                        }
                    }
            }
        },
        {
            handler,
            crash_log,
            logger_std_h,
            #{
                config => 
                    #{
                        file => "/var/log/riak/crash.log",
                        file_check => 100,
                        max_no_bytes => 1048576,
                        max_no_files => 10
                    },
                level => all,
                filters => [{crash_filter,{fun riak_logger:filter_ce/2,log}}],
                filter_default => stop,
                formatter => 
                    {
                        logger_formatter,
                        #{
                            single_line => false,
                            legacy_header => false,
                            template => standard_template(),
                            time_designator => $\s
                        }
                    }
            }
        },
        {
            handler,
            error_log,
            logger_std_h,
            #{
                config =>
                    #{
                        file => "/var/log/riak/error.log",
                        file_check => 100,
                        max_no_bytes => 1048576,
                        max_no_files => 10
                    },
                level => error,
                filters => [],
                filter_default => log,
                formatter => 
                    {
                        logger_formatter,
                        #{
                            single_line => true,
                            legacy_header => false,
                            template => standard_template(),
                            time_designator => $\s
                        }
                    }
            }
        },
        {
            handler,
            report_log,
            logger_std_h,
            #{
                config => 
                    #{
                        file => "/var/log/riak/report.log",
                        file_check => 100,
                        max_no_bytes => 1048576,
                        max_no_files => 10
                    },
                    level => info,
                    filters => [{report_filter,{fun riak_logger:filter_ps/2,log}}],
                    filter_default => stop,
                    formatter => 
                        {
                            logger_formatter,
                            #{
                                single_line => false,
                                legacy_header => false,
                                template => standard_template(),
                                time_designator => $\s
                            }
                        }
            }
        }
    ].

json_config_test() ->
    ConfFetchFun = fun(Key, Map) -> maps:get(Key, Map) end,
    Conf1 =
        #{
            ?FILE_CONSOLE_CFGKEY => "/var/log/riak/console.log",
            ?FILE_CRASH_CFGKEY => "/var/log/riak/crash.log",
            ?FILE_ERROR_CFGKEY => "/var/log/riak/error.log",
            ?FILE_REPORT_CFGKEY => "/var/log/riak/report.log",
            ?FILE_JSON_CFGKEY => "{{platform_log_dir}}/json/riak-log.json",
            ?MAX_FILECOUNT_CFGKEY => 10,
            ?MAX_FILESIZE_CFGKEY => 1024 * 1024,
            ?DEFAULT_FORMAT_CFGKEY => 
                "[time,\" [\",level,\"] \",pid,\"@\",mfa,"
                "\":\",line,\" \",msg,\"\\n\"].",
            ?DEFAULT_FILTERS_CFGKEY => [crash, error, sasl],
            ?ADDITIONAL_HANDLERS_CFGKEY => [crash, error, report, json]
        },
    {ok, JsonConfig} = handler_config(Conf1, ConfFetchFun),

    ExpectedJsonHandler =
        {
            handler,
            json_log,
            logger_std_h, 
            #{
                level => all,
                config => 
                    #{
                        compress_on_rotate => false,
                        file => "{{platform_log_dir}}/json/riak-log.json",
                        file_check => 100,
                        max_no_bytes => 1048576,
                        max_no_files => 10
                    },
                filter_default => log,
                filters => [],
                formatter => {riak_log_json_formatter, #{}}
            }
        },
    
    ExpectedConfig = expected_classic_config() ++ [ExpectedJsonHandler],

    ?assertMatch(ExpectedConfig, JsonConfig).

domain_config_test() ->
    ConfFetchFun = fun(Key, Map) -> maps:get(Key, Map) end,
    Conf1 =
        #{
            ?FILE_CONSOLE_CFGKEY => "/var/log/riak/console.log",
            ?FILE_CRASH_CFGKEY => "/var/log/riak/crash.log",
            ?FILE_ERROR_CFGKEY => "/var/log/riak/error.log",
            ?FILE_REPORT_CFGKEY => "/var/log/riak/report.log",
            ?FILE_BACKEND_CFGKEY => "/var/log/riak/backend.log",
            ?FILE_BACKGROUND_CFGKEY => "/var/log/riak/async.log",
            ?MAX_FILECOUNT_CFGKEY => 10,
            ?MAX_FILESIZE_CFGKEY => 1024 * 1024,
            ?DEFAULT_FORMAT_CFGKEY => 
                "[time,\" [\",level,\"] \",pid,\"@\",mfa,"
                "\":\",line,\" \",msg,\"\\n\"].",
            ?DEFAULT_FILTERS_CFGKEY =>
                [crash, error, sasl, backend, background],
            ?ADDITIONAL_HANDLERS_CFGKEY =>
                [crash, error, report, backend, background]
        },
    {ok, DomainConfig} = handler_config(Conf1, ConfFetchFun),

    ClassicConfig = expected_classic_config(),
    [DefaultHandler|OtherHandlers] = ClassicConfig,
    {H, N, T, M} = DefaultHandler,
    ExpectedFilters =
        [
            {
                backend_filter,
                {fun logger_filters:domain/2, {stop, sub, [backend]}}
            },
            {
                background_filter,
                {fun logger_filters:domain/2, {stop, sub, [background]}}
            },
            {default_filter, {fun riak_logger:filter_ces/2, stop}}
        ],
    UpdM = maps:put(filters, ExpectedFilters, M),
    ExpectedDefaultHandler = {H, N, T, UpdM},
    ExpectedBackendHandler =
        {
            handler,
            backend,
            logger_std_h,
            #{
                level => all,
                config =>
                    standard_config("/var/log/riak/backend.log", 1048576, 10),
                filter_default => stop,
                filters => 
                    [
                        {
                            domain_filter,
                            {fun logger_filters:domain/2, {log, sub, [backend]}}
                        }
                    ],
                formatter =>
                    {
                        logger_formatter,
                        standard_formatter(true, standard_template())
                    }
            }
        },
    ExpectedAsyncHandler =
        {
            handler,
            background,
            logger_std_h,
            #{
                level => all,
                config =>
                    standard_config("/var/log/riak/async.log", 1048576, 10),
                filter_default => stop,
                filters => 
                    [
                        {
                            domain_filter, 
                            {fun logger_filters:domain/2, {log, sub, [background]}}
                        }
                    ],
                formatter =>
                    {
                        logger_formatter,
                        standard_formatter(true, standard_template())
                    }
            }
        },

    ExpectedHandlers =
        [ExpectedDefaultHandler|OtherHandlers] ++ 
        [ExpectedBackendHandler, ExpectedAsyncHandler],

    ?assertMatch(ExpectedHandlers, DomainConfig).

-endif.