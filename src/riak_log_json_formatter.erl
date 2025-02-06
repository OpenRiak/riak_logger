%% -*- mode: erlang; erlang-indent-level: 4; indent-tabs-mode: nil -*-
%% -------------------------------------------------------------------
%%
%% Copyright (c) 2024-2025 Workday, Inc.
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
%%
%% @doc A JSON formatter for the Kernel Logger.
%%
%% See the <a
%% href="https://www.erlang.org/doc/apps/kernel/logger_chapter#handlers"
%% >Handlers</a> and <a
%% href="https://www.erlang.org/doc/apps/kernel/logger_chapter.html#formatters"
%% >Formatters</a> sections of the Kernel User's Guide for more information.
%%
%% @end
-module(riak_log_json_formatter).

%% Because there are no logger_xxx behaviors, xref sees the logger callbacks
%% as unused exports, but we can mock behaviors from its perspective ...
%% Xref -behavior(logger_formatter):
-ignore_xref([check_config/1, format/2]).

%% Public API
-export([
    default_config/0,
    default_fields/0,
    default_field_map/0,
    default_level_map/0
]).

%% Public Types
-export_type([
    config/0,
    event_field/0,
    field_filter/0,
    field_map/0,
    level_map/0,
    level_val/0,
    line_delim/0,
    log_level/0,
    meta_field/0,
    meta_fields/0,
    mfa_format/0,
    output_field/0,
    output_fields/0,
    report_cb/0,
    time_delim/0,
    time_offset/0,
    time_unit/0
]).

%% logger formatter callbacks
-export([
    check_config/1,
    format/2
]).

-on_load(init_const/0).

-ifdef(TEST).
-include_lib("kernel/include/logger.hrl").
-include_lib("eunit/include/eunit.hrl").
-compile([
    export_all,
    nowarn_export_all,
    nowarn_missing_spec
]).
-else.
-compile([warn_missing_spec_all]).
-endif.

-if(?OTP_RELEASE >= 27).
-define(USE_OTP_JSON, true).
-endif.

-type config() :: #{
    chars_limit     =>  pos_integer(),
    depth           =>  pos_integer(),
    field_filter    =>  field_filter(),
    field_map       =>  field_map(),
    level_map       =>  level_map(),
    line_delim      =>  line_delim(),
    mfa_format      =>  mfa_format(),
    report_cb       =>  report_cb(),
    time_delim      =>  time_delim(),
    time_offset     =>  time_offset(),
    time_unit       =>  time_unit()
}.
%% The configuration term for `riak_log_json_formatter' is a <a
%% href="https://www.erlang.org/doc/apps/erts/erlang#t:map/0">`map()'</a>
%% with the following keys:<dl>
%% <dt>`chars_limit :: ' <a
%% href="https://www.erlang.org/doc/apps/erts/erlang#t:pos_integer/0"
%% >`pos_integer()'</a></dt>
%% <dd>The value of the option with the same name to be used when calling
%% <a href="https://www.erlang.org/doc/apps/stdlib/io_lib.html#format/3"
%% >`io_lib:format/3'</a> to format the `message'. This value limits the
%% total number of characters printed for each log event's `message' field
%% - the overall line containing the full JSON object may be considerably
%% longer, based on included metadata and report fields.<br/>
%% Note that this is a soft limit; no hard limit is available.<br/>
%% There is no default limit on message length.</dd>
%% <dt>`depth :: ' <a
%% href="https://www.erlang.org/doc/apps/erts/erlang#t:pos_integer/0"
%% >`pos_integer()'</a></dt>
%% <dd>The maximum depth of nested terms included in the `message' field.
%% `"~p"' and `"~w"' format controls are rewritten as `"~P"' and `"~W"',
%% respectively, using this value as the depth parameter. See <a
%% href="https://www.erlang.org/doc/apps/stdlib/io.html#fwrite/3"
%% >`io:fwrite/3'</a> for details.<br/>
%% There is no default limit on depth.</dd>
%% <dt>`field_filter :: ' {@link field_filter()}</dt>
%% <dd>Indicates what fields to include in JSON output.<br/>
%% The default behavior is to output all fields.<br/>
%% Note that this filtering is applied <i>before</i> any field name mapping
%% specified by the `field_map' configuration, if present, and applies
%% <i>only</i> to top-level fields; nested fields are not evaluated.</dd>
%% <dt>`field_map :: ' {@link field_map()}</dt>
%% <dd>A map of [alternate] names to be output for JSON fields, possibly
%% overriding the defaults returned by {@link default_fields/0. default_fields()}.<br/>
%% Any top-level field name can be overridden, not just the predefined ones,
%% but nested field names are not affected. For instance, if an event contains
%% field `foo', in either its metadata or a report map, it can be mapped to
%% `bar' in the output.<br/>
%% The map need not include every field, only those to be overridden.</dd>
%% <dt>`level_map :: ' {@link level_map()}</dt>
%% <dd>A map of [alternate] levels or values to be output for the JSON `level'
%% field, overriding the defaults returned by {@link default_level_map/0. default_level_map()}.<br/>
%% The map need not include every level, only those to be overridden.</dd>
%% <dt>`line_delim :: ' {@link line_delim()}</dt>
%% <dd>A byte or (possibly empty) list of bytes used to delimit output lines
%% (JSON records). Note that <i>ANY</i> byte or list of bytes can be
%% specified to satisfy the needs of the parser that will be reading the
%% output - be <b><i>very</i></b> careful venturing outside the norms of
%% `$\n', `$,', `""' (for a memory accumulator), or `",\n"'.<br/>
%% Defaults to `$\n'.</dd>
%% <dt>`mfa_format :: ' {@link mfa_format()}</dt>
%% <dd>The level of verbosity of MFA information included in JSON output.<br/>
%% The default is `compact'.</dd>
%% <dt>`report_cb :: ' <a
%% href="https://www.erlang.org/doc/apps/kernel/logger#t:report_cb/0"
%% >`logger:report_cb()'</a></dt>
%% <dd>Specification of this element is <i>NOT</i> recommended, as its behavior
%% is likely to change.<br/>
%% The default behavior is to output each field separately in the JSON.</dd>
%% <dt>`time_delim :: ' {@link time_delim()}</dt>
%% <dd>A printable Latin1 character used to delimit the date and time portions
%% of the <a href="https://datatracker.ietf.org/doc/html/rfc3339">RFC-3339</a>
%% timestamp.<br/>
%% Defaults to `$T'.</dd>
%% <dt>`time_offset :: ' {@link time_offset()}</dt>
%% <dd>The time offset to be used when formatting the timestamp.
%% Refer to the datatype for details.<br/>
%% Defaults to `"Z"'.</dd>
%% <dt>`time_unit :: ' {@link time_unit()}</dt>
%% <dd>The resolution of the seconds portion of the timestamp.<br/>
%% Defaults to `millisecond'.</dd>
%% </dl>
%% All keys are optional, but configuration <i>MUST</i> be specified as a map,
%% even if empty. Default values are used for any missing keys.

-type event_field() :: level | meta | msg.
%% Top-level fields present in all <a
%% href="https://www.erlang.org/doc/apps/kernel/logger#t:log_event/0"
%% >`logger:log_event()'</a> objects.
%% Only the `level' field makes its way to the output; the `meta' and `msg'
%% fields are transformed during processing.

-type field_filter() :: {include | exclude, output_fields()}.
%% Indicates what event, metadata, and report fields to include in, or
%% exclude from, JSON output.
%%
%% Accepted values are:<dl>
%% <dt>`{include, ' {@link output_fields()}`}'</dt>
%% <dd>An explicit list specifying the <i>ONLY</i> fields that will be
%% included in the output. All non-matching top-level fields will be
%% excluded.<br/>
%% An empty inclusion list will cause the configuration to be rejected as
%% invalid.<ul><li>
%% Note that use of the `include' filter can have unexpected consequences as
%% new log generation statements are added to the system that may contain
%% previously unused metadata or report tags that will be silently excluded.
%% </li></ul></dd>
%% <dt>`{exclude, ' {@link output_fields()}`}'</dt>
%% <dd>An explicit list specifying top-level fields that will be excluded
%% from the output. All non-matching fields will be included.<br/>
%% An empty exclusion list is effectively ignored.</dd>
%% </dl>

-type field_map() :: #{output_field() => output_field()}.
%% A (possibly sparse) map of alternate field names to be output to the JSON.
%% Name mapping is only applied to top-level fields; nested field names are
%% not evaluated for mapping.

-type level_map() :: #{log_level() => log_level() | level_val()}.
%% A (possibly sparse) map of alternate levels or values to be output for the
%% JSON `level' field. The keys of the map can only be established log levels;
%% the associated values can be either another level atom, which is resolved
%% recursively, or a binary string to be output to the JSON result.

-type level_val() :: unicode:unicode_binary().
%% The string to be included in JSON output representing a {@link log_level()}.
%% The value <i>MUST</i> be a non-empty <a
%% href="https://www.erlang.org/doc/apps/stdlib/unicode.html#t:unicode_binary/0"
%% >unicode binary string</a> that does not require any characters to be
%% escaped.

-type line_delim() :: byte() | list(byte()).
%% The byte or (possibly empty) list of bytes to be written between output
%% lines.

-type log_level() :: logger:level().
%% One of the predefined constant logging <a
%% href="https://www.erlang.org/doc/apps/kernel/logger.html#t:level/0"
%% >levels</a>.

-type meta_field() ::
    domain | file | gl | line | mfa | ospid | pid | time.
%% Predefined metadata field tags.
%%
%% Some of these are provided at the point at which the log event is generated,
%% others are derived by the formatter.<dl>
%% <dt>`domain'</dt><dd>The event's originating domain (functional area), which
%% must be explicitly specified as metadata when the event is generated.</dd>
%% <dt>`file'</dt><dd>The source file generating the log event,
%% provided by the LOG_xxx macros.<br/>
%% The file's path is shortened to the file name with two levels of
%% encompassing directories.</dd>
%% <dt>`gl'</dt><dd>The group leader of the process originating the event,
%% provided by the `logger' module.</dd>
%% <dt>`line'</dt><dd>The line at which the event is generated,
%% provided by the LOG_xxx macros.</dd>
%% <dt>`mfa'</dt><dd>The Module, Function, and Arity from which the event is
%% generated, provided by the LOG_xxx macros.</dd>
%% <dt>`ospid'</dt><dd>The OS PID of the ERTS process,
%% obtained by the formatter.</dd>
%% <dt>`pid'</dt><dd>The Erlang PID of the process generating the event,
%% provided by the `logger' module.</dd>
%% <dt>`time'</dt><dd>The time at which the event occurred.<br/>
%% Normally calculated as the time the event entered the `logger' module, but
%% <i>CAN</i> be specified at the point of generation (as the value received
%% from `os:system_time(microsecond)', or equivalent microsecond timestamp)
%% for potentially more precise recording.</dd>
%% </dl>
%% Additional fields <i>CAN</i> be specified, but receive no special handling
%% and are included "as-is" when present in the event's metadata (subject to
%% filtering).

-type meta_fields() :: nonempty_list(meta_field() | atom()).
%% A non-empty list of metadata field keys.
%% The list <i>MAY</i> contain arbitrary fields (as atoms) included at the
%% point of event generation.

-type mfa_format() :: compact | expand | all.
%% <dl>
%% <dt>`compact'</dt><dd>Outputs `"mfa":"M:F/A"'</dd>
%% <dt>`expand'</dt><dd>Outputs `"module":"M","function":"F","arity":A'</dd>
%% <dt>`all'</dt><dd>Outputs all of the above.</dd>
%% </dl>

-type output_field() :: level | message | timestamp | meta_field() | atom().
%% A post-expansion log event field key.

-type output_fields() :: nonempty_list(output_field()).
%% A non-empty list of event field keys.

-type report_cb() :: logger:report_cb().
%% See <a
%% href="https://www.erlang.org/doc/apps/kernel/logger#t:report_cb/0"
%% >logger:report_cb()</a>.

-type time_delim() :: 32..126 | 160..255.
%% Printable Latin1 character.

-define(MAX_TIME_OFFSET,    840).   %% +14:00 (LINT) is a legit TZ, no DST.
-define(MIN_TIME_OFFSET,   -720).   %% -12:00 (ILDW), no DST.

-type time_offset() :: [] | [$Z] | [$z] | ?MIN_TIME_OFFSET..?MAX_TIME_OFFSET.
%% Offset from UTC. May be specified as a string or integer, where:<dl>
%% <dt>`""'</dt><dd>Denotes local time.</dd>
%% <dt>`"Z"' or `"z"'</dt><dd>Denotes UTC with that suffix.</dd>
%% <dt>`0'</dt><dd>Denotes UTC with suffix `"Z"'.</dd>
%% <dt>integer</dt><dd>Denotes the offset, in minutes, in the range
%% +14h (LINT) through -12h (ILDW), with suffix `"±hh:mm"'.</dd>
%% </dl>

-type time_unit() :: second | millisecond | microsecond.
%% Timestamp resolution.

-define(CONF_KEYS, [
    chars_limit, depth, field_filter, level_map, line_delim,
    report_cb, time_delim, time_offset, time_unit
]).

-define(DFLT_FIELDS, [
    arity, domain, file, function, gl, level, line,
    message, mfa, module, ospid, pid, timestamp
]).
-define(DFLT_FIELD_MAP, #{
    pid         => proc,
    %% Mapping to 'domain' gets special handling
    log_type    => domain
}).
-define(DFLT_LEVEL_MAP, #{
    emergency   => <<"EMERG">>,
    alert       => <<"ALERT">>,
    critical    => <<"CRIT">>,
    error       => <<"ERROR">>,
    warning     => <<"WARN">>,
    notice      => <<"NOTICE">>,
    info        => <<"INFO">>,
    debug       => <<"DEBUG">>
}).
-define(DFLT_LINE_DELIM,    $\n).
-define(DFLT_MFA_FORMAT,    compact).
-define(DFLT_TIME_DELIM,    $T).
-define(DFLT_TIME_OFFSET,   "Z").
-define(DFLT_TIME_UNIT,     millisecond).

-define(DFLT_FCONFIG, #{
    field_map   => ?DFLT_FIELD_MAP,
    level_map   => ?DFLT_LEVEL_MAP,
    line_delim  => ?DFLT_LINE_DELIM,
    mfa_format  => ?DFLT_MFA_FORMAT,
    time_delim  => ?DFLT_TIME_DELIM,
    time_offset => ?DFLT_TIME_OFFSET,
    time_unit   => ?DFLT_TIME_UNIT
}).

-define(DFLT_LOGGER_FCONFIG, #{
    legacy_header   => false,
    single_line     => false,   %% we want escaped newlines
    template        => [msg]
}).

%% This list MUST be ordered as if by lists:usort/1
-define(META_KEYS, [domain, file, gl, line, mfa, ospid, pid, time]).

%% Keys of persistent terms
-define(PT_OS_PID,      riak_log_js_os_pid).

%% ===================================================================
%% Public API
%% ===================================================================

-spec default_config() -> config().
%% @doc Returns the {@link config(). configuration} defaults.
%% @end
default_config() ->
    ?DFLT_FCONFIG.

-spec default_fields() -> nonempty_list(atom()).
%% @doc Returns the default fields that may be in a JSON output object.
%% @end
default_fields() ->
    ?DFLT_FIELDS.

-spec default_field_map() -> field_map().
%% @doc Returns the default {@link field_map()}.
%% @end
default_field_map() ->
    ?DFLT_FIELD_MAP.

-spec default_level_map() -> level_map().
%% @doc Returns the default {@link level_map()}.
%% @end
default_level_map() ->
    ?DFLT_LEVEL_MAP.

%% ===================================================================
%% logger formatter callbacks
%% ===================================================================

-spec check_config(FConfig :: logger:formatter_config() )
        -> ok | {error, term()}.
%% @doc Validates a configuration map.
%% @end
check_config(FConfig) ->
    case maps:fold(fun check_config_fold/3, [], FConfig) of
        [] ->
            ok;
        Errs ->
            {error, {invalid_formatter_config, ?MODULE, Errs}}
    end.

-spec format(
    Event :: logger:log_event(), FConfig :: config() )
        -> unicode:chardata().
%% @doc Formats a log event as a JSON object on a single line.
%% @end
format(#{level := Level, meta := Metadata} = Event, FConfig) ->
    #{level_map := LM, line_delim := LD} =
        Conf = maps:merge(?DFLT_FCONFIG, FConfig),
    Meta = build_meta_map(Metadata, Conf),
    MMap = case format_message(Event, Conf) of
        #{message := _} = MsgMap ->
            MsgMap;
        Map when erlang:is_map(Map) ->
            Map#{message => <<"report">>};
        Bin ->
            #{message => Bin}
    end,
    LMap = MMap#{level => map_level_value(Level, LM)},
    JsIn = map_field_keys(filter_final(LMap, Meta, Conf), Conf),
    [encode_value(JsIn), LD].

%% ===================================================================
%% Internal
%% ===================================================================
%% ToDo: Consider using map comprehensions in OTP 25+

-type data_map() :: #{atom() => term()}.
-type formatted() :: unicode:chardata().
-type fold_state() :: {config(), data_map()}.

-spec build_meta_map(
    Meta :: data_map(), FConfig :: config() ) -> data_map().
build_meta_map(Meta, #{field_filter := {include, Fields}} = FConfig) ->
    build_meta_map_fold(maybe_inject_ospid(
        lists:member(ospid, Fields), maps:with(Fields, Meta)), FConfig);
build_meta_map(Meta, #{field_filter := {exclude, [_|_] = Fields}} = FConfig) ->
    build_meta_map_fold(maybe_inject_ospid(
        not lists:member(ospid, Fields), maps:without(Fields, Meta)), FConfig);
build_meta_map(Meta, FConfig) ->
    %% Default behavior includes all fields
    build_meta_map_fold(maybe_inject_ospid(true, Meta), FConfig).

-spec maybe_inject_ospid(
    Inject :: boolean(), Meta :: data_map() ) -> data_map().
maybe_inject_ospid(true, Meta) ->
    Meta#{ospid => persistent_term:get(?PT_OS_PID)};
maybe_inject_ospid(_, Meta) ->
    Meta.

-spec build_meta_map_fold(
    Meta :: data_map(), FConfig :: config() ) -> data_map().
build_meta_map_fold(Meta, FConfig) ->
    {_, Result} = maps:fold(fun build_meta_map_fold/3, {FConfig, #{}}, Meta),
    Result.

-spec build_meta_map_fold(
    Key :: atom(), Val :: term(), State :: fold_state() ) -> fold_state().
build_meta_map_fold(file, File, {Cfg, Res}) ->
    Short = case filename:split(File) of
        [_, _, _, _ | _] = LongList ->
            [FN, D1, D2 | _] = lists:reverse(LongList),
            filename:join([D2, D1, FN]);
        _ ->
            File
    end,
    {Cfg, Res#{file => erlang:iolist_to_binary(Short)}};
build_meta_map_fold(mfa, MFA, {Cfg, Res}) ->
    Fmts = case maps:get(mfa_format, Cfg, ?DFLT_MFA_FORMAT) of
        all ->
            [compact, expand];
        One ->
            [One]
    end,
    {Cfg, format_mfa(Fmts, MFA, Res)};
build_meta_map_fold(time, Micros, {#{
        time_delim := TD, time_offset := TO, time_unit := TU} = Cfg, Res}) ->
    Time = case TU of
        microsecond ->
            Micros;
        _ ->
            erlang:convert_time_unit(Micros, microsecond, TU)
    end,
    Offset = if
        TO =:= []; TO =:= "Z"; TO =:= "z"; TO =:= 0 ->
            TO;
        erlang:is_integer(TO), TU =:= second ->
            (TO * 60);
        erlang:is_integer(TO) ->
            erlang:convert_time_unit((TO * 60), second, TU);
        true ->
            %% Nothing else *should* mke it through check_config/1
            TO
    end,
    TS = calendar:system_time_to_rfc3339(Time, [
        {unit, TU}, {offset, Offset}, {time_designator, TD}]),
    {Cfg, Res#{timestamp => erlang:list_to_binary(TS)}};
build_meta_map_fold(Key, Val, {Cfg, Res})->
    {Cfg, Res#{Key => Val}}.

-spec check_config_fold(
    Key :: atom(), Val :: term(), Errors :: list({term(), term()}) )
        -> list({term(), term()}).
%% @hidden Map fold helper for check_config/1.
check_config_fold(K, V, R)
        when    (K =:= chars_limit orelse K =:= depth)
        andalso (erlang:is_integer(V) andalso V > 0) ->
    R;
check_config_fold(field_filter, {exclude, []}, R) ->
    R;
check_config_fold(field_filter = K, {T, [_|_] = L} = V, R)
        when T =:= include; T =:= exclude ->
    case lists:all(fun erlang:is_atom/1, L) of
        true ->
            R;
        _ ->
            [{K, V} | R]
    end;
check_config_fold(field_map = K, V, R) when erlang:is_map(V) ->
    Check = fun
        (FK, FV, true) ->
            erlang:is_atom(FK) andalso erlang:is_atom(FV) andalso FK =/= FV;
        (_, _, _) ->
            false
    end,
    case maps:fold(Check, true, V) of
        true ->
            R;
        _ ->
            [{K, V} | R]
    end;
check_config_fold(level_map = K, V, R) when erlang:is_map(V) ->
    Levels = maps:keys(default_level_map()),
    Check = fun
        (LK, LV, true) when erlang:is_atom(LV), LV =/= LK ->
            lists:member(LK, Levels) andalso lists:member(LV, Levels);
        (LK, LV, true) when erlang:is_binary(LV), erlang:byte_size(LV) > 0 ->
            VList = erlang:binary_to_list(LV),
            lists:member(LK, Levels) andalso
                non_escape_chars(VList) andalso io_lib:char_list(VList);
        (_, _, _) ->
            false
    end,
    case maps:fold(Check, true, V) of
        true ->
            R;
        _ ->
            [{K, V} | R]
    end;
check_config_fold(line_delim, V, R)
        when erlang:is_integer(V), V >= 0, V =< 255 ->
    R;
check_config_fold(line_delim, [], R) ->
    R;
check_config_fold(line_delim = K, [_|_] = V, R) ->
    Check = fun(B) ->
        erlang:is_integer(B) andalso B >= 0 andalso B =< 255
    end,
    case lists:all(Check, V) of
        true ->
            R;
        _ ->
            [{K, V} | R]
    end;
check_config_fold(mfa_format, V, R)
        when V =:= all; V =:= compact; V =:= expand ->
    R;
check_config_fold(report_cb, V, R)
        when erlang:is_function(V, 1); erlang:is_function(V, 2) ->
    R;
check_config_fold(time_delim, V, R)
        when erlang:is_integer(V) andalso
        ((V >= 32 andalso V =< 126) orelse (V >= 160 andalso V =< 255)) ->
    R;
check_config_fold(time_offset, V, R)
        when V =:= []; V =:= [$z]; V =:= [$Z] ->
    R;
check_config_fold(time_offset, V, R)
        when erlang:is_integer(V), V >= ?MIN_TIME_OFFSET, V =< ?MAX_TIME_OFFSET ->
    R;
check_config_fold(time_unit, V, R)
        when V =:= second; V =:= millisecond; V =:= microsecond ->
    R;
check_config_fold(K, V, R) ->
    [{K, V} | R].

-spec filter_final(
    MMap :: data_map(), Meta :: data_map(), Conf :: config() )
        -> data_map().
%% @hidden `Meta' is already filtered, so filter `MMap' then merge.
filter_final(MMap, Meta, #{field_filter := {include, Fields}}) ->
    maps:merge(Meta, maps:with(Fields, MMap));
filter_final(MMap, Meta, #{field_filter := {exclude, [_|_] = Fields}}) ->
    maps:merge(Meta, maps:without(Fields, MMap));
filter_final(MMap, Meta, _Conf) ->
    maps:merge(Meta, MMap).

-spec format_message(
    Event :: logger:log_event(), FConfig :: config() )
        -> data_map() | binary().
%% @hidden Format the `msg' value of `Event'.
format_message(#{msg := {Arg, _} = Data}, Conf)
        when Arg =:= string; erlang:is_list(Arg) ->
    erlang:iolist_to_binary(format_message_string(Data, Conf));
format_message(#{msg := {report, [_|_] = Rpt}} = Event, Conf) ->
    format_message(Event#{msg := {report, maps:from_list(Rpt)}}, Conf);
format_message(#{msg := {report, #{report_cb := CB}}} = Event, Conf)
        when erlang:is_function(CB, 1); erlang:is_function(CB, 2) ->
    logger_formatter_format(Event, Conf);
format_message(#{msg := {report, _}} = Event, #{report_cb := CB} = Conf)
        when erlang:is_function(CB, 1); erlang:is_function(CB, 2) ->
    logger_formatter_format(Event, Conf);
format_message(#{msg := {report, Rpt}}, _Conf) when erlang:is_map(Rpt) ->
    Rpt;
format_message(Event, Conf) ->
    logger_formatter_format(Event, Conf).

-spec format_message_string(
    Msg :: {string | unicode:charlist(), list()}, Conf :: config() )
        -> iolist().
%% @hidden Format any non-report message.
format_message_string({string, [_|_] = Str}, Conf) ->
    format_message_string("~ts", [Str], Conf);
format_message_string({string, []}, _Conf) ->
    "none";
format_message_string({[_|_] = Fmt, [_|_] = Args}, Conf) ->
    format_message_string(Fmt, Args, Conf);
format_message_string({[_|_] = Fmt, []}, Conf) ->
    format_message_string("~ts", [Fmt], Conf);
format_message_string({[], [_|_] = Args}, Conf) ->
    format_message_string("MISSING FORMAT. Args: ~0p", [Args], Conf);
format_message_string({[], []}, _Conf) ->
    "none";
format_message_string(Data, Conf) ->
    format_message_string("STRING ERROR. Data: ~0p", [Data], Conf).

-spec format_message_string(
    Fmt :: unicode:charlist(), Args :: list(), Conf :: config() )
        -> iolist().
%% @hidden As by `io_lib:format/3' with depth limited.
format_message_string(Format, Args, Conf) ->
    Opts = case Conf of
        #{chars_limit := Limit} ->
            [{chars_limit, Limit}];
        _ ->
            []
    end,
    try
        Scanned = io_lib:scan_format(Format, Args),
        Specs = case Conf of
            #{depth := Depth} ->
                format_filter(Scanned, Depth);
            _ ->
                Scanned
        end,
        io_lib:build_text(Specs, Opts)
    catch
        Class:Reason ->
            io_lib:format(
                "FORMAT ERROR: ~0tp:~0tp: ~0tp - ~0tp",
                [Class, Reason, Format, Args])
    end.

-spec format_filter(
    Specs :: list(io_lib:format_spec()),
    Depth :: pos_integer() )
        -> list(io_lib:format_spec()).
%% @hidden Apply depth limit to `~p' and `~w' format specs.
format_filter([#{control_char := CC, args := Args} = Spec | Specs], Depth)
        when CC =:= $p; CC =:= $w ->
    UC = (CC - ($a - $A)),  % to uppercase, p => P, w => W
    [Spec#{control_char => UC, args => Args ++ [Depth]}
        | format_filter(Specs, Depth)];
format_filter([Spec | Specs], Depth) ->
    [Spec | format_filter(Specs, Depth)];
format_filter([], _Depth) ->
    [].

-spec format_mfa(
    Fmts :: list(compact | expand),
    MFA :: {module(), atom(), pos_integer()},
    Res :: data_map() ) -> data_map().
%% @hidden Format MFA as `compact', `expand'ed, or both.
format_mfa([compact | Fmts], {M, F, A} = MFA, Res) ->
    Val = erlang:iolist_to_binary([
        erlang:atom_to_binary(M), $:, erlang:atom_to_binary(F),
        $/, erlang:integer_to_binary(A)
    ]),
    format_mfa(Fmts, MFA, Res#{mfa => Val});
format_mfa([expand | Fmts], {M, F, A} = MFA, Res) ->
    format_mfa(Fmts, MFA, Res#{module => M, function => F, arity => A});
format_mfa([], _MFA, Res) ->
    Res.

-spec logger_formatter_format(
    Event :: logger:log_event(), FConfig :: logger:formatter_config() )
        -> binary().
%% @hidden Let the `logger_formatter' module format `msg'.
logger_formatter_format(Event, Conf) ->
    FConfig = maps:merge(?DFLT_LOGGER_FCONFIG,
        maps:with([chars_limit, depth, report_cb], Conf)),
    IOList = logger_formatter:format(Event, FConfig),
    erlang:iolist_to_binary(IOList).

%% Dialyzer correctly warns that the 2nd head can never match because
%% 'field_map' is present in the default config. We don't want to trigger a
%% 'badmatch' error if that ever changes, so we're keeping the protective
%% code in place.
-dialyzer({no_match, map_field_keys/2}).

-spec map_field_keys(MMap :: data_map(), Conf :: config()) -> data_map().
map_field_keys(MMap, #{field_map := FMap}) ->
    maps:fold(fun map_field_key_fold/3, MMap, FMap);
map_field_keys(MMap, _Conf) ->
    MMap.

-spec map_field_key_fold(
    Key :: atom(), Val :: atom(), MMap :: data_map() ) -> data_map().
map_field_key_fold(
        Old, domain = New, MapIn) when erlang:is_map_key(Old, MapIn) ->
    {Val, MapOut} = maps:take(Old, MapIn),
    DVal = case Val of
        [] ->
            Val;
        [_|_] ->
            case io_lib:deep_char_list(Val) of
                true ->
                    [lists:flatten(Val)];
                _ ->
                    Val
            end;
        _ ->
            [Val]
    end,
    MapOut#{New => DVal};
map_field_key_fold(Old, New, MapIn) when erlang:is_map_key(Old, MapIn) ->
    {Val, MapOut} = maps:take(Old, MapIn),
    MapOut#{New => Val};
map_field_key_fold(_, _, MMap) ->
    MMap.

-spec map_level_value(Key :: log_level(), LMap :: level_map() ) -> level_val().
map_level_value(Key, LMap) when erlang:is_map_key(Key, LMap) ->
    case maps:get(Key, LMap) of
        Key ->
            %% Avoid infinite recursion!
            maps:get(Key, default_level_map());
        Lev when erlang:is_atom(Lev) ->
            map_level_value(Lev, LMap);
        Val ->
            Val
    end;
map_level_value(Key, _) ->
    erlang:list_to_binary(string:uppercase(erlang:atom_to_list(Key))).

-spec non_escape_chars(list(char())) -> boolean().
%% @hidden Returns `true' if no escaping is needed.
non_escape_chars([Ch | Chars]) when Ch =:= $\s; Ch =:= $!; Ch >= $# ->
    non_escape_chars(Chars);
non_escape_chars([]) ->
    true;
non_escape_chars(_) ->
    false.

%% ===================================================================
%% JSON formatter
%% ===================================================================

-ifdef(USE_OTP_JSON).
-define(ENCODE_BINARY(Value),   json:encode_binary(Value)).
-else.  % use local implementation
-compile({inline, escape_char/1}).
-define(ENCODE_BINARY(Value),
    E = << (escape_char(Ch)) || <<Ch>> <= Value >>, << $\", E/binary, $\" >>
).
-endif. % ?USE_OTP_JSON

-spec encode_value(Value :: term()) -> formatted().
%% @hidden Primary value encoder
encode_value(Value) when erlang:is_binary(Value) ->
    ?ENCODE_BINARY(Value);
encode_value(null) ->
    <<"null">>;
encode_value(true) ->
    <<"true">>;
encode_value(false) ->
    <<"false">>;
encode_value(Value) when erlang:is_atom(Value) ->
    encode_value(erlang:atom_to_binary(Value, utf8));
encode_value(Value) when erlang:is_float(Value) ->
    erlang:float_to_binary(Value, [{decimals, 9}, compact]);
encode_value(Value) when erlang:is_integer(Value) ->
    erlang:integer_to_binary(Value);
encode_value([]) ->
    <<$[, $]>>;
encode_value([_|_] = Value) ->
    case io_lib:deep_char_list(Value) of
        true ->
            encode_value(erlang:iolist_to_binary(Value));
        _ ->
            Vals = [encode_value(Val) || Val <- Value],
            [ $[, lists:join($,, Vals), $] ]
    end;
encode_value(Value) when erlang:is_map(Value) ->
    Vals = maps:fold(
        fun(Key, Val, Res) ->
            [[encode_value(Key), $:, encode_value(Val)] | Res]
        end, [], Value),
    [ ${, lists:join($,, Vals), $} ];
encode_value(Value)
        when    erlang:is_pid(Value)
        orelse  erlang:is_port(Value)
        orelse  erlang:is_reference(Value) ->
    %% These types will never contain escapable characters.
    Val = erlang:iolist_to_binary(io_lib:format("~0p", [Value])),
    << $\", Val/binary, $\" >>;
encode_value(Value) ->
    encode_value(erlang:iolist_to_binary(io_lib:format("~0p", [Value]))).

-ifndef(USE_OTP_JSON).

%% The OTP-27 encoder lets the JIT build jump tables instead of range
%% comparisons. Without doing a slew of timing tests on earlier OTP releases
%% to see what's fastest where, we're just going with ranges for ease of
%% coding and readability. Presumably, most logged strings won't contain any,
%% or many, escapable characters.

-spec escape_char(Ch :: non_neg_integer()) -> binary().
escape_char($")    -> <<"\\\"">>;
escape_char($\\)   -> <<"\\\\">>;
escape_char($\b)   -> <<"\\b">>;
escape_char($\t)   -> <<"\\t">>;
escape_char($\n)   -> <<"\\n">>;
escape_char($\f)   -> <<"\\f">>;
escape_char($\r)   -> <<"\\r">>;
%% Literals *might* be faster, but we don't expect to encounter these much
%% in this use case.
escape_char(Ch) when Ch < 16 -> <<"\\u000", ($0 + Ch):8>>;
escape_char(Ch) when Ch < 32 -> <<"\\u001", ($0 + Ch):8>>;
%% Everything else *should* already be valid UTF-8.
escape_char(Ch)    -> <<Ch>>.

-endif. % ?USE_OTP_JSON

-spec init_const() -> ok.
%% @hidden Stores precomputed values in persistent terms.
init_const() ->
    persistent_term:put(?PT_OS_PID, erlang:list_to_integer(os:getpid())).

%% ===================================================================
%% Tests
%% ===================================================================

-ifdef(TEST).

check_config_test() ->
    M1 = #{},
    ?assertMatch(ok, check_config(M1)),

    M2 = default_config(),
    ?assertMatch(ok, check_config(M2)),

    M3 = #{bogus_key => bogus_val},
    ?assertMatch({
        error, {invalid_formatter_config,
            riak_log_json_formatter, [{bogus_key, bogus_val}]}},
        check_config(M3)),

    M4 = #{time_delim => 24},
    ?assertMatch({
        error, {invalid_formatter_config,
            riak_log_json_formatter, [{time_delim, 24}]}},
        check_config(M4)),

    M5 = #{time_offset => 1234},
    ?assertMatch({
        error, {invalid_formatter_config,
            riak_log_json_formatter, [{time_offset, 1234}]}},
        check_config(M5)),

    M6 = #{time_offset => 234},
    ?assertMatch(ok, check_config(M6)),

    M7 = maps:merge(default_config(), #{
        field_map => #{foo => <<"bar">>},   %% Bad type
        level_map => #{info => info}        %% Map to itself
    }),
    ?assertMatch({
        error, {invalid_formatter_config,
            riak_log_json_formatter, [{level_map, _}, {field_map, _}]}},
        check_config(M7)).

format_test() ->
    LogLoc = ?LOCATION,
    %% Make sure they haven't changed the macro in logger.hrl
    ?assertMatch([file, line, mfa], lists:sort(maps:keys(LogLoc))),
    {M, F, A} = MFA = maps:get(mfa, LogLoc),
    ?assertMatch({?MODULE, ?FUNCTION_NAME, ?FUNCTION_ARITY}, MFA),
    Meta = LogLoc#{
        pid         => erlang:self(),
        gl          => erlang:group_leader(),
        time        => logger:timestamp(),
        log_type    => eunit
    },
    Event = #{
        level => notice,
        meta => Meta,
        msg => {string, "Bob"}
    },
    MsgList = format(Event, #{mfa_format => all}),
    % io:format(user, "~nMsg: \"~s\"~n", [MsgList]),
    ?assertMatch(true, erlang:is_list(MsgList)),
    Msg = erlang:iolist_to_binary(MsgList),
    Len = erlang:byte_size(Msg),
    ?assertMatch(${, binary:first(Msg)),
    ?assertMatch($}, binary:at(Msg, (Len - 2))),
    ?assertMatch($\n, binary:last(Msg)),
    lists:foreach(
        fun(Fld) ->
            %% Each should yield exactly one match
            ?assertMatch([{_, _}], binary:matches(Msg, Fld), Fld)
        end, [
            <<"\"message\":\"Bob\"">>,
            <<"\"domain\":[\"eunit\"]">>,
            <<"\"file\":\"riak_logger/src/riak_log_json_formatter.erl\"">>,
            erlang:iolist_to_binary(
                io_lib:format("\"level\":\"~s\"",
                    [maps:get(maps:get(level, Event), default_level_map())])),
            erlang:iolist_to_binary(
                io_lib:format("\"line\":~b", [maps:get(line, Meta)])),
            erlang:iolist_to_binary(
                io_lib:format("\"mfa\":\"~s:~s/~b\"", [M, F, A])),
            erlang:iolist_to_binary(
                io_lib:format("\"module\":\"~s\"", [M])),
            erlang:iolist_to_binary(
                io_lib:format("\"function\":\"~s\"", [F])),
            erlang:iolist_to_binary(
                io_lib:format("\"arity\":~b", [A])),
            erlang:iolist_to_binary(
                io_lib:format("\"proc\":\"~0p\"", [maps:get(pid, Meta)])),
            erlang:iolist_to_binary(
                io_lib:format("\"ospid\":~s", [os:getpid()]))
        ]).

timestamp_test() ->
    %% Reference time, in microseconds
    Time = logger:timestamp(),
    %% Timestamps here are binary()
    GetRefTS = fun(Unit, Offset) ->
        Off = case erlang:is_integer(Offset) of
            true ->
                %% Offset is minutes, need same as Unit
                erlang:convert_time_unit((Offset * 60), second, Unit);
            _ ->
                Offset
        end,
        erlang:list_to_binary(calendar:system_time_to_rfc3339(
            erlang:convert_time_unit(Time, microsecond, Unit),
            [{unit, Unit}, {offset, Off}, {time_designator, $T}]))
    end,
    GetMapTS = fun(Cfg) ->
        #{timestamp := TS} = build_meta_map_fold(#{time => Time}, Cfg),
        TS
    end,
    %% Base config, with $T delimiter and "Z" timezone
    Conf = default_config(),
    ?assertMatch($T, maps:get(time_delim, Conf)),
    Units = [second, millisecond, microsecond],
    lists:foreach(
        fun(Unit) ->
            lists:foreach(
                fun(Off) ->
                    RefTS = GetRefTS(Unit, Off),
                    ModTS = GetMapTS(
                        Conf#{time_offset := Off, time_unit := Unit}),
                    ?assertEqual(RefTS, ModTS)
                end, ["", "Z", "z", 159])
        end, Units).

-endif. % ?TEST
