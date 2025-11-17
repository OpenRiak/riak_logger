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
%% The formatter is widely configurable as described for its {@link config()}
%% map, though in most cases the default configuration should be fine.
%%
%% Basic logging of JSON records, one per line, to rolling log files in Riak's
%% `advanced.config' file might look like:
%% ```
%%  {kernel, [
%%      {logger, [
%%           %% Records ALL events to JSON log
%%          {handler, json_log, logger_std_h, #{
%%              level => all,
%%              config => #{
%%                  compress_on_rotate => false,
%%                  file => "{{platform_log_dir}}/json/riak-log.json",
%%                  file_check => 100,
%%                  max_no_bytes => 1048576,
%%                  max_no_files => 10
%%              },
%%              filter_default => log,
%%              filters => [],
%%              formatter => {riak_log_json_formatter, #{
%%                  %% Defaults should be suitable for most use cases.
%%              }}
%%          }}
%%      ]}
%%  ]}
%% '''
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
%% overriding the defaults returned by {@link default_field_map/0.
%% default_field_map()}.<br/>
%% Any top-level field name can be overridden, not just the predefined ones,
%% but nested field names are not affected. For instance, if an event contains
%% field `foo', in either its metadata or a report map, it can be mapped to
%% `bar' in the output.<br/>
%% The map need not include every field, only those to be overridden.</dd>
%% <dt>`level_map :: ' {@link level_map()}</dt>
%% <dd>A map of [alternate] levels or values to be output for the JSON `level'
%% field, overriding the defaults returned by {@link default_level_map/0.
%% default_level_map()}.<br/>
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

-type meta_fields() :: nonempty_list(meta_field() | output_field()).
%% A non-empty list of metadata field keys.
%% The list <i>MAY</i> contain arbitrary fields (as atoms) included at the
%% point of event generation.

-type mfa_format() :: compact | expand | all.
%% <dl>
%% <dt>`compact'</dt><dd>Outputs `"mfa":"M:F/A"'</dd>
%% <dt>`expand'</dt><dd>Outputs `"module":"M","function":"F","arity":A'</dd>
%% <dt>`all'</dt><dd>Outputs all of the above.</dd>
%% </dl>

-type output_field() :: level | message | timestamp | atom().
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
%% @doc Returns the default {@link config(). configuration}.
%%
%% The default configuration is:
%% ```
%%  #{
%%      field_map   => default_field_map(),
%%      level_map   => default_level_map(),
%%      line_delim  => $\n,
%%      mfa_format  => compact,
%%      time_delim  => $T,
%%      time_offset => "Z",
%%      time_unit   => millisecond
%%  }
%% '''
%% @end
default_config() ->
    ?DFLT_FCONFIG.

-spec default_fields() -> nonempty_list(atom()).
%% @doc Returns the default fields that may be in a JSON output object.
%%
%% This function has little, if any, value and may be removed in a future
%% release.
%% @end
default_fields() ->
    ?DFLT_FIELDS.

-spec default_field_map() -> field_map().
%% @doc Returns the default {@link field_map()}.
%%
%% The default field map is:
%% ```
%%  #{
%%      pid         => proc,
%%      %% Mapping to 'domain' gets special handling
%%      log_type    => domain
%%  }
%% '''
%% @end
default_field_map() ->
    ?DFLT_FIELD_MAP.

-spec default_level_map() -> level_map().
%% @doc Returns the default {@link level_map()}.
%%
%% The default level map is:
%% ```
%%  #{
%%      emergency   => <<"EMERG">>,
%%      alert       => <<"ALERT">>,
%%      critical    => <<"CRIT">>,
%%      error       => <<"ERROR">>,
%%      warning     => <<"WARN">>,
%%      notice      => <<"NOTICE">>,
%%      info        => <<"INFO">>,
%%      debug       => <<"DEBUG">>
%%  }
%% '''
%% @end
default_level_map() ->
    ?DFLT_LEVEL_MAP.

%% ===================================================================
%% logger formatter callbacks
%% ===================================================================

-spec check_config(FConfig :: logger:formatter_config() )
        -> ok | {error, term()}.
%% @doc Validates a configuration map.
%%
%% This function is called by the Kernel Logger when a handler is configured
%% to use this formatter.
%% @end
check_config(FConfig) ->
    case maps:fold(fun check_config_fold/3, [], FConfig) of
        [] ->
            ok;
        Errs ->
            {error, {invalid_formatter_config, ?MODULE, Errs}}
    end.

%% See To Do comment matching Stack below.
-dialyzer({no_match, format/2}).

-spec format(
    Event :: logger:log_event(), FConfig :: config() )
        -> unicode:chardata().
%% @doc Formats a log event as a JSON object on a single line.
%%
%% This function is called by Kernel Logger handlers to format log events.
%%
%% In all cases we'll output a valid JSON record with at least `level',
%% `message', and `timestamp' fields, subject to configured filtering and/or
%% field name mapping.
%%
%% Per documentation and implementation of the <a
%% href="https://www.erlang.org/doc/apps/kernel/logger#t:log_event/0"
%% >`logger:log_event()'</a> type, the `level', `meta' and `msg' fields
%% <i>MUST</i> all be present in `Event' on entry to this function.
%% Testing has shown that `kernel' code violates this contract in some
%% invocation scenarios, so we're defensive against non-compliant events.
%%
%% The {@link config(). `FConfig'} map has been heavily validated by
%% {@link check_config/1. `check_config(FConfig)'} when the handler using this
%% formatter was added, so we aren't paranoid about contract violations in
%% that parameter it gets to this function.
%% @end
format(#{
        level := Level, meta := #{time := _, gl := _, pid := _} = Metadata,
        msg := MsgVal} = Event, FConfig) when erlang:is_tuple(MsgVal) ->
    Conf = merge_config(FConfig),
    Meta = build_meta_map(Metadata, Conf),
    MMap = try format_message(Event, Conf) of
        #{message := _} = MsgMap ->
            MsgMap;
        Map when erlang:is_map(Map) ->
            Map#{message => <<"report">>};
        Bin ->
            #{message => Bin}
    catch
        Class:Reason:Stack ->
            %% Our sole requirements here are:
            %% 1) Return a valid map with a `message' field whose value is a
            %%    quoted unicode string.
            %% 2) Do NOT raise another exception.
            %%
            %% We know from the head guard that MsgVal is a tuple, so let
            %% the encoder wrap it with quotes.
            MsgBin = format_any_msg(MsgVal, FConfig),
            {EFmt, EArgs, LocInf} = case Stack of
                %% 'A' may be Arity or Args, format the same either way
                [{Mod, Fun, A, Info} | _] ->
                    {"~0tp:~0tp/~0tp", [Mod, Fun, A], Info};
                %% ToDo: dialyzer says this can never match?
                %% Docs say it's a legit pattern, ignoring until a later date.
                [{Fun, A, Info} | _] ->
                    {"~0tp/~0tp", [Fun, A], Info};
                %% Nothing else is allowed, but don't want a case_clause here
                Other ->
                    {"~0tp", [Other], []}
            end,
            {Fmt, Args} = case LocInf of
                [_|_] = InfoList ->
                    case maps:from_list(InfoList) of
                        #{file := F, line := L} ->
                            {EFmt ++ " ~ts:~b",
                                EArgs ++ [filename:basename(F), L]};
                        #{file := F} ->
                            {EFmt ++ " ~ts", EArgs ++ [filename:basename(F)]};
                        #{line := L} ->
                            {EFmt ++ " line:~b", EArgs ++ [L]};
                        _ ->
                            {EFmt, EArgs}
                    end;
                _ ->
                    {EFmt, EArgs}
            end,
            ErrBin = unicode:characters_to_binary(io_lib:format(
                "~0tp:~0tp: " ++ Fmt, [Class, Reason] ++ Args)),
            #{message => MsgBin, 'format-error' => ErrBin}
    end,
    LMap = MMap#{level => map_level_value(Level, maps:get(level_map, Conf))},
    JsIn = map_field_keys(filter_final(LMap, Meta, Conf), Conf),
    [encode_value(JsIn), maps:get(line_delim, Conf)];
%% Per 'logger' documentation, an Event ALWAYS contains the below 'meta'
%% element. Testing has shown that there are paths through the logger,
%% at least via the old error_logger module, where this contract is violated.
format(Event, FConfig) when not erlang:is_map_key(meta, Event) ->
    Meta = #{
        gl => erlang:group_leader(),
        pid => erlang:self(),
        time => logger:timestamp()
    },
    format(Event#{meta => Meta}, FConfig);
%% Similar to the above, ensure that the 'meta' map always contains at least
%% the keys required by the contract. This *may* be dead code, but given that
%% we know the contract isn't inviolable rather safe than sorry.
%% This *should* always be invoked within the process generating the event.
format(#{meta := Meta} = Event, FConfig)
        when not erlang:is_map_key(time, Meta) ->
    format(Event#{meta => Meta#{time => logger:timestamp()}}, FConfig);
format(#{meta := Meta} = Event, FConfig)
        when not erlang:is_map_key(gl, Meta) ->
    format(Event#{meta => Meta#{gl => erlang:group_leader()}}, FConfig);
format(#{meta := Meta} = Event, FConfig)
        when not erlang:is_map_key(pid, Meta) ->
    format(Event#{meta => Meta#{pid => erlang:self()}}, FConfig);
%% Following should NEVER match, but more defensive code ...
format(Event, FConfig) when not erlang:is_map_key(level, Event) ->
    format(Event#{level => error}, FConfig);
format(#{msg := Msg} = Event, FConfig) ->
    %% Msg is not a tuple, make it one.
    %% This is pretty inefficient, but it should never, ever happen.
    format(Event#{msg := {string, format_any_msg(Msg, FConfig)}}, FConfig);
format(Event, FConfig) ->
    %% No 'msg' field at all
    format(Event#{msg => {string, <<>>}}, FConfig).

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
    {Cfg, Res#{file => unicode:characters_to_binary(Short)}};
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
            VList = unicode:characters_to_list(LV),
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
        -> data_map() | formatted().
%% @hidden Format the `msg' value of `Event'.
format_message(#{msg := {Arg, _} = Data}, Conf)
        when Arg =:= string; erlang:is_list(Arg) ->
    unicode:characters_to_binary(format_message_string(Data, Conf));
%% Anything else *should* be a 'report'.
format_message(#{msg := {report, Rpt}} = Event, Conf) ->
    case format_message_report(Rpt, Conf) of
        pass ->
            logger_formatter_format(Event, Conf);
        Res ->
            Res
    end;
%% In case they add something new ...
format_message(Event, Conf) ->
    logger_formatter_format(Event, Conf).

-spec format_message_report(
    Rpt :: logger:report(), Conf :: config() )
        -> data_map() | formatted() | pass.
%% @hidden Handle a bunch of funky 'report' situations.
%% Neither our map encoder or 'logger_formatter' can handle some of the
%% reports from older subsystems unaided, so we match patterns that need
%% special handling.
%% Return 'pass' to format the event with logger_formatter:format/2.
%% @end
format_message_report([], _Conf) ->
    <<>>;
%% Make sure the report is a map so we can match on its contents.
format_message_report([_|_] = Rpt, Conf) ->
    format_message_report(maps:from_list(Rpt), Conf);
%% If the event or config specify a callback, let 'logger_formatter' have it.
format_message_report(#{report_cb := CB}, _Conf)
        when erlang:is_function(CB, 1); erlang:is_function(CB, 2) ->
    pass;
format_message_report(_Rpt, #{report_cb := CB})
        when erlang:is_function(CB, 1); erlang:is_function(CB, 2) ->
    pass;
%% The problem here is that Args may be a list of integers, and a lot more
%% integers fall into the unicode range than the latin1 range, so we can
%% mis-type the value without context and print garbage.
%% Not sure if this should be limited to 'error_logger' or not.
format_message_report(
        #{args := Args, format := Fmt, label := {error_logger, _}} = Rpt, Conf)
        when erlang:is_list(Args), erlang:is_list(Fmt) ->
    Res = maps:without([args, format], Rpt),
    Res#{message => format_message_string({Fmt, Args}, Conf)};
%% We don't know where it came from, but hopefully the source follows a sane
%% format/args mapping.
format_message_report(#{args := Args, format := Fmt} = Rpt, Conf)
        when erlang:is_list(Args), erlang:is_list(Fmt) ->
    Msg = case format_message_string({Fmt, Args}, Conf) of
        <<"FORMAT ERROR: ", _/binary>> ->
            format_message_string({"~0tp - ~0tp", [Fmt, Args]}, Conf);
        Good ->
            Good
    end,
    Res = maps:without([args, format], Rpt),
    Res#{message => Msg};
%% Hopefully anything else will be directly mappable.
format_message_report(Rpt, _Conf) ->
    Rpt.

-spec format_message_string(
    Msg :: {string | unicode:charlist(), list()}, Conf :: config() )
        -> unicode:unicode_binary().
%% @hidden Format any non-report message.
format_message_string({string, []}, _Conf) ->
    <<>>;
format_message_string({string, <<>> = Bin}, _Conf) ->
    Bin;
format_message_string({string, Str}, Conf) ->
    format_message_string("~ts", [Str], Conf);
format_message_string({[_|_] = Fmt, [_|_] = Args}, Conf) ->
    format_message_string(Fmt, Args, Conf);
format_message_string({[_|_] = Fmt, []}, Conf) ->
    format_message_string("~ts", [Fmt], Conf);
format_message_string({[], [_|_] = Args}, Conf) ->
    format_message_string("MISSING FORMAT: Args: ~0tp", [Args], Conf);
format_message_string({[], []}, _Conf) ->
    <<>>;
format_message_string(Data, Conf) ->
    format_message_string("STRING ERROR: Data: ~0tp", [Data], Conf).

-spec format_message_string(
    Fmt :: unicode:charlist(), Args :: list(), Conf :: config() )
        -> unicode:unicode_binary().
%% @hidden As by `io_lib:format/3' with length/depth limited.
format_message_string(Format, Args, Conf) ->
    Opts = case Conf of
        #{chars_limit := Limit} ->
            [{chars_limit, Limit}];
        _ ->
            []
    end,
    Msg = try
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
                "FORMAT ERROR: ~0tp:~0tp: Fmt: ~0tp Args: ~0tp",
                [Class, Reason, Format, Args])
    end,
    unicode:characters_to_binary(Msg).

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

-spec format_any_msg(Term :: term(), Conf :: config() )
        -> unicode:unicode_binary().
%% @hidden Safely format any 'message' term into a unicode binary,
%% accounting for depth and length constraints.
%% If present, the 'depth' and 'chars_limit' values have been validated by
%% check_config/1, so this can never raise an exception, making it safe to
%% call from anywhere.
format_any_msg(Term, Conf) ->
    {Fmt, Args} = case Conf of
        #{depth := Depth} ->
            {"~0tP", [Term, Depth]};
        _ ->
            {"~0tp", [Term]}
    end,
    Opts = case Conf of
        #{chars_limit := Limit} ->
            [{chars_limit, Limit}];
        _ ->
            []
    end,
    Str = io_lib:format(Fmt, Args, Opts),
    maybe_dequote(unicode:characters_to_binary(Str)).

-spec format_mfa(
    Fmts :: list(compact | expand),
    MFA :: {module(), atom(), pos_integer()},
    Res :: data_map() ) -> data_map().
%% @hidden Format MFA as `compact', `expand'ed, or both.
format_mfa([compact | Fmts], {M, F, A} = MFA, Res) ->
    MBin = erlang:atom_to_binary(M),
    FBin = erlang:atom_to_binary(F),
    ABin = erlang:integer_to_binary(A),
    Val = << MBin/binary, $:, FBin/binary, $/, ABin/binary >>,
    format_mfa(Fmts, MFA, Res#{mfa => Val});
format_mfa([expand | Fmts], {M, F, A} = MFA, Res) ->
    format_mfa(Fmts, MFA, Res#{module => M, function => F, arity => A});
format_mfa([], _MFA, Res) ->
    Res.

-spec logger_formatter_format(
    Event :: logger:log_event(), FConfig :: logger:formatter_config() )
        -> unicode:unicode_binary().
%% @hidden Let the `logger_formatter' module format `msg'.
logger_formatter_format(Event, Conf) ->
    FConfig = maps:merge(?DFLT_LOGGER_FCONFIG,
        maps:with([chars_limit, depth, report_cb], Conf)),
    IOList = logger_formatter:format(Event, FConfig),
    unicode:characters_to_binary(IOList).

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
%% @hidden Map a level key to a level_map value, possibly recursively.
%% LMap is guaranteed to contain all of the legal logger:level() values.
map_level_value(Key, LMap) when erlang:is_map_key(Key, LMap) ->
    case maps:get(Key, LMap) of
        Key ->
            %% Avoid infinite recursion!
            maps:get(Key, ?DFLT_LEVEL_MAP);
        Lev when erlang:is_atom(Lev) ->
            map_level_value(Lev, LMap);
        Val ->
            Val
    end;
map_level_value(Key, _) when erlang:is_atom(Key) ->
    unicode:characters_to_binary(string:uppercase(erlang:atom_to_list(Key)));
map_level_value(Key, _) ->
    unicode:characters_to_binary(io_lib:format("~0tp", [Key])).

-spec maybe_dequote(Bin :: binary()) -> binary().
%% De-quote a binary in preparation for encoding as a sting.
maybe_dequote(Bin) when erlang:byte_size(Bin) > 2 ->
    Len = (erlang:byte_size(Bin) - 2),
    case Bin of
        << $\", Quoted:Len/binary, $\" >> ->
            Quoted;
        _ ->
            Bin
    end;
maybe_dequote(<< $\", $\" >>) ->
    <<>>;
maybe_dequote(Bin) ->
    Bin.

-spec merge_config(Config :: config()) -> config().
%% @hidden Merge supplied config, and level map if present, with defaults.
merge_config(#{level_map := LMap} = Config) ->
    Merged = maps:merge(default_config(), Config),
    Merged#{level_map := maps:merge(default_level_map(), LMap)};
merge_config(Config) ->
    maps:merge(default_config(), Config).

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
%% Almost certainly not the fastest way to do this, especially since *most*
%% strings won't need escaping. It shouldn't be awful, though, for the
%% relatively short strings being logged, so we'll let it suffice until we
%% get onto OTP-27.
-define(ENCODE_BINARY(Value),
    E = << (escape_char(Ch)) || <<Ch>> <= Value >>,
    << $\", E/binary, $\" >>
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
            encode_value(unicode:characters_to_binary(Value));
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
    Val = unicode:characters_to_binary(io_lib:format("~0tp", [Value])),
    << $\", Val/binary, $\" >>;
encode_value(Value) ->
    encode_value(maybe_dequote(
        unicode:characters_to_binary(io_lib:format("~0tp", [Value])))).

-ifndef(USE_OTP_JSON).

-spec escape_char(Ch :: non_neg_integer()) -> binary().
%% x00-x1f in order so the compiler can build a jump table
escape_char(0)      -> <<"\\u0000">>;
escape_char(1)      -> <<"\\u0001">>;
escape_char(2)      -> <<"\\u0002">>;
escape_char(3)      -> <<"\\u0003">>;
escape_char(4)      -> <<"\\u0004">>;
escape_char(5)      -> <<"\\u0005">>;
escape_char(6)      -> <<"\\u0006">>;
escape_char(7)      -> <<"\\u0007">>;
escape_char($\b)    -> <<"\\b">>;   %  8
escape_char($\t)    -> <<"\\t">>;   %  9
escape_char($\n)    -> <<"\\n">>;   % 10
escape_char(11)     -> <<"\\u000B">>;
escape_char($\f)    -> <<"\\f">>;   % 12
escape_char($\r)    -> <<"\\r">>;   % 13
escape_char(14)     -> <<"\\u000E">>;
escape_char(15)     -> <<"\\u000F">>;
escape_char(16)     -> <<"\\u0010">>;
escape_char(17)     -> <<"\\u0011">>;
escape_char(18)     -> <<"\\u0012">>;
escape_char(19)     -> <<"\\u0013">>;
escape_char(20)     -> <<"\\u0014">>;
escape_char(21)     -> <<"\\u0015">>;
escape_char(22)     -> <<"\\u0016">>;
escape_char(23)     -> <<"\\u0017">>;
escape_char(24)     -> <<"\\u0018">>;
escape_char(25)     -> <<"\\u0019">>;
escape_char(26)     -> <<"\\u001A">>;
escape_char(27)     -> <<"\\u001B">>;
escape_char(28)     -> <<"\\u001C">>;
escape_char(29)     -> <<"\\u001D">>;
escape_char(30)     -> <<"\\u001E">>;
escape_char(31)     -> <<"\\u001F">>;
%% These two aren't in the inclusive x00-x1f range
escape_char($")     -> <<"\\\"">>;
escape_char($\\)    -> <<"\\\\">>;
%% Everything else *should* already be valid UTF-8.
escape_char(Ch)     -> <<Ch>>.

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
    ?assertMatch(
        [{bogus_key, bogus_val}],
        check_config_test_errors(check_config(M3))),

    M4 = #{time_delim => 24},
    ?assertMatch(
        [{time_delim, 24}],
        check_config_test_errors(check_config(M4))),

    M5 = #{time_offset => 1234},
    ?assertMatch(
        [{time_offset, 1234}],
        check_config_test_errors(check_config(M5))),

    M6 = #{time_offset => 234},
    ?assertMatch(ok, check_config(M6)),

    M7 = merge_config(#{
        field_map => #{foo => <<"bar">>},   %% Bad type
        level_map => #{info => info}        %% Map to itself
    }),
    ?assertMatch(
        [{field_map, _}, {level_map, _}],
        check_config_test_errors(check_config(M7))),

    M8 = #{chars_limit => 0, depth => -2},
    ?assertMatch(
        [{chars_limit, _}, {depth, _}],
        check_config_test_errors(check_config(M8))).

%% Different OTP versions return the errors in different orders depending
%% on map folding implementation, so sort if more than one.
check_config_test_errors({error,
        {invalid_formatter_config, riak_log_json_formatter, [_] = Errors}}) ->
    Errors;
check_config_test_errors({error,
        {invalid_formatter_config, riak_log_json_formatter, Errors}}) ->
    lists:sort(Errors);
check_config_test_errors(Result) ->
    Result.

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
    ?assertMatch(true, erlang:is_list(MsgList)),
    Msg = unicode:characters_to_binary(MsgList),
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
            unicode:characters_to_binary(
                io_lib:format("\"level\":\"~ts\"",
                    [maps:get(maps:get(level, Event), default_level_map())])),
            unicode:characters_to_binary(
                io_lib:format("\"line\":~b", [maps:get(line, Meta)])),
            unicode:characters_to_binary(
                io_lib:format("\"mfa\":\"~ts:~ts/~b\"", [M, F, A])),
            unicode:characters_to_binary(
                io_lib:format("\"module\":\"~ts\"", [M])),
            unicode:characters_to_binary(
                io_lib:format("\"function\":\"~ts\"", [F])),
            unicode:characters_to_binary(
                io_lib:format("\"arity\":~b", [A])),
            unicode:characters_to_binary(
                io_lib:format("\"proc\":\"~0tp\"", [maps:get(pid, Meta)])),
            unicode:characters_to_binary(
                io_lib:format("\"ospid\":~ts", [os:getpid()]))
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

report_test() ->
    Event = #{level => info},
    Conf = #{},
    %% This sort of report blew up in v1.2.1 because 'args' was misinterpreted
    %% as a unicode string.
    Rpt = {report, #{
        args => [131072],
        format => "riak_kv_env: Open file limit: ~p",
        label => {error_logger, info_msg}
    }},
    Pats = [
        <<"\"level\":\"INFO\"">>,
        <<"\"message\":\"riak_kv_env: Open file limit: 131072\"">>,
        <<"\"label\":\"{error_logger,info_msg}\"">>
    ],
    Json = unicode:characters_to_binary(format(Event#{msg => Rpt}, Conf)),
    lists:foreach(
        fun(Pat) ->
            ?assertMatch({S, L}
                    when erlang:is_integer(S) andalso erlang:is_integer(L),
                    binary:match(Json, Pat))
        end, Pats).

unicode_test() ->
    Event = #{
        msg => {string, "tab:\t 0x1e:\x1e Ctrl-D:\4"},
        level => warnin, meta => #{
            gl => erlang:group_leader(),
            pid => erlang:self(),
            time => logger:timestamp(),
            line => ?LINE
        }},
    Conf = #{},
    Json = unicode:characters_to_binary(format(Event, Conf)),
    Patt = <<"\"message\":\"tab:\\t 0x1e:\\u001E Ctrl-D:\\u0004\"">>,
    ?assertMatch({S, L}
            when erlang:is_integer(S) andalso erlang:is_integer(L),
            binary:match(Json, Patt)).

bad_event_test() ->
    %% Throw a bunch of garbage at format/2 and ensure it doesn't raise
    %% an exception.
    Time = logger:timestamp(),
    Meta = #{
        gl => erlang:group_leader(),
        pid => erlang:self(),
        time => Time
    },
    Conf = #{},
    Data = [
        %% Legit Event
        {#{level => info, meta => Meta#{line => ?LINE},
            msg => {string, "a plain string"}}, Conf, msg},
        %% Illegal 'msg'
        {#{level => info, meta => Meta#{line => ?LINE},
            msg => "bad string msg"}, Conf, msg},
        %% No required fields
        {#{}, Conf, ""},
        %% Illegal format
        {#{level => notice, meta => Meta#{line => ?LINE},
            msg => {"~q", [junk]}}, Conf, <<"\"message\":\"FORMAT ERROR: ">>}
    ],
    bad_event_test_check(Data).

bad_event_test_check([{Event, Config, Match} | Rest]) ->
    JSL = case format(Event, Config) of
        [_|_] = JsList ->
            JsList;
        Bad ->
            erlang:error(bad_list, [Bad])
    end,
    Json = unicode:characters_to_binary(JSL),
    M = case Match of
        msg ->
            MV = case maps:get(msg, Event) of
                {string, MS} ->
                    MS;
                MS ->
                    MS
            end,
            unicode:characters_to_binary(
                io_lib:format("\"message\":\"~ts\"", [MV]));
        Key when erlang:is_atom(Key) ->
            unicode:characters_to_binary(io_lib:format(
                "\"~ts\":\"~ts\"", [Key, maps:get(Key, Event)]));
        Str when erlang:is_list(Str) ->
            unicode:characters_to_binary(
                io_lib:format("\"message\":\"~ts\"", [Str]));
        Bin ->
            Bin
    end,
    case binary:match(Json, M) of
        {S, L} when erlang:is_integer(S) andalso erlang:is_integer(L) ->
            ok;
        Res ->
            %% Make it look like an assertMatch failure for rebar reporting
            X1 = case Event of
                #{meta := #{line := Line}} ->
                    [{line, Line}];
                _ ->
                    []
            end,
            X2 = case Match of
                K when erlang:is_atom(K) ->
                    [{key, K}, {val, maps:get(K, Event)} | X1];
                V ->
                    [{match, V} | X1]
            end,
            Extra = [{json, Json}, {pattern, M}, {value, Res} | X2],
            erlang:error(assertMatch, Extra)
    end,
    bad_event_test_check(Rest);
bad_event_test_check([]) ->
    ok.

-endif. % ?TEST
