%% -*- mode: erlang; erlang-indent-level: 4; indent-tabs-mode: nil -*-
%% -------------------------------------------------------------------
%%
%% Copyright (c) 2025 Workday, Inc.
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
-module(formatter_SUITE).

-if(?OTP_RELEASE >= 27).
-define(HAVE_OTP_JSON, true).
-endif.

%% Setup/teardown
-export([
    init_per_suite/1, end_per_suite/1,
    init_per_testcase/2, end_per_testcase/2
]).

%% Tests to run
-export([all/0]).

%% Test cases
-export([
    json_formatter/0, json_formatter/1
]).

%% Dummy OTP behaviors
%% Not listed as behavior attributes to avoid conflicts
-export([
    % gen_server
    handle_call/3,
    handle_cast/2,
    % supervisor & gen_server
    init/1,
    % log handler callback
    log/2
]).

-include_lib("common_test/include/ct.hrl").
-include_lib("kernel/include/logger.hrl").
-include_lib("stdlib/include/assert.hrl").

%% Test cases

all() ->
    [json_formatter].

%% Suite setup/teardown

init_per_suite(Config) ->
    ok = logger:set_primary_config(level, debug),
    Config.

end_per_suite(_Config) ->
    ok.

%% Testcase setup/teardown

init_per_testcase(_Case, Config) ->
    Config.

end_per_testcase(Case, _Config) ->
    lists:foreach(
        fun(Handler) ->
            %% It may not be loaded, so don't sweat it if it's not there
            _ = logger:remove_handler(Handler)
        end, proplists:get_value(log_handlers, ?MODULE:Case(), [])).

%% JSON formatter test

json_formatter() ->
    [{log_handlers, [mem_log, json_log, text_log]}].
json_formatter(Config) ->
    LogDir = filename:join(?config(priv_dir, Config), "log"),
    LogFile = filename:join(LogDir, [?FUNCTION_NAME, ".log"]),
    JsonLog = filename:join(LogDir, [?FUNCTION_NAME, ".json"]),
    FModule = riak_log_json_formatter,
    FConfig = #{},
    ok = logger:set_primary_config(#{
        level => all,
        filter_default => log,
        filters => []
    }),
    ?assertMatch(ok, logger:add_handler(text_log, logger_std_h, #{
        level => all,
        config => #{
            file => LogFile,
            file_check => 100,
            max_no_bytes => 1048576,
            max_no_files => 10
        },
        filter_default => log,
        filters => [],
        formatter => {logger_formatter, #{
            legacy_header => false,
            single_line => false,
            time_designator => $T,
            template => [
                time, " [", level, "] ", {pid, [pid, "@"], []},
                {mfa, [mfa, ":"], []}, {line, [line, ":"], []},
                " ", msg, "\n"
            ]
        }}
    })),
    ?assertMatch(ok, logger:add_handler(json_log, logger_std_h, #{
        level => all,
        config => #{
            compress_on_rotate => false,
            file => JsonLog,
            file_check => 100,
            max_no_bytes => 1048576,
            max_no_files => 10
        },
        filter_default => log,
        filters => [],
        formatter => {FModule, FConfig}
    })),
    ?assertMatch(ok, start_log()),
    ?assertMatch(ok, logger:add_handler(mem_log, ?MODULE, #{
        level => all,
        config => #{},
        filter_default => log,
        filters => [],
        formatter => {FModule, FConfig#{line_delim => []}}
    })),
    timer:sleep(200),

    %% Start, then crash, a supervisor
    ?assertMatch(ok, start_sup()),
    timer:sleep(100),
    ?assertMatch(true, kill_sup()),
    %% Record some generic log events
    ?LOG_DEBUG("Simple string"),
    ?LOG_INFO("Formatted - atom: ~0p pid: ~0p", [an_atom, erlang:self()]),
    ?LOG_NOTICE("With 'log_type'", #{log_type => dummy}),

    ?assertMatch(ok, logger_std_h:filesync(text_log)),
    ?assertMatch(ok, logger_std_h:filesync(json_log)),
    timer:sleep(200),

    FLines = read_file_lines(JsonLog),
    FCount = erlang:length(FLines),
    ?assertMatch(L when L >= 4, FCount),

    MLines = mem_logs(),
    MCount = erlang:length(MLines),
    ?assertEqual(FCount, MCount),

    check_json_recs(FLines),
    check_json_recs(MLines),
    ?assertEqual(FLines, MLines).

read_file_lines(File) ->
    {ok, IoDev} = file:open(File, [read, raw]),
    read_file_lines(IoDev, []).

read_file_lines(IoDev, Lines) ->
    case file:read_line(IoDev) of
        eof ->
            _ = file:close(IoDev),
            Lines;
        {ok, Line} ->
            case string:trim(Line) of
                [_|_] = Str ->
                    Bin = erlang:list_to_binary(Str),
                    [Bin | read_file_lines(IoDev, Lines)];
                _ ->
                    read_file_lines(IoDev, Lines)
            end
    end.

-ifdef(HAVE_OTP_JSON).
check_json_recs(Lines) ->
    Recs = [json:decode(Ln) || Ln <- Lines],
    ?assertMatch(true, lists:all(fun erlang:is_map/1, Recs)),

    LVals = maps:values(riak_log_json_formatter:default_level_map()),
    ?assertMatch(true, lists:all(
        fun
            (#{<<"level">> := Level}) ->
                lists:member(Level, LVals);
            (_) ->
                false
        end, Recs)),

    ?assertMatch(true, lists:all(
        fun
            (#{<<"message">> := Msg}) ->
                erlang:is_binary(Msg) andalso erlang:byte_size(Msg) > 0;
            (_) ->
                false
        end, Recs)),

    ?assertMatch(true, lists:all(
        fun
            (#{<<"timestamp">> := TS}) ->
                erlang:is_binary(TS) andalso erlang:is_integer(
                    calendar:rfc3339_to_system_time(erlang:binary_to_list(TS)));
            (_) ->
                false
        end, Recs)).
-else.
check_json_recs(_) ->
    ok.
-endif. % HAVE_OTP_JSON


%% ===================================================================
%% supervisor/gen_server/log handler
%% ===================================================================

-define(LOG_SERVER, riak_logger_test_server).
-define(SUPERVISOR, riak_logger_test_sup).

log(Event, #{formatter := {FmtMod, FmtConf}}) ->
    MsgBin = erlang:iolist_to_binary(FmtMod:format(Event, FmtConf)),
    gen_server:cast(?LOG_SERVER, {store_log, MsgBin}).

mem_logs() ->
    gen_server:call(?LOG_SERVER, get_logs).

start_log() ->
    ?assertMatch({ok, Pid} when erlang:is_pid(Pid),
        gen_server:start_link(
            {local, ?LOG_SERVER}, ?MODULE, ?LOG_SERVER, [])),
    ?assertMatch(ignored, gen_server:call(?LOG_SERVER, howdy)).

start_sup() ->
    ?assertMatch({ok, Pid} when erlang:is_pid(Pid),
        supervisor:start_link({local, ?SUPERVISOR}, ?MODULE, ?SUPERVISOR)),
    ?assertMatch([], supervisor:which_children(?SUPERVISOR)).

kill_sup() ->
    Trap = erlang:process_flag(trap_exit, true),
    Pid = erlang:whereis(?SUPERVISOR),
    erlang:exit(Pid, die_now),
    receive
        {'EXIT', Pid, die_now} -> ok
    end,
    Trap orelse erlang:process_flag(trap_exit, Trap).

init(?SUPERVISOR) ->
    Flags = #{
        strategy        => one_for_one,
        intensity       => 1,
        period          => 5,
        auto_shutdown   => never
    },
    Specs = [],
    {ok, {Flags, Specs}};
init(?LOG_SERVER) ->
    {ok, []}.

handle_call(get_logs, _From, State) ->
    {reply, lists:reverse(State), State};
handle_call(_Request, _From, State) ->
    {reply, ignored, State}.

handle_cast({store_log, LogLine}, State) ->
    {noreply, [LogLine | State]};
handle_cast(_Request, State) ->
    {noreply, State}.
