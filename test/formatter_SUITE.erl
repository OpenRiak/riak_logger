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

-include_lib("common_test/include/ct.hrl").
-include_lib("kernel/include/logger.hrl").

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
%% For now, this just writes the log file, to be verified externally.
%% ToDo: Use the OTP-27+ 'json' module to verify the output lines.

json_formatter() ->
    [{log_handlers, [?FUNCTION_NAME]}].
json_formatter(Config) ->
    LogDir = filename:join(?config(priv_dir, Config), "log"),
    LogFile = filename:join(LogDir, [?FUNCTION_NAME, ".json"]),
    FModule = riak_log_json_formatter,
    FConfig = #{},
    HConfig = #{
        level => all,
        config => #{
            compress_on_rotate => false,
            file => LogFile,
            file_check => 100,
            max_no_bytes => 1048576,
            max_no_files => 10
        },
        filter_default => log,
        filters => [],
        formatter => {FModule, FConfig}
    },
    ok = logger:add_handler(?FUNCTION_NAME, logger_std_h, HConfig),
    ?LOG_DEBUG("Simple string"),
    ?LOG_INFO("Formatted: ~0p", [an_atom]),
    ?LOG_NOTICE("Notice string", #{log_type => dummy}).
