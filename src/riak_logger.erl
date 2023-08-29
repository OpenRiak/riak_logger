%% -------------------------------------------------------------------
%%
%% Copyright (c) 2023 Workday, Inc.
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
%% @doc Riak kernel logger configuration and operations.
%%
%% Filter functions are defined as
%% ```
%%  filter_<codes>(Event :: logger:log_event(), Action :: stop | log)
%%      -> logger:log_event() | stop | ignore.
%% '''
%% where `<codes>' is an alphabetically-ordered list of
%% ```
%%  c - match proc_lib-style crash reports
%%  e - match emulator-spawned process crashes
%%  p - match application/supervisor progress reports
%%  r - match events from processes whose group leader is remote
%%  s - match SASL reports
%% '''
%% This allows a single filter to be specified in a logger handler
%% specification, reducing or eliminating filter chaining to improve
%% performance.
%%
%% Note that some non-composite filters are semantically equivalent to
%% functions in the OTP `logger_filters' module and are documented as such.
%% In all cases the filters defined here should outperform their OTP
%% counterparts due to explicit function head pattern matching.
%%
-module(riak_logger).

% Filters
-export([
    filter_c/2,
    filter_ce/2,
    filter_cep/2,
    filter_ceps/2,
    filter_ceprs/2,
    filter_ces/2,
    filter_e/2,
    filter_p/2,
    filter_ps/2,
    filter_r/2,
    filter_s/2
]).

-compile([
    inline,
    %% This is crucial, so don't rely on implicit inlining alone.
    {inline, [filter_match/2]}
]).

-type f_action() :: log | stop.
-type f_result() :: logger:filter_return().

%% ===================================================================
%% Filters
%% ===================================================================

-define(FSPEC(F), -spec F(
    Event :: logger:log_event(), Action :: f_action()) -> f_result()).

?FSPEC(filter_c).
?FSPEC(filter_ce).
?FSPEC(filter_cep).
?FSPEC(filter_ceps).
?FSPEC(filter_ceprs).
?FSPEC(filter_ces).
?FSPEC(filter_e).
?FSPEC(filter_p).
?FSPEC(filter_ps).
?FSPEC(filter_r).
?FSPEC(filter_s).

%% @doc Match `proc_lib'-style crash reports.
%%
%% No equivalent in the `logger_filters' module.
filter_c(#{msg := {report, #{label := {_, crash}}}} = Event, Action) ->
    filter_match(Event, Action);
filter_c(_Event, _Action) ->
    ignore.

%% @doc Match crash event patterns.
filter_ce(#{msg := {report, #{label := {_, crash}}}} = Event, Action) ->
    filter_match(Event, Action);
filter_ce(#{meta := #{error_logger := #{emulator := true, tag := error}}} = Event, Action) ->
    filter_match(Event, Action);
filter_ce(_Event, _Action) ->
    ignore.

%% @doc Match c/e/p event patterns.
filter_cep(#{msg := {report, #{label := {_, crash}}}} = Event, Action) ->
    filter_match(Event, Action);
filter_cep(#{msg := {report, #{label := {_, progress}}}} = Event, Action) ->
    filter_match(Event, Action);
filter_cep(#{meta := #{error_logger := #{emulator := true, tag := error}}} = Event, Action) ->
    filter_match(Event, Action);
filter_cep(_Event, _Action) ->
    ignore.

%% @doc Match c/e/p/s event patterns.
filter_ceps(#{msg := {report, #{label := {_, crash}}}} = Event, Action) ->
    filter_match(Event, Action);
filter_ceps(#{msg := {report, #{label := {_, progress}}}} = Event, Action) ->
    filter_match(Event, Action);
filter_ceps(#{meta := #{domain := [otp, sasl | _]}} = Event, Action) ->
    filter_match(Event, Action);
filter_ceps(#{meta := #{error_logger := #{emulator := true, tag := error}}} = Event, Action) ->
    filter_match(Event, Action);
filter_ceps(_Event, _Action) ->
    ignore.

%% @doc Match c/e/p/r/s event patterns.
filter_ceprs(#{msg := {report, #{label := {_, crash}}}} = Event, Action) ->
    filter_match(Event, Action);
filter_ceprs(#{msg := {report, #{label := {_, progress}}}} = Event, Action) ->
    filter_match(Event, Action);
filter_ceprs(#{meta := #{domain := [otp, sasl | _]}} = Event, Action) ->
    filter_match(Event, Action);
filter_ceprs(#{meta := #{error_logger := #{emulator := true, tag := error}}} = Event, Action) ->
    filter_match(Event, Action);
filter_ceprs(#{meta := #{gl := GL}} = Event, Action) when erlang:node(GL) =/= erlang:node() ->
    filter_match(Event, Action);
filter_ceprs(_Event, _Action) ->
    ignore.

%% @doc Match c/e/s event patterns.
filter_ces(#{msg := {report, #{label := {_, crash}}}} = Event, Action) ->
    filter_match(Event, Action);
filter_ces(#{meta := #{domain := [otp, sasl | _]}} = Event, Action) ->
    filter_match(Event, Action);
filter_ces(#{meta := #{error_logger := #{emulator := true, tag := error}}} = Event, Action) ->
    filter_match(Event, Action);
filter_ces(_Event, _Action) ->
    ignore.

%% @doc Match emulator-spawned process crash reports.
%%
%% No equivalent in the `logger_filters' module.
filter_e(#{meta := #{error_logger := #{emulator := true, tag := error}}} = Event, Action) ->
    filter_match(Event, Action);
filter_e(_Event, _Action) ->
    ignore.

%% @doc Optimized match for progress reports.
%% @equiv logger_filters:progress(Event, Action)
filter_p(#{msg := {report, #{label := {_, progress}}}} = Event, Action) ->
    filter_match(Event, Action);
filter_p(_Event, _Action) ->
    ignore.

%% @doc Match p/s event patterns.
filter_ps(#{msg := {report, #{label := {_, progress}}}} = Event, Action) ->
    filter_match(Event, Action);
filter_ps(#{meta := #{domain := [otp, sasl | _]}} = Event, Action) ->
    filter_match(Event, Action);
filter_ps(_Event, _Action) ->
    ignore.

%% @doc Optimized match for events from processes whose group leader is
%% on a remote node.
%%
%% This filter is more expensive to execute than others in this module, and
%% should be reserved for applications where it is known to be relevant.
%% @equiv logger_filters:remote_gl(Event, Action)
filter_r(#{meta := #{gl := GL}} = Event, Action) when erlang:node(GL) =/= erlang:node() ->
    filter_match(Event, Action);
filter_r(_Event, _Action) ->
    ignore.

%% @doc Optimized match for SASL events.
%% @equiv logger_filters:domain(Event, {Action, sub, [otp, sasl]})
filter_s(#{meta := #{domain := [otp, sasl | _]}} = Event, Action) ->
    filter_match(Event, Action);
filter_s(_Event, _Action) ->
    ignore.

%% ===================================================================
%% Internal
%% ===================================================================

?FSPEC(filter_match).
%% @hidden This will be inlined away.
filter_match(Event, log) ->
    Event;
filter_match(_Event, Action) ->
    Action.
