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

-type config_map() :: any().
-type config_fetch_fun() ::
    fun((string(), config_map()) -> list()|pos_integer()).
-type standard_handler() ::
    {handler, atom(), logger_std_h, map()}.

-define(FILE_CONSOLE_CFGKEY, "logger.file").
-define(FILE_ERROR_CFGKEY, "error.file").
-define(FILE_CRASH_CFGKEY, "crash.file").
-define(FILE_REPORT_CFGKEY, "report.file").
-define(FILE_BACKEND_CFGKEY, "backend.file").
-define(FILE_BACKGROUND_CFGKEY, "background.file").
-define(FILE_JSON_CFGKEY, "json.file").
-define(MAX_FILESIZE_CFGKEY, "logger.max_file_size").
-define(MAX_FILECOUNT_CFGKEY, "logger.max_files").
-define(DEFAULT_FORMAT_CFGKEY, "logger.format").
-define(DEFAULT_FILTERS_CFGKEY, "logger.default_filters").
-define(ADDITIONAL_HANDLERS_CFGKEY, "logger.additional_handlers").

-define(STANDARD_FILTERS, [crash, error, progress, report, sasl]).