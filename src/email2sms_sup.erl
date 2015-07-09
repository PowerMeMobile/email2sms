-module(email2sms_sup).

-behaviour(supervisor).

%% API
-export([start_link/0]).

%% supervisor callbacks
-export([init/1]).

-include_lib("alley_common/include/supervisor_spec.hrl").

-define(CHILD(I, Restart, Timeout, Type), {I, {I, start_link, []}, Restart, Timeout, Type, [I]}).

%% ===================================================================
%% API
%% ===================================================================

-spec start_link() -> {ok, pid()} | ignore | {error, term()}.
start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

%% ===================================================================
%% supervisor callbacks
%% ===================================================================

init([]) ->
    {ok, {{one_for_one, 5, 10}, [
        ?CHILD(email2sms_smtp_server, transient, 5000, worker)
    ]}}.
