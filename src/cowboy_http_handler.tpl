-module(cowboy_http_handler_tpl).

-behaviour(cowboy_http_handler).

%% cowboy_http_handler callbacks
-export([
    init/3,
    handle/2,
    terminate/3
]).

-record(state, {
}).

%% ===================================================================
%% cowboy_http_handler callbacks
%% ===================================================================

init(_Type, Req, _Opts) ->
    {ok, Req, #state{}}.

handle(Req0, State = #state{}) ->
    {ok, Req1} = cowboy_req:reply(200, [
        {<<"content-type">>, <<"text/plain">>}
    ], <<"Hello World!">>, Req0),
    {ok, Req1, State}.

terminate(_Reason, _Req, #state{}) ->
    ok.

%% ===================================================================
%% Internal
%% ===================================================================
