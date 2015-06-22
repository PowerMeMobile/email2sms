-module(email2sms_smtp_server).

-behaviour(gen_smtp_server_session).

%% API
-export([start_link/0, stop/0]).

%% gen_smtp_server_session callbacks
-export([
    init/4,
    terminate/2,
    handle_HELO/2,
    handle_EHLO/3,
    handle_AUTH/4,
    handle_MAIL/2,
    handle_MAIL_extension/2,
    handle_RCPT/2,
    handle_RCPT_extension/2,
    handle_DATA/4,
    handle_RSET/1,
    handle_VRFY/2,
    handle_other/3,
    code_change/3
]).

-include_lib("alley_common/include/logging.hrl").

-record(st, {}).

%% ===================================================================
%% API
%% ===================================================================

-spec start_link() -> {ok, pid()} | ignore | {error, any()}.
start_link() ->
    {ok, Addr} = application:get_env(smtp_addr),
    {ok, Port} = application:get_env(smtp_port),
    {ok, Protocol} = application:get_env(smtp_protocol),
    {ok, Domain} = application:get_env(smtp_domain),
    Options  = [{address, Addr}, {port, Port}, {protocol, Protocol}, {domain, Domain}],
    Result = gen_smtp_server:start_link({local, ?MODULE}, ?MODULE, [Options]),
    case Result of
        {error, Reason} ->
            ?log_error("SMTP server start failed with: ~p", [Reason]);
        {ok, _Pid} ->
            ?log_info("SMTP server started (addr: ~p, port: ~p, protocol: ~p, domain: ~s)",
                [Addr, Port, Protocol, Domain])
    end,
    Result.

-spec stop() -> ok.
stop() ->
    ?log_info("SMTP server stopping", []),
    gen_smtp_server:stop(?MODULE).

%% ===================================================================
%% gen_smtp_server_session callbacks
%% ===================================================================

init(Domain, _SessionCount, Peeraddr, _Options) ->
    ?log_info("Got connection from: ~p", [Peeraddr]),
    {ok, Greeting} = application:get_env(smtp_greeting),
    Banner = io_lib:format("~s ESMTP ~s", [Domain, Greeting]),
    {ok, Banner, #st{}}.

terminate(normal, St) ->
    {ok, normal, St};
terminate(Reason, St) ->
    ?log_error("Terminate failed with: ~p", [Reason]),
    {ok, Reason, St}.

handle_HELO(_Peername, St) ->
    {ok, St}.

handle_EHLO(_Peername, Extensions, St) ->
    {ok, Extensions, St}.

handle_AUTH(_Type, _Username, _Password, St) ->
    {ok, St}.

handle_MAIL(_From, St) ->
    {ok, St}.

handle_MAIL_extension(_Extension, _St) ->
    error.

handle_RCPT(_To, St) ->
    {ok, St}.

%% This function is never ever called.
handle_RCPT_extension(_Extension, _St) ->
    error.

handle_DATA(From, To, Data, St) ->
    ?log_info("Got an email (from: ~s, to: ~s)",
        [From, string:join([binary_to_list(A) || A <- To], ", ")]),
    {ok, MaxMsgSize} = application:get_env(smtp_max_msg_size),
    if
        MaxMsgSize =:= undefined orelse size(Data) =< MaxMsgSize ->
            try
                really_handle_DATA(From, To, Data, St)
            catch
                Exc:Cls ->
                    ?log_error("Exception: ~p:~p", [Exc, Cls]),
                    ?log_error("Probably too deep mime nesting met", []),
                    {error, "554 MIME type not supported.", St}
            end;
        true ->
            ?log_error("Message too big (~w bytes)", [size(Data)]),
            {error, "521 Message Too Big", St}
    end.

handle_RSET(_St) ->
    #st{}.

handle_VRFY(_Address, St) ->
    {error, "252 VRFY disabled", St}.

handle_other(Verb, Arg, St) ->
    ?log_error("Unrecognized command (~s ~s)", [Verb, Arg]),
    {"500 Error: verb not recognized", St}.

code_change(_OldVsn, St, _Extra) ->
    {ok, St}.

%% -------------------------------------------------------------------------
%% private functions
%% -------------------------------------------------------------------------

really_handle_DATA(From, To, Data, St) ->
    {_Type, _Subtype, Headers, _Params, _Content} =
        Component = mimemail:decode(Data),
    UUID = uuid:unparse(uuid:generate()),
    {ok, UUID, St}.
