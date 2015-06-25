-module(email2sms_smtp_server).

-behaviour(gen_smtp_server_session).

%% API
-export([start_link/0, stop/0]).

%% gen_smtp_server_session callbacks
-export([
    init/4,
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
    code_change/3,
    terminate/2
]).

-include("application.hrl").
-include_lib("alley_common/include/logging.hrl").

-record(st, {}).

%% ===================================================================
%% API
%% ===================================================================

-spec start_link() -> {ok, pid()} | ignore | {error, any()}.
start_link() ->
    {ok, Addr} = application:get_env(?APP, smtp_addr),
    {ok, Port} = application:get_env(?APP, smtp_port),
    {ok, Protocol} = application:get_env(?APP, smtp_protocol),
    {ok, [Domain|_]} = application:get_env(?APP, smtp_local_domains),
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

init(Domain, SessionCount, PeerAddr, _Options) ->
    ?log_debug("Got connection from: ~p", [PeerAddr]),
    {ok, MaxSessionCount} = application:get_env(?APP, smtp_max_session_count),
	case SessionCount > MaxSessionCount of
		false ->
            {ok, Greeting} = application:get_env(?APP, smtp_greeting),
            Banner = [Domain, " ESMTP ", Greeting],
			{ok, Banner, #st{}};
		true ->
			?log_error("Max session count exceeded: ~p", [SessionCount]),
			{stop, normal, ["554 ", Domain, " is busy right now"]}
	end.

handle_HELO(_Peername, St) ->
    {ok, St}.

handle_EHLO(_Peername, Extensions, St) ->
    {ok, MaxMsgSize} = application:get_env(?APP, smtp_max_msg_size),
    Extensions2 =
        case MaxMsgSize of
            undefined ->
                proplists:delete("SIZE", Extensions);
            _ when is_integer(MaxMsgSize) ->
                [{"SIZE", integer_to_list(MaxMsgSize)} | proplists:delete("SIZE", Extensions)]
        end,
    {ok, Extensions2, St}.

handle_AUTH(_Type, _Username, _Password, St) ->
    {ok, St}.

handle_MAIL(_From, St) ->
    {ok, St}.

handle_MAIL_extension(Extension, _St) ->
	?log_debug("Unknown MAIL FROM extension: ~s", [Extension]),
    error.

handle_RCPT(_To, St) ->
    {ok, St}.

handle_RCPT_extension(Extension, _St) ->
	?log_debug("Unknown RCPT TO extension: ~s", [Extension]),
    error.

handle_DATA(From, To, Data, St) ->
    ?log_debug("Got an email (from: ~s, to: ~s)",
        [From, string:join([binary_to_list(A) || A <- To], ", ")]),
    try
        do_handle_DATA(From, To, Data, St)
    catch
        Exc:Cls ->
            ?log_error("Exception: ~p:~p", [Exc, Cls]),
            ?log_error("Probably too deep mime nesting met", []),
            {error, "554 MIME type not supported.", St}
    end.

handle_RSET(_St) ->
    #st{}.

handle_VRFY(Address, St) ->
    ?log_debug("Verify called: ~s", [Address]),
    {error, "252 VRFY disabled", St}.

handle_other(Verb, Arg, St) ->
    ?log_info("Unrecognized other command (Verb: ~s, Arg: ~s)", [Verb, Arg]),
    {"500 Error: verb not recognized", St}.

code_change(_OldVsn, St, _Extra) ->
    {ok, St}.

terminate(normal, St) ->
    {ok, normal, St};
terminate(Reason, St) ->
    ?log_error("Terminate failed with: ~p", [Reason]),
    {ok, Reason, St}.

%% ===================================================================
%% Internal
%% ===================================================================

do_handle_DATA(From, To, Data, St) ->
    {_Type, _Subtype, Headers, _Params, _Content} =
        Component = mimemail:decode(Data),
    UUID = uuid:unparse(uuid:generate()),
    {ok, UUID, St}.
