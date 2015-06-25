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

%-define(TEST, 1).
-ifdef(TEST).
    -include_lib("eunit/include/eunit.hrl").
    -compile(export_all).
-endif.

-type email() :: binary().

-record(st, {
    type :: binary(),
    subtype :: binary(),
    headers :: [{binary(), binary()}],
    params  :: [{binary(), term()}],
    content :: term(),
    recipients :: [email()]
}).

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
    ?log_debug("Got an email (from: ~p, to: ~p)", [From, To]),

    {Type, Subtype, Headers, Params, Content} = mimemail:decode(Data),

    %% lower case keys.
    Headers2 = [{binstr:to_lower(K), V} || {K, V} <- Headers],

    %% use already cleaned up from.
    Headers3 = lists:keyreplace(<<"from">>, 1, Headers2, {<<"from">>, From}),

    %% cleanup to, cc and recover bcc.
    {To2, Cc, Bcc} = recover_to_cc_bcc(To, Headers3),
    Headers4 = lists:keyreplace(<<"to">>, 1, Headers3, {<<"to">>, To2}),
    Headers5 = lists:keyreplace(<<"cc">>, 1, Headers4, {<<"cc">>, Cc}),
    Headers6 = [{<<"bcc">>, Bcc} | Headers5],

    ?log_debug("~p", [Type]),
    ?log_debug("~p", [Subtype]),
    ?log_debug("~p", [Headers2]),
    ?log_debug("~p", [Headers6]),
    %?log_debug("~p", [Params]),
    %?log_debug("~p", [Content]),

    %ContentType = <<Type/binary, "/", Subtype/binary>>,

    St2 = St#st{
        type = Type,
        subtype = Subtype,
        headers = Headers6,
        params = Params,
        content = Content
    },

    handle_data(filter_recipients, St2).

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

handle_data(filter_recipients, St) ->
    {ok, Fields} = application:get_env(?APP, smtp_recipient_fields),
    {ok, Domains} = application:get_env(?APP, smtp_local_domains),
    {ok, MaxRecipients} = application:get_env(?APP, smtp_max_recipient_count),
    Recipients = collect_recipients_from_fields(St#st.headers, Fields),
    Recipients2 = filter_recipients_using_domains(Recipients, Domains),
    Count = length(Recipients2),
    if
        Count =:= 0 ->
            {error, "550 No valid recipients found", St};
        Count > MaxRecipients ->
            {error, "550 Too many recipients specified", St};
        true ->
            handle_data(authenticate_subject, St#st{recipients = Recipients2})
    end;
handle_data(authenticate_subject, St) ->
    {error, "502 Not implemented", St};
handle_data(prepare_body, St) ->
    {error, "502 Not implemented", St};
handle_data(send, St) ->

    UUID = uuid:unparse(uuid:generate()),
    {ok, UUID, St},
    {error, "502 Not implemented", St}.

recover_to_cc_bcc(All, Headers) ->
    To = parse_addresses(proplists:get_value(<<"to">>, Headers, [])),
    Cc = parse_addresses(proplists:get_value(<<"cc">>, Headers, [])),
    Bcc = (All -- To) -- Cc,
    {To, Cc, Bcc}.

%% get rid of possible names in form `"name" <address@host.domain>'
%% variations. only return `address@host.domain' parts
parse_addresses(AddrsRaw) ->
    {ok, AddrsParsed} = smtp_util:parse_rfc822_addresses(AddrsRaw),
    [list_to_binary(Addr) || {_Name, Addr} <- AddrsParsed].

collect_recipients_from_fields(Headers, Fields) ->
    collect_recipients_from_fields(Headers, Fields, []).

collect_recipients_from_fields(_Headers, [], Acc) ->
    Acc;
collect_recipients_from_fields(Headers, [F|Fs], Acc) ->
    Acc2 = Acc ++ proplists:get_value(F, Headers, []),
    collect_recipients_from_fields(Headers, Fs, Acc2).

filter_recipients_using_domains(Recipients, Domains) ->
    filter_recipients_using_domains(Recipients, Domains, []).

filter_recipients_using_domains([], _Domains, Acc) ->
    lists:reverse(Acc);
filter_recipients_using_domains([R|Rs], Domains, Acc) ->
    [_Addr, Domain] = binary:split(R, <<"@">>),
    case lists:member(Domain, Domains) of
        true ->
            filter_recipients_using_domains(Rs, Domains, [R|Acc]);
        false ->
            filter_recipients_using_domains(Rs, Domains, Acc)
    end.

%% ===================================================================
%% Begin Tests
%% ===================================================================

-ifdef(TEST).

parse_addresses_test() ->
    ?assertEqual([<<"to@m.c">>],
        parse_addresses(<<"\"to\" <to@m.c>">>)),
    ?assertEqual([<<"to@m.c">>],
        parse_addresses(<<"\"to@m.c\" <to@m.c>">>)),
    ?assertEqual([<<"to@m.c">>],
        parse_addresses(<<"<to@m.c>">>)),
    ?assertEqual([<<"to@m.c">>],
        parse_addresses(<<"to@m.c">>)),
    ?assertEqual([<<"to@m.c">>, <<"to2@m.c">>, <<"to3@m.c">>, <<"to4@m.c">>],
        parse_addresses(
            <<"\"to\" <to@m.c>,\"to2@m.c\" <to2@m.c>,<to3@m.c>,to4@m.c">>)).

recover_to_cc_bcc_test() ->
    ?assertEqual({[], [], []}, recover_to_cc_bcc([], [])),
    ?assertEqual({[<<"to@m.c">>], [<<"cc@m.c">>], [<<"bcc@m.c">>]},
        recover_to_cc_bcc(
            [<<"to@m.c">>, <<"cc@m.c">>, <<"bcc@m.c">>],
            [{<<"to">>,<<"to@m.c">>},
             {<<"cc">>,<<"cc@m.c">>}])).

collect_recipients_from_fields_test() ->
    Headers = [{<<"to">>,[<<"to@m.c">>]},
               {<<"cc">>,[<<"cc@m.c">>]},
               {<<"bcc">>,[<<"bcc@m.c">>]}],
    Fields0 = [],
    FieldsCc = [<<"cc">>],
    FieldsAll = [<<"to">>, <<"cc">>, <<"bcc">>],
    ?assertEqual([], collect_recipients_from_fields(Headers, Fields0)),
    ?assertEqual([<<"cc@m.c">>], collect_recipients_from_fields(Headers, FieldsCc)),
    ?assertEqual([<<"to@m.c">>, <<"cc@m.c">>, <<"bcc@m.c">>], collect_recipients_from_fields(Headers, FieldsAll)).

filter_recipients_using_domains_test() ->
    Recipients = [<<"a@m.c">>, <<"b@n.c">>, <<"c@m.d">>, <<"d@n.d">>],
    Domains0 = [],
    Domains1 = [<<"m.c">>],
    Domains2 = [<<"n.c">>, <<"n.d">>, <<"n.e">>],
    ?assertEqual([], filter_recipients_using_domains(Recipients, Domains0)),
    ?assertEqual([<<"a@m.c">>], filter_recipients_using_domains(Recipients, Domains1)),
    ?assertEqual([<<"b@n.c">>, <<"d@n.d">>], filter_recipients_using_domains(Recipients, Domains2)).

-endif.

%% ===================================================================
%% End Tests
%% ===================================================================
