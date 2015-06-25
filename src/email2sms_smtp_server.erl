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
-include("email2sms_errors.hrl").
-include_lib("alley_common/include/logging.hrl").
-include_lib("alley_services/include/alley_services.hrl").

%-define(TEST, 1).
-ifdef(TEST).
    -include_lib("eunit/include/eunit.hrl").
    -compile(export_all).
-endif.

-type email() :: binary().
-type auth_schema() :: from_address
                     | subject
                     | to_address.

-record(st, {
    type :: binary(),
    subtype :: binary(),
    headers :: [{binary(), binary()}],
    params  :: [{binary(), term()}],
    content :: term(),
    recipients :: [email()],
    auth_schema :: auth_schema(),
    customer :: #auth_customer_v1{}
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
            {stop, normal, ?E_SERVER_BUSY}
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
    {error, ?E_NOT_RECOGNIZED, St}.

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
    Emails = collect_emails_from_fields(St#st.headers, Fields),
    Recipients = filter_recipients_using_domains(Emails, Domains),
    Count = length(Recipients),
    if
        Count =:= 0 ->
            {error, ?E_NO_RECIPIENTS, St};
        Count > MaxRecipients ->
            {error, ?E_TOO_MANY_RECIPIENTS, St};
        true ->
            handle_data(authenticate, St#st{recipients = Recipients})
    end;
handle_data(authenticate, St) ->
    {ok, Schemes} = application:get_env(?APP, auth_schemes),
    Methods = [
        {from_address, fun authenticate_from_address/1},
        {subject,      fun authenticate_subject/1},
        {to_address,   fun authenticate_to_address/1}
    ],
    Fun = fun
        ({Schema, Method}, next_schema) ->
            case lists:member(Schema, Schemes) of
                true ->
                    case Method(St) of
                        {ok, Customer} ->
                            {Schema, Customer};
                        {error, Reason} ->
                            ?log_debug("Authentication schema: ~p failed with: ~p",
                                [Schema, Reason]),
                            next_schema
                    end;
                false ->
                    next_schema
            end;
        ({_, _}, {Schema, Customer}) ->
            {Schema, Customer}
    end,
    case lists:foldl(Fun, next_schema, Methods) of
        next_schema ->
            {error, ?E_AUTHENTICATION, St};
        {Schema, Customer} ->
            St2 = St#st{
                auth_schema = Schema,
                customer = Customer
            },
            handle_data(check_coverage, St2)
    end;
handle_data(check_coverage, St) ->
    handle_data(prepare_body, St);
handle_data(prepare_body, St) ->
    handle_data(send, St);
handle_data(send, St) ->
    Customer = St#st.customer,
    CustomerUuid = Customer#auth_customer_v1.customer_uuid,
    UserId = Customer#auth_customer_v1.user_id,
    Originator = Customer#auth_customer_v1.default_source,
    Recipients = St#st.recipients,
    %{Encoding, NumType} = reformat_message_type(Req#'SendSms'.messageType),
    %Message = alley_services_utils:convert_arabic_numbers(Req#'SendSms'.smsText, NumType),
    Encoding = default,
    Message = <<"Hello from Email">>,
    Size = alley_services_utils:chars_size(Encoding, Message),
    Params = common_smpp_params(Customer) ++ [
        {esm_class, 3},
        {protocol_id, 0}
    ],
    Req = #send_req{
        customer = Customer,
        customer_uuid = CustomerUuid,
        user_id = UserId,
        interface = mm,
        originator = reformat_addr(Originator),
        recipients = reformat_addrs(Recipients),

        req_type = single,
        message = Message,
        encoding = Encoding,
        size = Size,
        params = Params
    },
    case alley_services_mt:send(Req) of
        {ok, Result} ->
            ?log_debug("Got submit result: ~p", [Result]),
            send_result(Result, St);
        {error, Error} ->
            ?log_error("Submit failed with: ~p", [Error]),
            send_result(#send_result{result = Error}, St)
    end.

send_result(#send_result{
    result = ok,
    req_id = ReqId,
    rejected = Rejected,
    customer = Customer,
    credit_left = _CreditLeft
}, St) ->
    {ok, ReqId, St};
send_result(#send_result{result = Result}, St) ->
    {error, "550 Send failed", St}.

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

collect_emails_from_fields(Headers, Fields) ->
    collect_emails_from_fields(Headers, Fields, []).

collect_emails_from_fields(_Headers, [], Acc) ->
    Acc;
collect_emails_from_fields(Headers, [F|Fs], Acc) ->
    Acc2 = Acc ++ proplists:get_value(F, Headers, []),
    collect_emails_from_fields(Headers, Fs, Acc2).

filter_recipients_using_domains(Emails, Domains) ->
    filter_recipients_using_domains(Emails, Domains, []).

filter_recipients_using_domains([], _Domains, Acc) ->
    lists:reverse(Acc);
filter_recipients_using_domains([E|Es], Domains, Acc) ->
    [Addr, Domain] = binary:split(E, <<"@">>),
    case lists:member(Domain, Domains) of
        true ->
            filter_recipients_using_domains(Es, Domains, [Addr|Acc]);
        false ->
            filter_recipients_using_domains(Es, Domains, Acc)
    end.

authenticate_from_address(St) ->
    {error, not_implemented}.

authenticate_subject(St) ->
    Subject = proplists:get_value(<<"subject">>, St#st.headers),
    case binary:split(Subject, <<":">>, [global]) of
        [CustomerId, UserId, Password] ->
            ?log_debug("CustomerId: ~p, UserId: ~p, Password: ~p",
                [CustomerId, UserId, Password]),
                case alley_services_auth:authenticate(CustomerId, UserId, mm, Password) of
                    {ok, #auth_resp_v1{result = #auth_customer_v1{} = Customer}} ->
                        {ok, Customer};
                    {ok, #auth_resp_v1{
                        result = #auth_error_v1{code = Error}}
                    } ->
                        ?log_error("Got failed auth response with: ~p", [Error]),
                        {error, Error};
                    {error, Error} ->
                        ?log_error("Auth failed with: ~p", [Error]),
                        {error, Error}
                end;
        _ ->
            {error, parse_subject}
    end.

authenticate_to_address(St) ->
    {error, not_implemented}.

common_smpp_params(Customer) ->
    ReceiptsAllowed = Customer#auth_customer_v1.receipts_allowed,
    NoRetry = Customer#auth_customer_v1.no_retry,
    Validity = alley_services_utils:fmt_validity(
        Customer#auth_customer_v1.default_validity),
    [
        {registered_delivery, ReceiptsAllowed},
        {service_type, <<>>},
        {no_retry, NoRetry},
        {validity_period, Validity},
        {priority_flag, 0}
    ].

reformat_addr(undefined) ->
    reformat_addr(<<"">>);
reformat_addr(Addr = #addr{}) ->
    Addr;
reformat_addr(Addr) ->
    alley_services_utils:addr_to_dto(Addr).

reformat_addrs(undefined) ->
    [];
reformat_addrs(Addrs) ->
    [alley_services_utils:addr_to_dto(Addr) || Addr <- Addrs].

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

collect_emails_from_fields_test() ->
    Headers = [{<<"to">>,[<<"to@m.c">>]},
               {<<"cc">>,[<<"cc@m.c">>]},
               {<<"bcc">>,[<<"bcc@m.c">>]}],
    Fields0 = [],
    FieldsCc = [<<"cc">>],
    FieldsAll = [<<"to">>, <<"cc">>, <<"bcc">>],
    ?assertEqual([], collect_emails_from_fields(Headers, Fields0)),
    ?assertEqual([<<"cc@m.c">>], collect_emails_from_fields(Headers, FieldsCc)),
    ?assertEqual([<<"to@m.c">>, <<"cc@m.c">>, <<"bcc@m.c">>], collect_emails_from_fields(Headers, FieldsAll)).

filter_recipients_using_domains_test() ->
    Emails = [<<"a@m.c">>, <<"b@n.c">>, <<"c@m.d">>, <<"d@n.d">>],
    Domains0 = [],
    Domains1 = [<<"m.c">>],
    Domains2 = [<<"n.c">>, <<"n.d">>, <<"n.e">>],
    ?assertEqual([], filter_recipients_using_domains(Emails, Domains0)),
    ?assertEqual([<<"a">>], filter_recipients_using_domains(Emails, Domains1)),
    ?assertEqual([<<"b">>, <<"d">>], filter_recipients_using_domains(Emails, Domains2)).

-endif.

%% ===================================================================
%% End Tests
%% ===================================================================
