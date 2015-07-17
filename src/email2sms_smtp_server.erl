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
    remote_ip :: inet:ip_address(),
    remote_host :: binary(),
    orig_data :: binary(),
    type :: binary(),
    subtype :: binary(),
    headers :: [{binary(), binary()}],
    params  :: [{binary(), term()}],
    content :: term(),
    all_recipients :: [email()],
    recipients :: [email()],
    auth_schema :: auth_schema(),
    customer :: #auth_customer_v2{} | [#auth_customer_v2{}],
    message :: binary(),
    encoding :: default | ucs2,
    size :: pos_integer()
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
            {ok, Vsn} = application:get_key(?APP, vsn),
            Banner = [Domain, " ESMTP ", Greeting, " ", Vsn],
            {ok, Banner, #st{remote_ip = PeerAddr}};
        true ->
            ?log_error("Max session count exceeded: ~p", [SessionCount]),
            {stop, normal, ?E_SERVER_BUSY}
    end.

handle_HELO(Hostname, St) ->
    {ok, MaxMsgSize} = application:get_env(?APP, smtp_max_msg_size),
    case MaxMsgSize of
        undefined ->
            {ok, St#st{remote_host = Hostname}};
        _ when is_integer(MaxMsgSize) ->
            {ok, MaxMsgSize, St#st{remote_host = Hostname}}
    end.

handle_EHLO(Hostname, Extensions, St) ->
    {ok, MaxMsgSize} = application:get_env(?APP, smtp_max_msg_size),
    Extensions2 =
        case MaxMsgSize of
            undefined ->
                proplists:delete("SIZE", Extensions);
            _ when is_integer(MaxMsgSize) ->
                [{"SIZE", integer_to_list(MaxMsgSize)} | proplists:delete("SIZE", Extensions)]
        end,
    {ok, Extensions2, St#st{remote_host = Hostname}}.

handle_AUTH(_Type, _Username, _Password, St) ->
    {ok, St}.

handle_MAIL(_From, St) ->
    {ok, St}.

handle_MAIL_extension(Extension, _St) ->
    ?log_debug("Unknown MAIL FROM extension: ~s", [Extension]),
    error.

handle_RCPT(_To, St) ->
    %% because of to the smtp_recipient_fields setting,
    %% it's impossible to filter out the non-local addresses here,
    %% as the actual field name is unknown at this stage.
    {ok, St}.

handle_RCPT_extension(Extension, _St) ->
    ?log_debug("Unknown RCPT TO extension: ~s", [Extension]),
    error.

handle_DATA(From, To, Data, St) ->
    ?log_debug("Got an email (from: ~p, to: ~p)", [From, To]),

    ReqTime = calendar:universal_time(),
    Res =
        try handle_data(From, To, Data, St)
        catch
            Class:Error ->
                Stacktrace = erlang:get_stacktrace(),
                ?log_error("Exception: ~p:~p Stacktrace: ~p",
                    [Class, Error, Stacktrace]),
                {error, ?E_INTERNAL, St}
        end,


    RespTime = calendar:universal_time(),
    {_, Message, _} = Res,
    alley_services_smtp_logger:log(
        St#st.remote_ip, St#st.remote_host,
        From, bstr:join(To, <<",">>),
        ReqTime, Data,
        RespTime, Message),

    Res.

handle_RSET(_St) ->
    #st{}.

handle_VRFY(Address, St) ->
    ?log_debug("Verify called: ~s", [Address]),
    {error, "252 VRFY disabled", St}.

handle_other(Verb, Arg, St) ->
    ?log_info("Unrecognized other command (Verb: ~p, Arg: ~p)", [Verb, Arg]),
    {?E_NOT_RECOGNIZED, St}.

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

handle_data(From, To, Data, St) ->
    {Type, Subtype, Headers, Params, Content} =
        lower_case(mimemail:decode(Data)),

    %% use already cleaned up from.
    Headers2 = lists:keyreplace(<<"from">>, 1, Headers, {<<"from">>, From}),

    %% cleanup to, cc and recover bcc.
    {To2, Cc, Bcc} = recover_to_cc_bcc(To, Headers2),
    Headers3 = lists:keyreplace(<<"to">>, 1, Headers2, {<<"to">>, To2}),
    Headers4 = lists:keyreplace(<<"cc">>, 1, Headers3, {<<"cc">>, Cc}),
    Headers5 = [{<<"bcc">>, Bcc} | Headers4],

    ?log_debug("~p/~p", [Type, Subtype]),
    ?log_debug("~p", [Headers5]),
    ?log_debug("~p", [Params]),
    ?log_debug("~p", [Content]),

    St2 = St#st{
        orig_data = Data,
        type = Type,
        subtype = Subtype,
        headers = Headers5,
        params = Params,
        content = Content,
        all_recipients = To
    },

   handle_data(filter_recipients_by_fields, St2).

handle_data(filter_recipients_by_fields, St) ->
    {ok, Fields} = application:get_env(?APP, smtp_recipient_fields),
    Recipients = collect_recipients_from_fields(St#st.headers, Fields),
    if
        length(Recipients) =:= 0 ->
            ?log_error("No recipients left after filtering by fields", []),
            {error, ?E_NO_RECIPIENTS, St};
        true ->
            handle_data(filter_recipients_by_domains, St#st{
                recipients = Recipients
            })
    end;

handle_data(filter_recipients_by_domains, St) ->
    {ok, Domains} = application:get_env(?APP, smtp_local_domains),
    Recipients = St#st.recipients,
    Recipients2 = filter_recipients_using_domains(Recipients, Domains),
    if
        length(Recipients2) =:= 0 ->
            ?log_error("No recipients left after filtering by domains", []),
            {error, ?E_NO_RECIPIENTS, St};
        true ->
            handle_data(check_max_recipient_count, St#st{
                recipients = Recipients2
            })
    end;

handle_data(check_max_recipient_count, St) ->
    {ok, MaxRecipients} = application:get_env(?APP, smtp_max_recipient_count),
    Recipients = St#st.recipients,
    if
        length(Recipients) > MaxRecipients ->
            ?log_error("Too many recipients", []),
            {error, ?E_TOO_MANY_RECIPIENTS, St};
        true ->
            handle_data(decode_message, St)
    end;

handle_data(decode_message, St) ->
    Type    = St#st.type,
    Subtype = St#st.subtype,
    Headers = St#st.headers,
    Params  = St#st.params,
    Content = St#st.content,
    case decode_message(Type, Subtype, Headers, Params, Content) of
        {ok, Message} ->
            Message2 = cleanup_message(Message),
            {ok, Encoding} = alley_services_utils:guess_encoding(Message),
            handle_data(check_parts_count, St#st{
                message = Message2,
                encoding = Encoding
            });
        {error, unknown_content_type} ->
            {error, ?E_UNKNOWN_CONTENT_TYPE, St}
    end;

handle_data(check_parts_count, St) ->
    {ok, MaxMsgParts} =
        application:get_env(?APP, max_msg_parts),

    Message = St#st.message,
    Encoding = St#st.encoding,
    Size = alley_services_utils:chars_size(Encoding, Message),
    MsgParts = alley_services_utils:calc_parts_number(Size, Encoding),
    case MsgParts =< MaxMsgParts of
        true ->
            handle_data(authenticate, St#st{size = Size});
        false ->
            {error, ?E_TOO_MANY_PARTS, St}
    end;

handle_data(authenticate, St) ->
    {ok, Schemes} = application:get_env(?APP, auth_schemes),
    Methods = [
        {from_address, fun authenticate_from_address/1},
        {subject,      fun authenticate_subject/1},
        {to_address,   fun authenticate_to_address/1}
    ],
    Fun = fun
        (Schema, next_schema) ->
            case proplists:get_value(Schema, Methods) of
                undefined ->
                    next_schema;
                Method ->
                    case Method(St) of
                        {ok, Result} ->
                            {Schema, Result};
                        {error, Reason} ->
                            ?log_debug("Auth schema: ~p failed with: ~p",
                                [Schema, Reason]),
                            next_schema
                    end
            end;
        (_, {Schema, Result}) ->
            {Schema, Result}
    end,
    case lists:foldl(Fun, next_schema, Schemes) of
        next_schema ->
            {error, ?E_AUTHENTICATION, St};
        {Schema, {Customers, BadRecipients}} ->
            Recipients = St#st.recipients -- BadRecipients,
            if
                length(Recipients) =:= 0 ->
                    ?log_error("No recipients left after to_address auth", []),
                    {error, ?E_NO_RECIPIENTS, St};
                true ->
                    St2 = St#st{
                        auth_schema = Schema,
                        customer = Customers,
                        recipients = Recipients
                    },
                    handle_data(filter_recipients_by_coverage, St2)
            end;
        {Schema, Customer} ->
            St2 = St#st{
                auth_schema = Schema,
                customer = Customer
            },
            handle_data(filter_recipients_by_coverage, St2)
    end;

handle_data(filter_recipients_by_coverage, St) when St#st.auth_schema =:= to_address ->
    Cs = St#st.customer,
    Rs = St#st.recipients,

    CheckFun = fun(Customer, Recipient) ->
        Tab = ets:new(coverage_tab, [private]),
        fill_coverage_tab(Customer, Tab),
        Routable = is_recipient_routable(Recipient, Tab),
        ets:delete(Tab),
        Routable
    end,

    CsRs = lists:zip(Cs, Rs),
    CsRs2 = [{C, R} || {C, R} <- CsRs, CheckFun(C, R)],
    {Cs2, Rs2} = lists:unzip(CsRs2),

    if
        length(Rs2) =:= 0 ->
            ?log_error("No recipients left after filtering by coverage", []),
            {error, ?E_NO_RECIPIENTS, St};
        true ->
            handle_data(check_invalid_recipient_policy, St#st{
                customer = Cs2,
                recipients = Rs2
            })
    end;
handle_data(filter_recipients_by_coverage, St) ->
    Customer = St#st.customer,
    Recipients = St#st.recipients,

    Tab = ets:new(coverage_tab, [private]),
    fill_coverage_tab(Customer, Tab),
    Recipients2 = [R || R <- Recipients, is_recipient_routable(R, Tab)],
    ets:delete(Tab),

    if
        length(Recipients2) =:= 0 ->
            ?log_error("No recipients left after filtering by coverage", []),
            {error, ?E_NO_RECIPIENTS, St};
        true ->
            handle_data(check_invalid_recipient_policy, St#st{
                recipients = Recipients2
            })
    end;

handle_data(check_invalid_recipient_policy, St) ->
    {ok, InvalidRecipientPolicy} =
        application:get_env(?APP, invalid_recipient_policy),

    All = St#st.all_recipients,
    Accepted = St#st.recipients,
    RejectedCount = length(All -- Accepted),

    case InvalidRecipientPolicy of
        reject_message when RejectedCount =/= 0 ->
            ?log_error("Message rejected by reject_message policy", []),
            {error, ?E_INVALID_RECIPIENT_POLICY, St};
        ignore_invalid ->
            handle_data(send, St);
        notify_invalid ->
            handle_data(send, St)
    end;

handle_data(send, St) when St#st.auth_schema =:= to_address ->
    Cs = St#st.customer,
    Rs = [msisdn_from_email(R) || R <- St#st.recipients],
    Msg = St#st.message,
    Enc = St#st.encoding,
    Size = St#st.size,
    Res = [send_message_throttled(St#st.auth_schema, C, [R], Msg, Enc, Size) ||
            {C, R} <- lists:zip(Cs, Rs)],
    ReqIds = [ReqId || {ok, #send_result{result = ok, req_id = ReqId}} <- Res],
    case ReqIds of
        [] ->
            send_result(#send_result{result = send_failed}, St);
        _ ->
            ReqIds2 = bstr:join(ReqIds, <<",">>),
            send_result(#send_result{result = ok, req_id = ReqIds2}, St)
    end;
handle_data(send, St) ->
    Customer = St#st.customer,
    Recipients = [msisdn_from_email(R) || R <- St#st.recipients],
    Msg = St#st.message,
    Enc = St#st.encoding,
    Size = St#st.size,
    case send_message_throttled(
            St#st.auth_schema, Customer, Recipients, Msg, Enc, Size) of
        {ok, Result} ->
            send_result(Result, St);
        {error, Error} ->
            send_result(#send_result{result = Error}, St)
    end.

fill_coverage_tab(Customer, CoverageTab) ->
    Networks = Customer#auth_customer_v2.networks,
    Providers = Customer#auth_customer_v2.providers,
    DefProvId = Customer#auth_customer_v2.default_provider_id,
    alley_services_coverage:fill_coverage_tab(
        Networks, Providers, DefProvId, CoverageTab).

is_recipient_routable(Email, CoverageTab) ->
    Addr = msisdn_from_email(Email),
    case alley_services_coverage:which_network(Addr, CoverageTab) of
        undefined ->
            false;
        {_NetId, _DestAddr2, _ProvId, _Price} ->
            true
    end.

send_message_throttled(AuthSchema, Customer, Recipients, Message, Encoding, Size) ->
    Prefix =
        case AuthSchema of
            to_address -> inbound;
            _          -> outbound
        end,
    CustomerId = Customer#auth_customer_v2.customer_id,
    OutboundRps = Customer#auth_customer_v2.rps,
    {ok, InboundRps} = application:get_env(?APP, inbound_rps_per_user),

    QName = {Prefix, CustomerId},
    case {Prefix, jobs:queue_info(QName, rate_limit)}  of
        {outbound, undefined} ->
            jobs:add_queue(QName, [
                {max_time, 1000},
                {rate, [{limit, OutboundRps}]}
            ]);
        {outbound, Rate} when OutboundRps =/= Rate ->
            jobs:modify_regulator(rate, QName, {rate, QName, 1}, [
                {limit, OutboundRps}
            ]);
        {inbound, undefined} ->
            jobs:add_queue(QName, [
                {max_time, 1000},
                {rate, [{limit, InboundRps}]}
            ]);
        {inbound, Rate} when InboundRps =/= Rate ->
            jobs:modify_regulator(rate, QName, {rate, QName, 1}, [
                {limit, InboundRps}
            ]);
        _ ->
            nop
    end,

    case jobs:ask({Prefix, CustomerId}) of
        {ok, _JobId} ->
            send_message(Customer, Recipients, Message, Encoding, Size);
        {error, rejected} ->
            {error, throttled};
        {error, timeout} ->
            {error, throttled}
    end.

send_message(Customer, Recipients, Message, Encoding, Size) ->
    CustomerUuid = Customer#auth_customer_v2.customer_uuid,
    UserId = Customer#auth_customer_v2.user_id,
    Originator = Customer#auth_customer_v2.default_source,

    Params = common_smpp_params(Customer) ++ [
        {esm_class, 3},
        {protocol_id, 0}
    ],
    Req = #send_req{
        customer = Customer,
        customer_uuid = CustomerUuid,
        user_id = UserId,
        interface = email,
        originator = Originator,
        recipients = Recipients,

        req_type = single,
        message = Message,
        encoding = Encoding,
        size = Size,
        params = Params
    },
    case alley_services_mt:send(Req) of
        {ok, Result} ->
            ?log_debug("Got submit result: ~p", [Result]),
            {ok, Result};
        {error, Error} ->
            ?log_error("Submit failed with: ~p", [Error]),
            {error, Error}
    end.

send_result(#send_result{result = ok, req_id = ReqId}, St) ->
    {ok, InvalidRecipientPolicy} =
        application:get_env(?APP, invalid_recipient_policy),

    case InvalidRecipientPolicy of
        ignore_invalid ->
            nop;
        notify_invalid ->
            All = St#st.all_recipients,
            Accepted = St#st.recipients,
            Rejected = All -- Accepted,
            if
                length(Rejected) > 0 ->
                    From = proplists:get_value(<<"from">>, St#st.headers),
                    MsgId = proplists:get_value(<<"message-id">>, St#st.headers, <<"N/A">>),
                    Data = St#st.orig_data,
                    notify_rejected(From, MsgId, Data, Rejected);
                true ->
                    nop
            end
    end,

    {ok, ReqId, St};
send_result(#send_result{result = Result}, St) ->
    {error, email2sms_errors:format_error(Result), St}.

%% https://www.ietf.org/rfc/rfc3461.txt
notify_rejected(Notifee, MsgId, Data, RejectedAddrs) ->
    ?log_debug("Notify: ~p recipients rejected : ~p", [Notifee, RejectedAddrs]),
    {ok, Postmaster} = application:get_env(?APP, smtp_postmaster),
    {ok, Opts} = application:get_env(?APP, smtp_client_opts),

    Email = {
        Postmaster,
        [Notifee],
        mimemail:encode({
            <<"text">>, <<"plain">>, [
                {<<"Subject">>, <<"Delivery failure for ", (binstr:join(RejectedAddrs, <<", ">>))/binary>>},
                {<<"From">>, Postmaster},
                {<<"To">>, Notifee}
            ],
            [],
            <<"Your message (id ", MsgId/binary, ") could not be delivered to:",
              "\r\n",
              "\r\n\t",
              (binstr:join(RejectedAddrs, <<"\r\n\t">>))/binary,
              "\r\n",
              "\r\n",
              "----- Original message -----",
              "\r\n",
              "\r\n",
              Data/binary>>
        })
    },
    Callback =
        fun({ok, Res}) ->
            ?log_debug("Notify: ~p succeeded with: ~p", [Notifee, Res]);
           (Error) ->
            ?log_error("Notify: ~p failed with: ~p", [Notifee, Error])
        end,
    gen_smtp_client:send(Email, Opts, Callback).

lower_case({Type, Subtype, Headers, Params, Content})
        when Type =:= <<"multipart">> ->
    Headers2 = [{bstr:lower(K), V} || {K, V} <- Headers],
    Params2 =  [{bstr:lower(K), V} || {K, V} <- Params],
    Content2 = [lower_case(C) || C <- Content],
    {Type, Subtype, Headers2, Params2, Content2};
lower_case({Type, Subtype, Headers, Params, Content}) ->
    Headers2 = [{bstr:lower(K), V} || {K, V} <- Headers],
    Params2 =  [{bstr:lower(K), V} || {K, V} <- Params],
    {Type, Subtype, Headers2, Params2, Content}.

recover_to_cc_bcc(All, Headers) ->
    {ok, To} = parse_addresses(proplists:get_value(<<"to">>, Headers, [])),
    {ok, Cc} = parse_addresses(proplists:get_value(<<"cc">>, Headers, [])),
    Bcc = (All -- To) -- Cc,
    {To, Cc, Bcc}.

%% get rid of possible names in form `"name" <address@domain>'
%% variations. only return `address@domain' parts
parse_addresses(AddrsRaw) ->
    case smtp_util:parse_rfc822_addresses(AddrsRaw) of
        {ok, AddrsParsed} ->
            {ok, [list_to_binary(Addr) || {_Name, Addr} <- AddrsParsed]};
        {error, Reason} ->
            ?log_error("parse_rfc822_addresses: ~p failed with: ~p", [AddrsRaw, Reason]),
            case re:replace(AddrsRaw, "\"", "", [global, {return, binary}]) of
                AddrsRaw ->
                    {error, Reason};
                AddrsRaw2 ->
                    parse_addresses(AddrsRaw2)
            end
    end.

collect_recipients_from_fields(Headers, Fields) ->
    collect_recipients_from_fields(Headers, Fields, []).

collect_recipients_from_fields(_Headers, [], Acc) ->
    Acc;
collect_recipients_from_fields(Headers, [F|Fs], Acc) ->
    Acc2 = Acc ++ proplists:get_value(F, Headers, []),
    collect_recipients_from_fields(Headers, Fs, Acc2).

filter_recipients_using_domains(Emails, Domains) ->
    filter_recipients_using_domains(Emails, Domains, []).

filter_recipients_using_domains([], _Domains, Acc) ->
    lists:reverse(Acc);
filter_recipients_using_domains([E|Es], Domains, Acc) ->
    [_Addr, Domain] = binary:split(E, <<"@">>),
    case lists:member(Domain, Domains) of
        true ->
            filter_recipients_using_domains(Es, Domains, [E|Acc]);
        false ->
            filter_recipients_using_domains(Es, Domains, Acc)
    end.

authenticate_from_address(St) ->
    ?log_debug("Auth schema: from_address", []),
    From = proplists:get_value(<<"from">>, St#st.headers),
    case alley_services_auth:authenticate_by_email(From, email) of
        {ok, #auth_resp_v2{result = #auth_customer_v2{} = Customer}} ->
            {ok, Customer};
        {ok, #auth_resp_v2{result = #auth_error_v2{code = Error}}} ->
            ?log_error("Got failed auth response with: ~p", [Error]),
            {error, Error};
        {error, Error} ->
            ?log_error("Auth failed with: ~p", [Error]),
            {error, Error}
    end.

authenticate_subject(St) ->
    ?log_debug("Auth schema: subject", []),
    Subject = proplists:get_value(<<"subject">>, St#st.headers, <<>>),
    case binary:split(Subject, <<":">>, [global]) of
        [CustomerId, UserId, Password] ->
            ?log_debug("CustomerId: ~p, UserId: ~p, Password: ~p",
                [CustomerId, UserId, Password]),
                case alley_services_auth:authenticate(CustomerId, UserId, Password, email) of
                    {ok, #auth_resp_v2{result = #auth_customer_v2{} = Customer}} ->
                        {ok, Customer};
                    {ok, #auth_resp_v2{result = #auth_error_v2{code = Error}}} ->
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
    ?log_debug("Auth schema: to_address", []),
    Recipients = St#st.recipients,
    Res = [{R, authenticate_by_msisdn(R)} || R <- Recipients],
    Customers = [C || {_R, {ok, #auth_customer_v2{} = C}} <- Res],
    BadRecipients = [R || {R, {error, _}} <- Res],
    case Customers of
        [] ->
            {error, no_recipients};
        _ ->
            {ok, {Customers, BadRecipients}}
    end.

authenticate_by_msisdn(Email) ->
    Msisdn = msisdn_from_email(Email),
    case alley_services_auth:authenticate_by_msisdn(Msisdn, email) of
        {ok, #auth_resp_v2{result = #auth_customer_v2{} = Customer}} ->
            Features = Customer#auth_customer_v2.features,
            case check_feature(<<"sms_from_email">>, Features) of
                allow ->
                    {ok, Customer};
                denied ->
                    ?log_error("Not allowed SMS from Email", []),
                    {error, wrong_interface}
            end;
        {ok, #auth_resp_v2{result = #auth_error_v2{code = Error}}} ->
            ?log_error("Got failed auth response with: ~p", [Error]),
            {error, Error};
        {error, Error} ->
            ?log_error("Auth failed with: ~p", [Error]),
            {error, Error}
    end.

check_feature(Feature, Features) ->
    case lists:keyfind(Feature, #feature_v1.name, Features) of
        #feature_v1{value = <<"true">>} ->
            allow;
        _ ->
            denied
    end.

common_smpp_params(Customer) ->
    ReceiptsAllowed = Customer#auth_customer_v2.receipts_allowed,
    NoRetry = Customer#auth_customer_v2.no_retry,
    Validity = alley_services_utils:fmt_validity(
        Customer#auth_customer_v2.default_validity),
    [
        {registered_delivery, ReceiptsAllowed},
        {service_type, <<>>},
        {no_retry, NoRetry},
        {validity_period, Validity},
        {priority_flag, 0}
    ].

msisdn_from_email(Email) ->
    [Addr, _Domain] = binary:split(Email, <<"@">>),
    reformat_addr(Addr).

reformat_addr(undefined) ->
    reformat_addr(<<"">>);
reformat_addr(Addr = #addr{}) ->
    Addr;
reformat_addr(Addr) ->
    alley_services_utils:addr_to_dto(Addr).

decode_message(<<"text">>, <<"plain">>, _Headers, _Params, Content) ->
    {ok, Content};

decode_message(<<"text">>, <<"html">>, _Headers, _Params, Content) ->
    Content2 = re:replace(Content, "<[^>]*>", "", [global, {return, list}]),
    %?log_debug("~p", [Content2]),
    Content3 = re:replace(Content2, "\\s+", "", [global, {return, list}]),
    %?log_debug("~p", [Content3]),
    Content4 = http_uri:decode(Content3),
    %?log_debug("~p", [Content4]),
    {ok, list_to_binary(Content4)};

decode_message(<<"multipart">>, _, _, _, []) ->
    {error, unknown_content_type};
decode_message(<<"multipart">> = Type, Subtype, Headers, Params, [C|Cs]) ->
    ?log_debug("~p", [C]),
    {CType, CSubtype, CHeaders, CParams, CContent} = C,
    case decode_message(CType, CSubtype, CHeaders, CParams, CContent) of
        {ok, Message} ->
            {ok, Message};
        {error, Error} ->
            ?log_debug("decode_message failed with: ~p", [Error]),
            decode_message(Type, Subtype, Headers, Params, Cs)
    end;

decode_message(_Type, _Subtype, _Headers, _Params, _Content) ->
    {error, unknown_content_type}.

cleanup_message(Message) ->
    cleanup_message(Message, [<<"----">>, <<"Disclaimer">>]).

cleanup_message(Message, []) ->
    bstr:strip(Message);
cleanup_message(Message, [S|Ss]) ->
    case binary:split(Message, S) of
        [Message2|_] ->
            cleanup_message(Message2, Ss);
        Message ->
            cleanup_message(Message, Ss)
    end.

%% ===================================================================
%% Begin Tests
%% ===================================================================

-ifdef(TEST).

parse_addresses_test() ->
    ?assertEqual({ok, [<<"to@m.c">>]},
        parse_addresses(<<"\"to\" <to@m.c>">>)),
    ?assertEqual({ok, [<<"to@m.c">>]},
        parse_addresses(<<"\"to@m.c\" <to@m.c>">>)),
    ?assertEqual({ok, [<<"to@m.c">>]},
        parse_addresses(<<"<to@m.c>">>)),
    ?assertEqual({ok, [<<"to@m.c">>]},
        parse_addresses(<<"to@m.c">>)),
    ?assertEqual({ok, [<<"to@m.c">>, <<"to2@m.c">>, <<"to3@m.c">>, <<"to4@m.c">>]},
        parse_addresses(
            <<"\"to\" <to@m.c>,\"to2@m.c\" <to2@m.c>,<to3@m.c>,to4@m.c">>)),
    %% Paste to Thinderbird: 123@tam.xyz; 456@mail.com
    ?assertEqual({ok, [<<"123@tam.xyz">>, <<"456@mail.com">>]},
        parse_addresses(<<"\"123\"@tam.xyz, 456@mail.com">>)).

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
    Emails = [<<"a@m.c">>, <<"b@n.c">>, <<"c@m.d">>, <<"d@n.d">>],
    Domains0 = [],
    Domains1 = [<<"m.c">>],
    Domains2 = [<<"n.c">>, <<"n.d">>, <<"n.e">>],
    ?assertEqual([], filter_recipients_using_domains(Emails, Domains0)),
    ?assertEqual([<<"a@m.c">>], filter_recipients_using_domains(Emails, Domains1)),
    ?assertEqual([<<"b@n.c">>, <<"d@n.d">>], filter_recipients_using_domains(Emails, Domains2)).

-endif.

%% ===================================================================
%% End Tests
%% ===================================================================
