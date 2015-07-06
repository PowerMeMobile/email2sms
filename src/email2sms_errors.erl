-module(email2sms_errors).

-include("email2sms_errors.hrl").

-export([
    format_error/1
]).

%% ===================================================================
%% API
%% ===================================================================

-spec format_error(atom() | binary() | list()) -> list().
format_error(invalid_credentials) ->
    ?E_AUTHENTICATION;
format_error(originator_not_found) ->
    ?E_NO_ORIGINATOR;
format_error(no_recipients) ->
    ?E_NO_RECIPIENTS;
format_error(no_dest_addrs) ->
    ?E_NO_RECIPIENTS;
format_error(timeout) ->
    ?E_TIMEOUT;
format_error(server_busy) ->
    ?E_SERVER_BUSY;
format_error(send_failed) ->
    ?E_SEND_FAILED;
format_error(invalid_recipient_policy) ->
    ?E_INVALID_RECIPIENT_POLICY;
format_error(credit_limit_exceeded) ->
    ?E_CREDIT_LIMIT_EXCEEDED;
format_error(Error) when is_atom(Error) ->
    ["550 ", atom_to_list(Error)];
format_error(Error) when is_binary(Error) ->
    ["550 ", binary_to_list(Error)];
format_error(Error) when is_list(Error) ->
    ["550 ", Error].
