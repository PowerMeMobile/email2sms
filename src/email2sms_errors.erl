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
format_error(no_recipients) ->
    ?E_NO_RECIPIENTS;
format_error(timeout) ->
    ?E_TIMEOUT;
format_error(server_busy) ->
    ?E_SERVER_BUSY;
format_error(Error) when is_atom(Error) ->
    atom_to_list(Error);
format_error(Error) when is_binary(Error) ->
    binary_to_list(Error);
format_error(Error) when is_list(Error) ->
    Error.
