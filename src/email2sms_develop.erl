-module(email2sms_develop).

-export([init/0]).

-spec init() -> ok.
init() ->
    %% disabled lager until included to the project
    %lager:set_loglevel(lager_console_backend, debug),
    ok = application:ensure_started(sync).
