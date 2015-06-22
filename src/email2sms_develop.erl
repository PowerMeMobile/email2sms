-module(email2sms_develop).

-export([init/0]).

-spec init() -> ok.
init() ->
    lager:set_loglevel(lager_console_backend, debug),
    ok = application:ensure_started(sync).
