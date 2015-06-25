-ifndef(email2sms_errors_hrl).
-define(email2sms_errors_hrl, defined).

-define(E_AUTHENTICATION,      "550 Invalid user account").
-define(E_INTERNAL,            "554 Internal server error").
-define(E_NOT_IMPLEMENTED,     "502 Not implemented").
-define(E_TIMEOUT,             "554 Request timeout").
-define(E_NO_RECIPIENTS,       "550 No valid recipients found").
-define(E_TOO_MANY_RECIPIENTS, "550 Too many recipients specified").
-define(E_SERVER_BUSY,         "554 Server is busy").
-define(E_NOT_RECOGNIZED,      "500 Not recognized").

-endif.
