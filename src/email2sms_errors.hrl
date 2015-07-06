-ifndef(email2sms_errors_hrl).
-define(email2sms_errors_hrl, defined).

-define(E_AUTHENTICATION,           "550 Invalid user account").
-define(E_INTERNAL,                 "554 Internal server error").
-define(E_NOT_IMPLEMENTED,          "502 Not implemented").
-define(E_TIMEOUT,                  "554 Request timeout").
-define(E_NO_ORIGINATOR,            "550 Originator is not found").
-define(E_NO_RECIPIENTS,            "550 No valid recipients found").
-define(E_TOO_MANY_RECIPIENTS,      "550 Too many recipients specified").
-define(E_SERVER_BUSY,              "554 Server is busy").
-define(E_NOT_RECOGNIZED,           "500 Not recognized").
-define(E_TOO_MANY_PARTS,           "550 Too many SMS parts").
-define(E_UNKNOWN_CONTENT_TYPE,     "550 Unknown content type").
-define(E_SEND_FAILED,              "550 Send failed").
-define(E_INVALID_RECIPIENT_POLICY, "550 Rejected by invalid recipient policy").
-define(E_CREDIT_LIMIT_EXCEEDED,    "550 Customer's credit limit is exceeded").

-endif.
