-module(eauth_utils).
-author('@m-2k').

-include("eauth.hrl").
-compile(export_all).


utf8_to_list(Bin) -> unicode:characters_to_list(Bin,utf8).
list_to_utf8(List) -> unicode:characters_to_binary(List,utf8,utf8).

to_lower(Bin) when is_binary(Bin) -> list_to_utf8(ux_string:to_lower(utf8_to_list(Bin)));
to_lower(List) -> ux_string:to_lower(List).

strip(Bin) -> re:replace(Bin, re(strip), <<>>, [global,{return,binary}]).

re(mail) -> {ok,Re}=re:compile(wf:config(eauth,email_regexp,?EMAIL_REGEXP)),Re;
re(strip) -> {ok,Re}=re:compile(<<"(^\\s+)|(\\s+$)">>),Re.

email_validation(Email) when is_binary(Email) ->
    Email2=to_lower(strip(Email)),
    case re:run(Email2,re(mail)) of
        {match,_} -> {ok,Email2};
        _ -> {error,Email2}
    end.

wait() ->
    timer:sleep(case wf:config(eauth,wrong_delay) of D when is_integer(D) andalso D > 0 -> D; _ -> ?WRONG_DELAY end).

password_hash(Pass,Salt) ->
    SaltLocal=wf:config(eauth,salt_local,?SALT_LOCAL),
    crypto:hash(wf:config(eauth,hash_algorithm,?HASH_ALGORITHM),list_to_binary([Pass,Salt,SaltLocal])).

password() -> password(wf:config(eauth,password_length,?PASSWORD_LENGTH)).
password(Length) -> password(Length,wf:config(eauth,password_symbols,?PASSWORD_SYMBOLS)).
password(Length,Symbols) ->
    Count=size(Symbols),
    << << (binary:at(Symbols,rand:uniform(Count) - 1)) >> || _ <- lists:seq(1,Length) >>.
salt() -> crypto:strong_rand_bytes(wf:config(eauth,salt_length,?SALT_LENGTH)).
