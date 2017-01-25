-module(eauth).
-author('@m-2k').
-behaviour(application).
-behaviour(supervisor).

-include("eauth.hrl").
-include("eauth_user.hrl").

% -include_lib("kvs/include/user.hrl").
-include_lib("kvs/include/metainfo.hrl").

-compile(export_all).

start(_,_) -> start_link().
stop(_) -> ok.
start_link() -> supervisor:start_link({local,?MODULE},?MODULE,[]).
init([]) -> {ok, {{one_for_one,5,10}, []} }.


signin(Mail,Passwd) -> eauth_event:signin(Mail,Passwd).
activate(Key) -> eauth_event:activate(Key).
join(Mail,JoinMessageFun) -> eauth_event:join(Mail,JoinMessageFun).
reset(Mail,ResetMessageFun) -> eauth_event:reset(Mail,ResetMessageFun).
