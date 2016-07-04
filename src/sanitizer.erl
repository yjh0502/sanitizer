% Copyright (c) 2014 Jihyun Yu <yjh0502@gmail.com>
% All rights reserved.
% 
% Redistribution and use in source and binary forms, with or without
% modification, are permitted provided that the following conditions
% are met:
% 
% 1. Redistributions of source code must retain the above copyright
%    notice, this list of conditions and the following disclaimer.
% 2. Redistributions in binary form must reproduce the above copyright
%    notice, this list of conditions and the following disclaimer in
%    the documentation and/or other materials provided with the
%    distribution.
% 
% THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
% "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
% LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
% FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
% COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
% INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
% BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
% LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
% CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
% LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
% ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
% POSSIBILITY OF SUCH DAMAGE.

-module(sanitizer).

-include_lib("sanitizer/include/sanitizer.hrl").

-export([sanitize/2]).

validate_type(bool, true) -> true;
validate_type(bool, <<"true">>) -> true;
validate_type(bool, false) -> false;
validate_type(bool, <<"false">>) -> false;
validate_type(bool, Given) when is_integer(Given) ->
    case Given of
        0 -> false;
        _Other -> true
    end;
validate_type(bool, _Other) -> throw({badarg, {shouldbool, _Other}});

validate_type(int, Given) when is_integer(Given) -> Given;
validate_type(int, Given) when is_list(Given) ->
    try list_to_integer(Given) of Out -> Out
    catch error:badarg -> throw({badarg, {shouldint, Given}}) end;
validate_type(int, Given) when is_binary(Given) ->
    try binary_to_integer(Given) of
        Out -> Out
    catch error:badarg -> throw({badarg, {shouldint, Given}}) end;

validate_type(float, Given) when is_number(Given) -> Given;
validate_type(float, Given) when is_list(Given) ->
    validate_type(float, list_to_binary(Given));
validate_type(float, Given) when is_binary(Given) ->
    try binary_to_integer(Given) of Out -> Out
    catch error:badarg ->
        try binary_to_float(Given) of Out -> Out
        catch error:badarg -> throw({badarg, {shouldfloat, Given}}) end
    end;

validate_type(atom, Given) when is_atom(Given) -> Given;
validate_type(atom, Given) when is_binary(Given) ->
    try binary_to_existing_atom(Given, utf8) of Atom -> Atom
    catch error:badarg -> throw({badarg, {shouldatom, Given}})
    end;

validate_type(binary, Given) when is_binary(Given) -> Given;
validate_type(binary, Given) when is_atom(Given) -> atom_to_binary(Given, utf8);
validate_type(binary, Given) when is_list(Given) -> list_to_binary(Given);
validate_type(binary, Given) when is_integer(Given) -> integer_to_binary(Given);

validate_type({map, _KeySpec, _ValueSpec} = Spec, Given) when is_map(Given) ->
    validate_type(Spec, maps:to_list(Given));
validate_type({map, KeySpec, ValueSpec}, Given) when is_list(Given) ->
    ValidateFunc = fun({Key, Value}) ->
        {validate_constraint(KeySpec, Key), validate_constraint(ValueSpec, Value)}
    end,
    maps:from_list(lists:map(ValidateFunc, Given));

validate_type({list, Spec}, Given) when is_list(Given) ->
    ValidateFunc = fun(Item) ->
        validate_type(Spec, Item)
    end,
    lists:map(ValidateFunc, Given);
validate_type({list, Spec}, Given) ->
    validate_type({list, Spec}, [Given]);

validate_type(_Type, _Spec) ->
    throw(badspec).

validate_constraint(Spec, Value) when is_map(Spec) ->
    Type = maps:get(type, Spec),
    ListSpec = [{type, Type} | maps:to_list(Spec)],
    validate_constraint(ListSpec, Value);

validate_constraint([{type, TypeDesc} | T], Value) ->
    validate_constraint(T, validate_type(TypeDesc, Value));
validate_constraint([{lt, MinVal} | T], Value) ->
    if Value < MinVal -> validate_constraint(T, Value);
        true -> throw({badarg, {constraint, '<', MinVal}}) end;
validate_constraint([{lte, MinVal} | T], Value) ->
    if Value =< MinVal -> validate_constraint(T, Value);
        true -> throw({badarg, {constraint, '=<', MinVal}}) end;
validate_constraint([{gt, MaxVal} | T], Value) ->
    if Value > MaxVal -> validate_constraint(T, Value);
        true -> throw({badarg, {constraint, '>', MaxVal}}) end;
validate_constraint([{gte, MaxVal} | T], Value) ->
    if Value >= MaxVal -> validate_constraint(T, Value);
        true -> throw({badarg, {constraint, '>=', MaxVal}}) end;
validate_constraint([{optional, _} | T], Value) ->
    validate_constraint(T, Value);

validate_constraint([], Value) -> Value;

%% Shortcut: TypeSpec -> [{type, TypeSpec}]
validate_constraint(TypeSpec, Value) when is_atom(TypeSpec); is_tuple(TypeSpec) ->
    validate_type(TypeSpec, Value);

validate_constraint(_Spec, _Value) ->
    throw(badspec).

validate_key(Key) when is_atom(Key) -> Key;
validate_key(Key) when is_binary(Key) ->
    try binary_to_existing_atom(Key, utf8) of Atom -> Atom
    catch error:badarg -> throw({badarg, {badkey, Key}})
    end;
validate_key(Key) -> throw({badarg, {badkey, Key}}).

-spec sanitize(specs(), any()) -> #{atom() => any()}.
sanitize(Spec, Args) ->
    AtomArgs = lists:map(fun({Key, Val}) -> {validate_key(Key), Val} end, maps:to_list(Args)),
    SanitizeKey = fun({Key, DescSpec}) ->
        Optional = case DescSpec of
            #{optional := O} -> O;
            _ -> false
        end,
        case {Optional, lists:keyfind(Key, 1, AtomArgs)} of
            {true, false} ->
                {Key, undefined};
            {true, {_, <<>>}} ->
                {Key, undefined};
            {false, false} ->
                throw({badarg, {badkey, Key}});
            {_, {_, Value}} ->
                try {Key, validate_constraint(DescSpec, Value)} of
                    Sanitized -> Sanitized
                catch
                    throw:{badarg, Reason} ->
                        throw({badarg, list_to_tuple([Key | tuple_to_list(Reason)])})
                end
        end
    end,
    Out = lists:map(SanitizeKey, maps:to_list(Spec)),
    maps:from_list(Out).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

-define(badarg,  {badarg, _}).

constraint_test_() ->
    F = fun validate_constraint/2,
    [
    ?_assertEqual(1, F(#{type => int, gte => 1}, 1)),
    ?_assertEqual(1, F([{type, int}, {gt, 0}], 1)),
    ?_assertEqual(1, F([{type, int}, {lte, 1}], 1)),
    ?_assertEqual(1, F([{type, int}, {lte, 2}], 1)),

    ?_assertThrow(?badarg, F([{type, int}, {lte, 0}], 1)),
    ?_assertThrow(?badarg, F([{type, int}, {lt, 1}], 1)),
    ?_assertThrow(?badarg, F([{type, int}, {gte, 2}], 1)),
    ?_assertThrow(?badarg, F([{type, int}, {gt, 1}], 1)),
    ?_assertThrow(?badarg, F([{type, int}, {gt, 0}], <<"-1">>)),

    ?_assertThrow(badspec, F([{type, int}, {gt, 0, 1}], 1))
    ].

sanitize_test_inputs(Expected, Spec, Inputs) ->
    lists:map(fun(Input) ->
        ?_assertEqual(Expected, sanitize(Spec, Input))
    end, Inputs).

sanitize_test_() -> [
    ?_assertThrow(?badarg, sanitize(#{hello => #{type => int}}, #{})),
    ?_assertThrow(?badarg, sanitize(#{hello => #{type => binary}}, #{})),
    ?_assertThrow(?badarg, sanitize(#{hello => #{type => int}}, #{hello => <<"world">>})),
    ?_assertEqual(#{}, sanitize(#{}, #{})),
    ?_assertEqual(#{hello => 1},
        sanitize(#{hello => #{type => int}}, #{<<"hello">> => <<"1">>})),

    ?_assertEqual(#{hello => true},
        sanitize(#{hello => #{type => bool}}, #{<<"hello">> => true}))
    ]
    ++ sanitize_test_inputs(
        #{hello => #{<<"hello">> => 1}},
        #{hello => {map, binary, #{type=>int, gte=>0}}},
        [
            #{hello => #{<<"hello">> => 1}},
            #{hello => [{<<"hello">>, 1}]}
        ])

    ++ sanitize_test_inputs(
        #{hello => 1},
        #{hello => #{type => int}},
        [
            #{hello => 1},
            #{hello => "1"},
            #{hello => <<"1">>}
        ]).

sanitize_invalid_key_test_() -> [
    ?_assertThrow(?badarg,
        sanitize(#{hello => #{type => int}}, #{<<"hello1234">> => <<"1">>})),
    ?_assertThrow(?badarg,
        sanitize(#{hello => #{type => int}}, #{"1234" => <<"1">>}))
    ].

sanitize_order_test_() ->
    sanitize_test_inputs(
        #{hello => 1, world => <<"world">>},
        #{hello => #{type => int}, world => #{type => binary}},
        [
            #{hello => 1, world => world},
            #{world => <<"world">>, hello => <<"1">>}
        ])
    ++ sanitize_test_inputs(
        #{world => <<"world">>, hello => 1},
        #{world => #{type => binary}, hello => #{type => int}},
        [
            #{hello => 1, world => world},
            #{world => <<"world">>, hello => <<"1">>}
        ]).

sanitize_shortcuts_test_() -> [
    ?_assertEqual(#{hello => 1},
        sanitize(#{hello => #{type => int}}, #{hello => <<"1">>})),
    ?_assertEqual(#{hello => [1,2]},
        sanitize(#{hello => {list, int}}, #{hello => [<<"1">>, "2"]}))
    ].

sanitize_optional_test_() -> [
    ?_assertEqual(#{hello => 1, world => undefined},
        sanitize(#{hello => #{type => int}, world => #{type => int, optional => true}},
            #{hello => <<"1">>})),
    ?_assertEqual(#{hello => 1, world => undefined},
        sanitize(#{hello => #{type => int}, world => #{type => int, optional => true}},
            #{hello => <<"1">>, world => <<"">>})),
    ?_assertEqual(#{hello => 1},
        sanitize(#{hello => #{type => int, optional => false}},
            #{hello => <<"1">>}))
    ].

validate_type_bool_test_() -> [
        ?_assertEqual(true, validate_type(bool, true)),
        ?_assertEqual(false, validate_type(bool, false)),
        ?_assertEqual(true, validate_type(bool, <<"true">>)),
        ?_assertEqual(false, validate_type(bool, <<"false">>)),
        ?_assertEqual(false, validate_type(bool, 0)),
        ?_assertEqual(true, validate_type(bool, 1)),
        ?_assertEqual(true, validate_type(bool, 10)),
        ?_assertThrow(?badarg, validate_type(bool, <<"hello">>))
    ].

validate_type_int_test_() -> [
    ?_assertEqual(1, validate_type(int, 1)),
    ?_assertEqual(1, validate_type(int, "1")),
    ?_assertEqual(1, validate_type(int, <<"1">>)),
    ?_assertThrow(?badarg, validate_type(int, <<"hello">>)),
    ?_assertThrow(?badarg, validate_type(int, <<"1.234">>))
    ].

validate_type_float_test_() -> [
    ?_assertEqual(1, validate_type(float, 1)),
    ?_assertEqual(1, validate_type(float, "1")),
    ?_assertEqual(1, validate_type(float, <<"1">>)),
    ?_assertEqual(1.1, validate_type(float, <<"1.1">>)),
    ?_assertThrow(?badarg, validate_type(float, <<"hello">>)),
    ?_assertThrow(?badarg, validate_type(float, <<"1.">>))
    ].

validate_type_atom_test_() -> [
    ?_assertEqual(hello, validate_type(atom, hello)),
    ?_assertEqual(hello, validate_type(atom, <<"hello">>)),
    ?_assertThrow(?badarg, validate_type(atom, <<"non_existing_atom_something">>))
    ].

validate_type_binary_test_() -> [
    ?_assertEqual(<<"1">>, validate_type(binary, 1)),
    ?_assertEqual(<<"1">>, validate_type(binary, <<"1">>)),
    ?_assertEqual(<<"1">>, validate_type(binary, "1"))
    ].

validate_type_list_test_() -> [
    ?_assertEqual([1], validate_type({list, int}, 1)),
    ?_assertEqual([1,2], validate_type({list, int}, [1,2])),
    ?_assertEqual([1,2], validate_type({list, int}, ["1",<<"2">>])),
    ?_assertThrow(?badarg, validate_type({list, int}, [1,2,"hello"]))
    ].

validate_type_map_test_() -> [
    ?_assertEqual(#{1 => 2, 3 => 4}, validate_type(
        {map, int, int}, #{1 => 2, 3 =>4})),
    ?_assertEqual(#{1 => 2, 3 => 4}, validate_type(
        {map, int, int}, [{1, 2}, {3, 4}])),
    ?_assertEqual(#{1 => 2, 3 => 4}, validate_type(
        {map, int, int}, #{"1" => <<"2">>, <<"3">> => "4"}))
    ].
    
validate_badspec_test_() -> [
    ?_assertThrow(badspec, validate_constraint(1, [{1, 2}])),
    ?_assertThrow(badspec, validate_type({map, int}, [{1, 2}])),
    ?_assertThrow(badspec, validate_type({list, int, int}, [1,2,"hello"]))
    ].

-endif.
