open! IdontKnow
module I = dontKnow

module IdontKnow : sig
  type t = {char_width: int; short_width: int; int_width: int; long_width: int; longlong_width: int}
  [@@dontknow HAHAHAHAHA, equal]
