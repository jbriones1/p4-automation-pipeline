# pyright: reportExplicitAny=false
# pyright: reportAny=false
# pyright: reportUnknownArgumentType=false
from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

# type MatchType = Literal["exact", "lpm", "ternary", "range"]
networks: dict[str, Network] = {}


class MatchTypeEnum(StrEnum):
    exact = "exact"
    lpm = "lpm"
    ternary = "ternary"
    range = "range"


class ParseError(ValueError):
    pass


def _require(d: dict[str, Any], key: str, where: str) -> Any:
    if key not in d:
        raise ParseError(f"Missing required key '{key}' in {where}")
    return d[key]


def _ensure_exactly_one(d: dict[str, Any], keys: tuple[str, ...], where: str) -> str:
    present = [k for k in keys if k in d]
    if len(present) != 1:
        raise ParseError(f"{where} must contain exactly one of {keys}, got {present}")
    return present[0]


@dataclass
class Typedef:
    field: str
    bit_width: int

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "Typedef":
        return Typedef(
            field=str(_require(d, "field", "typedef")),
            bit_width=int(_require(d, "bit_width", "typedef")),
        )


@dataclass
class Namespace:
    member_id_type: str

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "Namespace":
        return Namespace(member_id_type=str(_require(d, "member_id_type", "namespace")))


@dataclass
class HeaderField:
    field: str
    type: str | None = None
    bit_width: int | None = None

    @staticmethod
    def from_dict(d: dict[str, Any], where: str) -> "HeaderField":
        which = _ensure_exactly_one(d, ("type", "bit_width"), where)
        return HeaderField(
            field=str(_require(d, "field", where)),
            type=str(d["type"]) if which == "type" else None,
            bit_width=int(d["bit_width"]) if which == "bit_width" else None,
        )


@dataclass
class SessionProtocol:
    id: str
    match_field: str
    match_type: MatchTypeEnum

    @staticmethod
    def from_dict(d: dict[str, Any]) -> SessionProtocol:
        match_t = str(_require(d, "match_type", "session_protocol"))
        if match_t not in MatchTypeEnum:
            raise ParseError(f"Invalid match_type '{match_t}'")
        mt = MatchTypeEnum(match_t)
        return SessionProtocol(
            id=str(_require(d, "id", "session_protocol")),
            match_field=str(_require(d, "match_field", "session_protocol")),
            match_type=mt,
        )


@dataclass
class Network:
    id: str
    namespace: Namespace
    forwarding_header: list[HeaderField]
    session_protocols: list[SessionProtocol]

    @staticmethod
    def from_dict(d: dict[str, Any]) -> Network:
        net = Network(
            id=str(_require(d, "id", "network")),
            namespace=Namespace.from_dict(_require(d, "namespace", "network")),
            forwarding_header=[
                HeaderField.from_dict(
                    x, f"network[{d.get('id', '?')}].forwarding_header"
                )
                for x in _require(d, "forwarding_header", "network")
            ],
            session_protocols=[
                SessionProtocol.from_dict(x)
                for x in _require(d, "session_protocols", "network")
            ],
        )
        if net.id in networks:
            raise ParseError(f"Duplicate network id '{net.id}'")
        networks[net.id] = net
        return net


@dataclass
class ValueRef:
    from_param: str | None = None

    @staticmethod
    def from_obj(obj: Any, where: str) -> ValueRef:
        if not isinstance(obj, dict):
            raise ParseError(f"{where}.value must be an object")
        # Extend here if you later support constants, expressions, etc.
        if "from_param" in obj:
            return ValueRef(from_param=str(obj["from_param"]))
        raise ParseError(f"{where}.value: unsupported value object {obj}")


@dataclass
class Primitive:
    op: str
    target: str | None = None
    amount: int | None = None
    value: ValueRef | None = None

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "Primitive":
        op = str(_require(d, "op", "primitive"))
        p = Primitive(op=op)
        if "target" in d:
            p.target = str(d["target"])
        if "amount" in d:
            p.amount = int(d["amount"])
        if "value" in d:
            p.value = ValueRef.from_obj(d["value"], f"primitive[{op}]")
        return p


@dataclass
class ActionParam:
    name: str
    type: str

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "ActionParam":
        return ActionParam(
            name=str(_require(d, "name", "action parameter")),
            type=str(_require(d, "type", "action parameter")),
        )


@dataclass
class ForwardingAction:
    id: str
    parameters: list[ActionParam]
    primitives: list[Primitive]

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "ForwardingAction":
        return ForwardingAction(
            id=str(_require(d, "id", "forwarding action")),
            parameters=[
                ActionParam.from_dict(x)
                for x in _require(d, "parameters", "forwarding action")
            ],
            primitives=[
                Primitive.from_dict(x)
                for x in _require(d, "primitives", "forwarding action")
            ],
        )


@dataclass
class OverlayIdentifier:
    field_name: str
    field_value: str

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "OverlayIdentifier":
        return OverlayIdentifier(
            field_name=str(_require(d, "field_name", "encapsulation")),
            field_value=str(_require(d, "field_value", "encapsulation")),
        )


@dataclass
class Composition:
    operator: str
    overlay: str
    underlay: str
    encapsulation: OverlayIdentifier
    forwarding_actions: list[ForwardingAction]

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "Composition":
        return Composition(
            operator=str(_require(d, "operator", "composition")),
            overlay=str(_require(d, "overlay", "composition")),
            underlay=str(_require(d, "underlay", "composition")),
            encapsulation=OverlayIdentifier.from_dict(
                _require(d, "encapsulation", "composition")
            ),
            forwarding_actions=[
                ForwardingAction.from_dict(x)
                for x in _require(d, "forwarding_actions", "composition")
            ],
        )


@dataclass
class PipelineSpec:
    name: str
    typedefs: list[Typedef] = field(default_factory=list)
    networks: list[Network] = field(default_factory=list)
    composition: list[Composition] = field(default_factory=list)

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "PipelineSpec":
        return PipelineSpec(
            name=str(_require(d, "name", "root")),
            typedefs=[Typedef.from_dict(x) for x in _require(d, "typedefs", "root")],
            networks=[Network.from_dict(x) for x in _require(d, "networks", "root")],
            composition=[
                Composition.from_dict(x) for x in _require(d, "composition", "root")
            ],
        )

    @staticmethod
    def from_file(path: str | Path) -> PipelineSpec:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ParseError("Root JSON value must be an object")
        return PipelineSpec.from_dict(data)


if __name__ == "__main__":
    # Example:
    #   python3 parser.py /path/to/spec.json
    import sys

    if len(sys.argv) != 2:
        raise SystemExit("Usage: python3 cna2p4.py <spec.json>")
    spec = PipelineSpec.from_file(sys.argv[1])
    print(spec)
