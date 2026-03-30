from enum import StrEnum


class Action(StrEnum):
    Noop = "noop"
    SetField = "set_field"
    Decrement = "decrement"
    SetEgressPort = "set_egress_port"
    Drop = "drop"
