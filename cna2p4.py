# pyright: reportAny=false
# pyright: reportExplicitAny=false
# pyright: reportUnknownArgumentType=false
import argparse
import json
import re
from typing import Any

from consts import ForwardAction


def ident(name: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9_]", "_", name)
    if not s:
        s = "x"
    if s[0].isdigit():
        s = "_" + s
    return s


def indent_line(line: str, level: int = 1) -> str:
    indent = " " * 4 * level
    return f"{indent}{line}"


def p4_type(field: dict[str, Any], typedefs: dict[str, int]) -> str:
    if "type" in field:
        t = ident(field["type"])
        if t not in typedefs:
            raise ValueError(
                f"Field '{field.get('field')}' references unknown typedef '{t}'"
            )
        return t
    bw = field.get("bit_width")
    if bw is None:
        raise ValueError(f"Field '{field.get('field')}' requires 'type' or 'bit_width'")
    return f"bit<{int(bw)}>"


def as_expr_target(target: str, header_names: set[str]) -> str:
    parts = target.split(".")
    if len(parts) >= 2 and parts[0] in header_names:
        return "hdr." + ".".join(parts)
    return target


def as_expr_indicator(indicator_field: str, header_names: set[str]) -> str:
    parts = indicator_field.split(".")
    if len(parts) >= 2 and parts[0] in header_names:
        return "hdr." + ".".join(parts)
    return indicator_field


def as_expr_value(value: Any) -> str:
    if isinstance(value, dict) and "from_param" in value:
        return ident(value["from_param"])
    if isinstance(value, str):
        return value
    return str(value)


def render_typedefs(typedefs_raw: list[dict[str, Any]]) -> tuple[str, dict[str, int]]:
    lines: list[str] = []
    typedefs: dict[str, int] = {}
    for td in typedefs_raw:
        name = ident(td["field"])
        bw = int(td["bit_width"])
        typedefs[name] = bw
        lines.append(f"typedef bit<{bw}> {name};")
    return "\n".join(lines), typedefs


def collect_proto_defs(cna: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Build a lookup from protocol id to its full definition."""
    return {ident(p["id"]): p for p in cna.get("protocols", [])}


def collect_headers(cna: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """
    Return a mapping from P4 header name -> list of field dicts.

    - Forwarding protocols (role: "forwarding") are instantiated once per
      network instance: the instance id becomes the header name and the
      field definitions come from the protocol type referenced by "type".
    - Session protocols (role: "session") keep their own protocol id as the
      header name, since they are shared across all network instances that
      embed them.
    """
    proto_defs = collect_proto_defs(cna)
    headers: dict[str, list[dict[str, Any]]] = {}

    # Network instances → headers resolved through their protocol type
    for n in cna.get("networks", []):
        instance_id = ident(n["id"])
        proto_type = ident(n["type"])
        proto = proto_defs.get(proto_type)
        if proto is None:
            raise ValueError(
                f"Network '{n['id']}' references unknown protocol type '{n['type']}'"
            )
        headers[instance_id] = proto.get("headers", [])

    # Session protocols get their own header entry keyed by protocol id
    for p in cna.get("protocols", []):
        if p.get("role") == "session":
            headers[ident(p["id"])] = p.get("headers", [])

    return headers


def render_consts(consts_raw: list[dict[str, Any]]) -> str:
    lines: list[str] = []
    for const in consts_raw:
        name = ident(const["field"])
        bw = const.get("bit_width")
        value = const.get("value")
        if bw is None or value is None:
            raise ValueError(
                f"Const '{const.get('field')}' requires 'bit_width' and 'value'"
            )
        value_expr = value if isinstance(value, str) else str(value)
        lines.append(f"const bit<{int(bw)}> {name} = {value_expr};")
    return "\n".join(lines)


def render_headers(
    headers: dict[str, list[dict[str, Any]]], typedefs: dict[str, int]
) -> str:
    out: list[str] = []
    for hname, fields in headers.items():
        out.append(f"header {hname}_t {{")
        for f in fields:
            fname = ident(f["field"])
            ftype = p4_type(f, typedefs)
            out.append(f"    {ftype} {fname};")
        out.append("}")
        out.append("")
    return "\n".join(out).rstrip()


def render_struct_headers(headers: dict[str, list[dict[str, Any]]]) -> str:
    out = ["struct headers_t {"]
    for hname in headers.keys():
        out.append(f"    {hname}_t {hname};")
    out.append("}")
    return "\n".join(out)


def render_metadata_struct() -> str:
    return "struct metadata_t {\n}"


def build_parse_edges(
    cna: dict[str, Any],
) -> tuple[dict[str, list[tuple[str, str, str]]], str]:
    """
    Build a graph of parser transitions.

    Each edge is (indicator_field, indicator_value, next_state) and is keyed
    by the header whose select expression triggers the transition.

    Layering composition contributes edges from the underlay header to the
    overlay header (e.g. eth1.ether_type -> ip1).  Session protocol entries on
    each network instance contribute edges from that instance's header to the
    session protocol header (e.g. ip1.protocol -> tcp).

    The parser root is the lowest-level network instance — whichever instance
    is not itself an overlay in any layering composition.
    """
    edges: dict[str, list[tuple[str, str, str]]] = {}

    # All network instance ids, in declaration order
    networks = [ident(n["id"]) for n in cna.get("networks", [])]

    # Layering composition: underlay -> overlay transition
    overlays: set[str] = set()
    for comp in cna.get("composition", []):
        if comp.get("operator") == "layering":
            underlay = ident(comp["underlay"])
            overlay = ident(comp["overlay"])
            overlays.add(overlay)
            enc = comp.get("session_identifier", {})
            field = enc.get("field")
            value = enc.get("value")
            if field and value:
                edges.setdefault(underlay, []).append((field, value, overlay))

    # Session protocols embedded in each network instance
    for net in cna.get("networks", []):
        net_id = ident(net["id"])
        for s in net.get("session_protocols", []):
            proto = ident(s["protocol"])
            field = s["indicator_field"]
            value = s["indicator_value"]
            edges.setdefault(net_id, []).append((field, value, proto))

    # The root is the first network instance that is not an overlay
    roots = [n for n in networks if n not in overlays]
    root = roots[0] if roots else (networks[0] if networks else "")

    return edges, root


def render_parser(cna: dict[str, Any], headers: dict[str, list[dict[str, Any]]]) -> str:
    header_names = set(headers.keys())
    edges, root = build_parse_edges(cna)

    states: list[str] = []
    states.append(
        "parser ParserImpl("
        + "packet_in packet, "
        + "out headers_t hdr, "
        + "inout metadata_t meta, "
        + "inout standard_metadata_t standard_metadata) {"
    )
    states.append("    state start {")
    if root:
        states.append(f"        transition parse_{root};")
    else:
        states.append("        transition accept;")
    states.append("    }")
    states.append("")

    for hname in headers.keys():
        states.append(f"    state parse_{hname} {{")
        states.append(f"        packet.extract(hdr.{hname});")

        next_edges = edges.get(hname, [])
        if next_edges:
            # All edges for one header share the same indicator field
            field_expr = as_expr_indicator(next_edges[0][0], header_names)
            states.append(f"        transition select({field_expr}) {{")
            for _, value, nxt in next_edges:
                states.append(f"            {value}: parse_{nxt};")
            states.append("            default: accept;")
            states.append("        }")
        else:
            states.append("        transition accept;")

        states.append("    }")
        states.append("")

    states.append("}")
    return "\n".join(states).rstrip()


def render_action(action: dict[str, Any], header_names: set[str]) -> tuple[str, str]:
    name = ident(action["id"])
    params = action.get("parameters", [])
    operations = action.get("operations", [])

    param_strs: list[str] = []
    for p in params:
        pname = ident(p["name"])
        if "type" in p:
            ptype = ident(p["type"])
        else:
            ptype = f"bit<{int(p['bit_width'])}>"
        param_strs.append(f"{ptype} {pname}")

    out = [f"action {name}({', '.join(param_strs)}) {{"]

    if not operations:
        out.append("    // no operations")
    else:
        for operation in operations:
            op = operation.get("op")
            if op == ForwardAction.SetField:
                target = as_expr_target(operation["target"], header_names)
                value = as_expr_value(operation["value"])
                out.append(f"    {target} = {value};")
            elif op == ForwardAction.Decrement:
                target = as_expr_target(operation["target"], header_names)
                amount = operation.get("amount", 1)
                out.append(f"    {target} = {target} - {amount};")
            elif op == ForwardAction.SetEgressPort:
                value = as_expr_value(operation["value"])
                out.append(f"    standard_metadata.egress_spec = {value};")
            elif op == ForwardAction.Drop:
                out.append("    mark_to_drop(standard_metadata);")
            elif op == ForwardAction.Noop:
                out.append("    ;")
            else:
                out.append(f"    // unsupported operation: {op}")

    out.append("}")
    return name, "\n".join(out)


def pick_default_action(action_names: list[tuple[str, dict[str, Any]]]) -> str:
    for name, action in action_names:
        if not action.get("parameters"):
            return f"{name}()"
    return "NoAction()"


def render_ingress(
    cna: dict[str, Any], headers: dict[str, list[dict[str, Any]]]
) -> str:
    header_names = set(headers.keys())

    action_defs: list[str] = []
    table_defs: list[str] = []
    apply_lines: list[str] = []

    # One table per layering composition (forwarding actions)
    # and one table per service (policy/middlebox actions)
    groups: list[tuple[str, list[dict[str, Any]]]] = []

    for comp in cna.get("composition", []):
        gname = ident(f"fwd_{comp.get('overlay', 'net')}")
        groups.append((gname, comp.get("forwarding_actions", [])))

    for svc in cna.get("services", []):
        gname = ident(f"{svc['id']}_policy")
        groups.append((gname, svc.get("actions", [])))

    used_names: set[str] = set()

    for gname, actions in groups:
        if not actions:
            continue

        rendered_actions: list[tuple[str, dict[str, Any]]] = []
        for a in actions:
            # Deduplicate action names across groups
            base_name = ident(a["id"])
            name = base_name
            i = 1
            while name in used_names:
                i += 1
                name = f"{base_name}_{i}"
            used_names.add(name)

            action_copy = dict(a)
            action_copy["id"] = name
            action_name, action_code = render_action(action_copy, header_names)
            action_defs.append(action_code)
            rendered_actions.append((action_name, action_copy))

        tbl = ident(f"{gname}_tbl")
        table_defs.append(f"table {tbl} {{")
        table_defs.append("    key = {")
        table_defs.append("    }")
        table_defs.append("    actions = {")
        for an, _ in rendered_actions:
            table_defs.append(f"        {an};")
        table_defs.append("        NoAction;")
        table_defs.append("    }")
        table_defs.append("    size = 1024;")
        table_defs.append(
            f"    default_action = {pick_default_action(rendered_actions)};"
        )
        table_defs.append("}")
        table_defs.append("")
        apply_lines.append(f"        {tbl}.apply();")

    out = [
        "control IngressImpl("
        + "inout headers_t hdr, "
        + "inout metadata_t meta, "
        + "inout standard_metadata_t standard_metadata) {",
        "",
    ]

    if action_defs:
        for block in action_defs:
            out.extend(f"    {line}" if line else "" for line in block.splitlines())
            out.append("")

    if table_defs:
        out.extend(
            f"    {line}" if line else ""
            for line in "\n".join(table_defs).rstrip().splitlines()
        )
        out.append("")

    out.append("    apply {")
    if apply_lines:
        out.extend(apply_lines)
    out.append("    }")
    out.append("}")
    return "\n".join(out).rstrip()


def render_egress() -> str:
    return (
        "control EgressImpl("
        "inout headers_t hdr, "
        "inout metadata_t meta, "
        "inout standard_metadata_t standard_metadata) {\n"
        "    apply {\n"
        "    }\n"
        "}"
    )


def render_verify_checksum() -> str:
    return (
        "control VerifyChecksumImpl(inout headers_t hdr, inout metadata_t meta) {\n"
        "    apply {\n"
        "    }\n"
        "}"
    )


def render_compute_checksum() -> str:
    return (
        "control ComputeChecksumImpl(inout headers_t hdr, inout metadata_t meta) {\n"
        "    apply {\n"
        "    }\n"
        "}"
    )


def render_deparser(headers: dict[str, list[dict[str, Any]]]) -> str:
    out = ["control DeparserImpl(packet_out packet, in headers_t hdr) {", "    apply {"]
    for hname in headers.keys():
        header = f"hdr.{hname}"
        out.append(indent_line(f"if ({header}.isValid()) {{", 2))
        out.append(indent_line(f"packet.emit({header});", 3))
        out.append(indent_line("}", 2))
    out.append(indent_line("}", 1))
    out.append("}")
    return "\n".join(out)


def generate_p4(cna: dict[str, Any]) -> str:
    consts_txt = render_consts(cna.get("consts", []))
    typedefs_txt, typedefs = render_typedefs(cna.get("typedefs", []))
    headers = collect_headers(cna)

    parts = [
        "#include <core.p4>",
        "#include <v1model.p4>",
        "",
        consts_txt,
        "",
        typedefs_txt,
        "",
        render_headers(headers, typedefs),
        "",
        render_struct_headers(headers),
        "",
        render_metadata_struct(),
        "",
        render_parser(cna, headers),
        "",
        render_verify_checksum(),
        "",
        render_ingress(cna, headers),
        "",
        render_egress(),
        "",
        render_compute_checksum(),
        "",
        render_deparser(headers),
        "",
        "V1Switch(",
        "    ParserImpl(),",
        "    VerifyChecksumImpl(),",
        "    IngressImpl(),",
        "    EgressImpl(),",
        "    ComputeChecksumImpl(),",
        "    DeparserImpl()",
        ") main;",
    ]

    return "\n".join(parts).rstrip() + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate P4_16 from CNA JSON specification"
    )
    _ = parser.add_argument("input", help="Path to CNA JSON file")
    _ = parser.add_argument(
        "-o",
        "--output",
        help="Output P4 file (default: <name>.p4 derived from CNA root 'name')",
    )
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8") as f:
        cna = json.load(f)

    output_path = args.output
    if not output_path:
        cna_name = cna.get("name")
        if not isinstance(cna_name, str) or not cna_name.strip():
            raise ValueError(
                "CNA root object must contain a non-empty 'name' "
                + "when --output is not provided"
            )
        output_path = f"{ident(cna_name)}.p4"

    p4_code = generate_p4(cna)

    with open(output_path, "w", encoding="utf-8") as f:
        _ = f.write(p4_code)

    print(f"Generated {output_path} from {args.input}")


if __name__ == "__main__":
    main()
