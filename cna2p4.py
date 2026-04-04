# pyright: reportAny=false
# pyright: reportExplicitAny=false
# pyright: reportUnknownArgumentType=false
import argparse
import json
import re
from typing import Any

from consts import Action


class ParseError(Exception):
    pass


def ident(name: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9_]", "_", name)
    if not s:
        s = "x"
    if s[0].isdigit():
        s = "_" + s
    return s


def strip_header_prefix(field: str) -> str:
    """
    Strip a leading 'networkId.' prefix from a qualified field reference.

    Example: 'ip1.protocol' -> 'protocol'
    This normalises indicator_field and selection_predicate field values so the
    parser can use them directly as field names within the current header state.
    """
    parts = field.split(".")
    if len(parts) >= 2:
        return ".".join(parts[1:])
    return field


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
      network instance: the instance id becomes the header name.
    - Session protocols (role: "session") keep their own protocol id as the
      header name, since they are shared across all network instances that
      embed them.
    """
    proto_defs = collect_proto_defs(cna)
    headers: dict[str, list[dict[str, Any]]] = {}

    for n in cna.get("networks", []):
        instance_id = ident(n["id"])
        proto_type = ident(n["type"])
        proto = proto_defs.get(proto_type)
        if proto is None:
            raise ValueError(
                f"Network '{n['id']}' references unknown protocol type '{n['type']}'"
            )
        headers[instance_id] = proto.get("headers", [])

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


def check_composition_cycles(cna: dict[str, Any]) -> None:
    """
    Raise ParseError if the composition graph contains a cycle.

    Each composition entry contributes a directed edge from underlay to overlay.
    A cycle means some network is both an ancestor and a descendant of itself,
    e.g. net1 -> net2 in one entry and net2 -> net1 in another.

    As a side effect this guarantees the composition graph is a DAG, which is a
    precondition for the parser ordering to be well-defined.
    """
    graph: dict[str, list[str]] = {}
    for comp in cna.get("composition", []):
        underlay = ident(comp.get("underlay", ""))
        overlay = ident(comp.get("overlay", ""))
        if underlay and overlay:
            graph.setdefault(underlay, []).append(overlay)

    visited: set[str] = set()
    in_stack: set[str] = set()

    def dfs(node: str) -> None:
        visited.add(node)
        in_stack.add(node)
        for neighbour in graph.get(node, []):
            if neighbour not in visited:
                dfs(neighbour)
            elif neighbour in in_stack:
                raise ParseError(
                    f"Cycle detected in composition: "
                    f"'{neighbour}' is both an ancestor and descendant of itself"
                )
        in_stack.remove(node)

    for node in list(graph.keys()):
        if node not in visited:
            dfs(node)


def build_parse_edges(
    cna: dict[str, Any],
) -> tuple[dict[str, list[tuple[str, str, str]]], str, set[str]]:
    """
    Build a graph of parser transitions.

    Each edge is a 3-tuple (field_name, indicator_value, next_state):
      - field_name      local field name within the current header to select on.
                        An empty string signals a *direct* transition (no select).
      - indicator_value the constant value that triggers the transition.
      - next_state      the header state to transition into.

    Returns (edges, root, conditional_headers) where conditional_headers is the
    set of header names that are only extracted on a conditional parser branch.
    This includes overlay networks, encapsulation protocols, and session
    protocols — anything that is not unconditionally extracted from the root.
    The caller uses this set to decide which deparser emit() calls need an
    isValid() guard.

    Operator handling
    -----------------
    layering:   underlay --[session_identifier]--> overlay
                Each session_protocol embeds an additional edge from its network.

    subduction: The shared_link ingress selection_predicate creates an edge from
                the underlay to the encapsulation_protocol header (if present) or
                directly to the overlay.  The encapsulation_protocol then
                transitions unconditionally (direct edge) to the overlay.

    The parser root is the lowest-level network instance — whichever instance
    is not itself an overlay in any composition.
    """
    edges: dict[str, list[tuple[str, str, str]]] = {}
    networks = [ident(n["id"]) for n in cna.get("networks", [])]
    overlays: set[str] = set()

    for comp in cna.get("composition", []):
        op = comp.get("operator")

        if op == "layering":
            underlay = ident(comp["underlay"])
            overlay = ident(comp["overlay"])
            overlays.add(overlay)
            enc = comp.get("session_identifier", {})
            field = enc.get("field", "")
            value = enc.get("value", "")
            if field and value:
                edges.setdefault(underlay, []).append(
                    (strip_header_prefix(field), value, overlay)
                )

        elif op == "subduction":
            underlay = ident(comp["underlay"])
            overlay = ident(comp["overlay"])
            enc_proto = comp.get("encapsulation_protocol")
            overlays.add(overlay)

            for sl in comp.get("shared_links", []):
                if sl.get("direction", "ingress") != "ingress":
                    # egress / delegate_to_underlay shared links are a
                    # forwarding concern, not a parser concern.
                    continue
                pred = sl.get("selection_predicate", {})
                field = pred.get("field", "")
                value = pred.get("value", "")
                if not (field and value):
                    continue
                field_name = strip_header_prefix(field)
                # Packets matching the predicate rise through the
                # encapsulation protocol first, then to the overlay.
                # If there is no encapsulation protocol they jump directly
                # to the overlay.
                target = ident(enc_proto) if enc_proto else overlay
                edges.setdefault(underlay, []).append((field_name, value, target))

            if enc_proto:
                enc_id = ident(enc_proto)
                overlays.add(enc_id)
                # Direct (unconditional) transition from encapsulation header
                # to overlay header — represented by an empty field_name.
                edges[enc_id] = [("", "", overlay)]

    # Session protocols are also conditional: they are only extracted when
    # their indicator field matches, so they belong in conditional_headers too.
    session_protos: set[str] = set()
    for net in cna.get("networks", []):
        net_id = ident(net["id"])
        for s in net.get("session_protocols", []):
            proto = ident(s["protocol"])
            field = s.get("indicator_field", "")
            field_name = strip_header_prefix(field)
            value = s.get("indicator_value", "")
            if field_name and value:
                edges.setdefault(net_id, []).append((field_name, value, proto))
                session_protos.add(proto)

    conditional_headers = overlays | session_protos

    roots = [n for n in networks if n not in overlays]
    root = roots[0] if roots else (networks[0] if networks else "")
    return edges, root, conditional_headers


def render_parser(cna: dict[str, Any], headers: dict[str, list[dict[str, Any]]]) -> str:
    edges, root, _ = build_parse_edges(cna)

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
            # A single edge with an empty field_name is a direct transition
            # (used for encapsulation-protocol -> overlay in subduction).
            if len(next_edges) == 1 and not next_edges[0][0]:
                states.append(f"        transition parse_{next_edges[0][2]};")
            else:
                field_name = next_edges[0][0]
                field_expr = f"hdr.{hname}.{field_name}"
                states.append(f"        transition select({field_expr}) {{")
                for _, value, nxt in next_edges:
                    if value:
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
            if op == Action.SetField:
                target = as_expr_target(operation["target"], header_names)
                value = as_expr_value(operation["value"])
                out.append(f"    {target} = {value};")
            elif op == Action.Decrement:
                target = as_expr_target(operation["target"], header_names)
                amount = operation.get("amount", 1)
                out.append(f"    {target} = {target} - {amount};")
            elif op == Action.SetEgressPort:
                value = as_expr_value(operation["value"])
                out.append(f"    standard_metadata.egress_spec = {value};")
            elif op == Action.Drop:
                out.append("    mark_to_drop(standard_metadata);")
            elif op == Action.Noop:
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
    """
    Generate the ingress control block.

    For each composition (layering or subduction) that declares forwarding
    actions, one match-action table is emitted.  The apply block then guards
    each table with a header-validity check so that:

      * Subduction overlay tables are applied first (higher priority): a packet
        carrying the inner overlay header is forwarded according to the overlay's
        rules.
      * Layering tables are applied in an else-if chain after subduction: a
        plain packet that never entered the overlay falls through to its own
        forwarding table.
    """
    header_names = set(headers.keys())

    action_defs: list[str] = []
    table_defs: list[str] = []

    # (table_name, overlay_header_id, operator)
    table_entries: list[tuple[str, str, str]] = []
    used_names: set[str] = set()

    for comp in cna.get("composition", []):
        op = comp.get("operator")
        if op not in ("layering", "subduction"):
            continue

        overlay = ident(comp.get("overlay", "net"))
        gname = ident(f"fwd_{overlay}")
        actions = comp.get("forwarding_actions", [])
        if not actions:
            continue

        rendered_actions: list[tuple[str, dict[str, Any]]] = []
        for a in actions:
            name = ident(a["id"])
            if name in used_names:
                raise ParseError(f"Duplicated action identifier: {name}")
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

        table_entries.append((tbl, overlay, op))

    # Build the apply block: subduction overlays take priority, then layering.
    subduction_entries = [(t, o) for t, o, op in table_entries if op == "subduction"]
    layering_entries = [(t, o) for t, o, op in table_entries if op == "layering"]
    ordered = subduction_entries + layering_entries

    apply_lines: list[str] = []
    if ordered:
        tbl, overlay = ordered[0]
        apply_lines.append(f"        if (hdr.{overlay}.isValid()) {{")
        apply_lines.append(f"            {tbl}.apply();")
        for tbl, overlay in ordered[1:]:
            apply_lines.append(f"        }} else if (hdr.{overlay}.isValid()) {{")
            apply_lines.append(f"            {tbl}.apply();")
        apply_lines.append("        }")

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


def render_deparser(
    cna: dict[str, Any],
    headers: dict[str, list[dict[str, Any]]],
) -> str:
    """
    Generate the deparser control block.

    Headers that are only extracted on a conditional parser branch (overlays,
    encapsulation protocols, and session protocols) are wrapped in an isValid()
    guard to make the conditionality explicit.  Headers that are always
    extracted (the parser root and any unconditional successor) are emitted
    without a guard.

    Although P4's emit() is already a no-op for invalid headers, the explicit
    guards make the deparser self-documenting: a reader can see which headers
    are optional without tracing the parser graph.
    """
    _, _, conditional_headers = build_parse_edges(cna)

    out = ["control DeparserImpl(packet_out packet, in headers_t hdr) {", "    apply {"]
    for hname in headers.keys():
        if hname in conditional_headers:
            out.append(indent_line(f"if (hdr.{hname}.isValid()) {{", 2))
            out.append(indent_line(f"    packet.emit(hdr.{hname});", 2))
            out.append(indent_line("}", 2))
        else:
            out.append(indent_line(f"packet.emit(hdr.{hname});", 2))
    out.append(indent_line("}", 1))
    out.append("}")
    return "\n".join(out)


def render_verify_checksum() -> str:
    return (
        "control EmptyVerifyChecksum(inout headers_t hdr, inout metadata_t meta) {\n"
        "    apply { }\n"
        "}"
    )


def render_compute_checksum() -> str:
    return (
        "control EmptyComputeChecksum(inout headers_t hdr, inout metadata_t meta) {\n"
        "    apply { }\n"
        "}"
    )


def generate_p4(cna: dict[str, Any]) -> str:
    check_composition_cycles(cna)

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
        render_ingress(cna, headers),
        "",
        render_egress(),
        "",
        render_deparser(cna, headers),
        "",
        render_verify_checksum(),
        "",
        render_compute_checksum(),
        "",
        "V1Switch(",
        "    ParserImpl(),",
        "    EmptyVerifyChecksum(),",
        "    IngressImpl(),",
        "    EgressImpl(),",
        "    EmptyComputeChecksum(),",
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
        help="Output P4 file (default: <n>.p4 derived from CNA root 'name')",
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
