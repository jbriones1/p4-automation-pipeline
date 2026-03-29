# pyright: reportAny=false
# pyright: reportExplicitAny=false
# pyright: reportUnknownArgumentType=false
import argparse
import json
import re
from typing import Any


def ident(name: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9_]", "_", name)
    if not s:
        s = "x"
    if s[0].isdigit():
        s = "_" + s
    return s


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


def collect_headers(cna: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    headers: dict[str, list[dict[str, Any]]] = {}

    for n in cna.get("networks", []):
        headers[ident(n["id"])] = n.get("forwarding_header", [])

    for p in cna.get("protocols", []):
        headers[ident(p["id"])] = p.get("headers", [])

    return headers


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
    edges: dict[str, list[tuple[str, str, str]]] = {}

    networks = [ident(n["id"]) for n in cna.get("networks", [])]

    overlays: set[str] = set()
    for comp in cna.get("composition", []):
        if comp.get("operator") == "layering":
            underlay = ident(comp["underlay"])
            overlay = ident(comp["overlay"])
            overlays.add(overlay)
            enc = comp.get("encapsulation", {})
            field = enc.get("indicator_field")
            value = enc.get("indicator_value")
            if field and value:
                edges.setdefault(underlay, []).append((field, value, overlay))

    for net in cna.get("networks", []):
        net_id = ident(net["id"])
        for s in net.get("session_protocols", []):
            proto = ident(s["protocol"])
            field = s["indicator_field"]
            value = s["indicator_value"]
            edges.setdefault(net_id, []).append((field, value, proto))

    roots = [n for n in networks if n not in overlays]
    root = roots[0] if roots else (networks[0] if networks else "")

    return edges, root


def render_parser(cna: dict[str, Any], headers: dict[str, list[dict[str, Any]]]) -> str:
    header_names = set(headers.keys())
    edges, root = build_parse_edges(cna)

    states: list[str] = []
    states.append(
        "parser ParserImpl(packet_in packet, out headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {"
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
    primitives = action.get("primitives", [])

    param_strs: list[str] = []
    for p in params:
        pname = ident(p["name"])
        if "type" in p:
            ptype = ident(p["type"])
        else:
            ptype = f"bit<{int(p['bit_width'])}>"
        param_strs.append(f"{ptype} {pname}")

    out = [f"action {name}({', '.join(param_strs)}) {{"]

    if not primitives:
        out.append("    // no primitives")
    else:
        for prim in primitives:
            op = prim.get("op")
            if op == "set_field":
                target = as_expr_target(prim["target"], header_names)
                value = as_expr_value(prim["value"])
                out.append(f"    {target} = {value};")
            elif op == "decrement":
                target = as_expr_target(prim["target"], header_names)
                amount = prim.get("amount", 1)
                out.append(f"    {target} = {target} - {amount};")
            elif op == "set_egress_port":
                value = as_expr_value(prim["value"])
                out.append(f"    standard_metadata.egress_spec = {value};")
            elif op == "drop":
                out.append("    mark_to_drop(standard_metadata);")
            elif op == "noop":
                out.append("    ;")
            else:
                out.append(f"    // unsupported primitive: {op}")

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

    groups: list[tuple[str, list[dict[str, Any]]]] = []

    for comp in cna.get("composition", []):
        gname = ident(f"fwd_{comp.get('overlay', 'net')}")
        groups.append((gname, comp.get("forwarding_actions", [])))

    for mb in cna.get("middleboxes", []):
        gname = ident(f"{mb['id']}_policy")
        groups.append((gname, mb.get("actions", [])))

    used_names: set[str] = set()

    for gname, actions in groups:
        if not actions:
            continue

        rendered_actions: list[tuple[str, dict[str, Any]]] = []
        for a in actions:
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
        "control IngressImpl(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {",
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
    return """control EgressImpl(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {
    apply {
    }
}"""


def render_verify_checksum() -> str:
    return """control VerifyChecksumImpl(inout headers_t hdr, inout metadata_t meta) {
    apply {
    }
}"""


def render_compute_checksum() -> str:
    return """control ComputeChecksumImpl(inout headers_t hdr, inout metadata_t meta) {
    apply {
    }
}"""


def render_deparser(headers: dict[str, list[dict[str, Any]]]) -> str:
    out = ["control DeparserImpl(packet_out packet, in headers_t hdr) {", "    apply {"]
    for hname in headers.keys():
        out.append(f"        packet.emit(hdr.{hname});")
    out.append("    }")
    out.append("}")
    return "\n".join(out)


def generate_p4(cna: dict[str, Any]) -> str:
    typedefs_txt, typedefs = render_typedefs(cna.get("typedefs", []))
    headers = collect_headers(cna)

    parts = [
        "#include <core.p4>",
        "#include <v1model.p4>",
        "",
        "const bit<16> TYPE_IPV4 = 0x0800;",
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
        help="Output P4 file (default: <name>.p4 from CNA root 'name')",
    )
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8") as f:
        cna = json.load(f)

    output_path = args.output
    if not output_path:
        cna_name = cna.get("name")
        if not isinstance(cna_name, str) or not cna_name.strip():
            raise ValueError(
                "CNA root object must contain a non-empty 'name' when --output is not provided"
            )
        output_path = f"{ident(cna_name)}.p4"

    p4_code = generate_p4(cna)

    with open(output_path, "w", encoding="utf-8") as f:
        _ = f.write(p4_code)

    print(f"Generated {output_path} from {args.input}")


if __name__ == "__main__":
    main()
