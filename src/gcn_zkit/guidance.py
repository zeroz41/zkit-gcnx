"""Native-port guidance shared by MCP and session context; policy comes from each project."""

PORT_GUIDANCE = (
    'For native porting, read the project architecture/quality contract and identify the shared owner, '
    'interfaces, dependency direction and lifetime before implementation. Prefer composed reusable behavior '
    'and validated data over copied controllers or monolithic per-content paths; use inheritance only where '
    'substitutability and ownership fit. Keep original formats and protocols in adapters/importers, with native '
    'definitions/events crossing the boundary. Recover authored commands and metadata: never fabricate behavior '
    'from an asset name, identity, shape or one sample layout. Automate discovery, dependency closure, conversion '
    'and validation through the project importer so newly discovered content follows the same path; preserve '
    'outputs on failure and report unsupported records explicitly. Carry the requested system through import, '
    'native definitions, shared runtime, live admission and registered verification. Inventory coverage or a '
    'component comparison is not completion. These port architecture rules do not refactor matching decomp: '
    'preserve its original layout, translation units, compiler constraints and byte-match requirements.'
)
