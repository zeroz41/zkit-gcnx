"""Port guidance shared by the MCP instructions and the session brief; each project supplies its own policy."""

PORT_GUIDANCE = (
    "Porting: behavior comes only from decomp code that is matched, named and clean (`zkit port-plan` marks "
    "each function); anything unclear is decomp work first or an explicitly unsupported boundary, never a guess. "
    "Reproduce what the original observably does, not how its era-bound code was structured: shared owners, "
    "interfaces at real boundaries, composition, data-driven content through the importer, protocol adapters "
    "feeding a native interface. Fix causes where the original computes them, for every consumer, not per object. "
    "Presentation can be reimplemented freely, but with enhancements off it must match the original. These rules "
    "never restructure the matching decomp. `zkit contract port` has the full contract."
)
