"""Port guidance shared by the MCP instructions and the session brief; each project supplies its own policy."""

PORT_GUIDANCE = (
    "Porting (a source port by default): the decomp's game code compiles natively, unchanged except at declared "
    "edit sites, and links against a native library instead of the console SDK, so the port changes the game as "
    "little as possible. Behavior comes from the matched decomp itself (`zkit port-plan` marks what is matched, "
    "named and clean); a function that exists only as assembly is an unsupported boundary until it is matched. "
    "Game code keeps the original's structure. Kits replace a middleware library's hardware-facing functions and "
    "leave its logic alone; a seam replaces the shared middleware owner, never single call sites. Every edit to a "
    "decomp file is one of five declared kinds (seam call site, portability, interpolation hook, enhancement, "
    "change), and the matching build still builds and matches. Original formats are read only by the importer. "
    "Simulation sees ticks only. `zkit contract source-port` has the full contract; `zkit contract port` is for a "
    "native rewrite that uses the decomp only as its behavioral reference."
)
