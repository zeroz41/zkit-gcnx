"""Fidelity recipe preflight (recipe_format fidelity-v1). Running a recipe stays with the native repo."""

from __future__ import annotations

import json
import re

from .project import Project, file_record


def check_recipe(project: Project, reference: str, catalog_reference: str | None = None) -> dict:
    repository, _, _ = reference.partition(":")
    repo = project.config["repositories"].get(repository, {})
    if repo.get("recipe_format") != "fidelity-v1":
        raise ValueError("This adapter requires recipe_format=fidelity-v1")
    base = project.file(repository, repo["recipes"])
    path = project.reference(reference)
    if not path.is_relative_to(base) or path.suffix != ".json":
        raise ValueError("Recipe must be JSON inside the configured recipe directory")
    recipe = json.loads(path.read_text(encoding="utf-8"))
    errors, evidence = [], []
    for field in ("boundary", "excluded", "evidence", "packages", "original_checks", "tests"):
        if field not in recipe:
            errors.append(f"Missing {field}")
    if not isinstance(recipe.get("boundary"), str) or not recipe.get("boundary", "").strip():
        errors.append("Boundary must be nonempty text")
    for field in ("excluded", "evidence", "packages", "tests"):
        if not isinstance(recipe.get(field), list) or any(not isinstance(x, str) or not x.strip() for x in recipe.get(field, [])):
            errors.append(f"{field} must be a list of nonempty strings")
    tests = recipe.get("tests", [])
    if isinstance(tests, list) and all(isinstance(x, str) for x in tests):
        if not tests or len(set(tests)) != len(tests):
            errors.append("Tests must be nonempty and unique")
    for entry in recipe.get("evidence", []) if isinstance(recipe.get("evidence"), list) else []:
        if not isinstance(entry, str):
            continue
        match = re.fullmatch(r"\{(root|decomp|build|data)\}/(.+)", entry)
        if not match:
            errors.append(f"Unsupported evidence path: {entry}")
            continue
        owner = repo.get("decomp_repository") if match[1] == "decomp" else repository
        if owner not in project.config["repositories"]:
            errors.append("Missing decomp_repository binding")
            continue
        relative = match[2]
        if match[1] in {"build", "data"}:
            binding = repo.get("recipe_bindings", {}).get(match[1])
            if not isinstance(binding, str) or not binding:
                errors.append(f"Missing explicit recipe_bindings.{match[1]} for {entry}")
                continue
            relative = binding + "/" + relative
        evidence_path = project.file(owner, relative)
        row = {"reference": f"{owner}:{relative}", **file_record(evidence_path)}
        evidence.append(row)
        if not row["exists"]:
            errors.append(f"Missing evidence: {row['reference']}")
    if not evidence:
        errors.append("At least one resolvable evidence file is required")
    checks = recipe.get("original_checks", [])
    if not isinstance(checks, list) or not checks:
        errors.append("At least one original check is required")
    else:
        names = set()
        for check in checks:
            if not isinstance(check, dict):
                errors.append("Original checks must be objects")
                continue
            name = check.get("name")
            if not isinstance(name, str) or not name or name in names:
                errors.append("Original checks need unique names")
            else:
                names.add(name)
            command = check.get("command")
            if not isinstance(command, list) or not command or any(not isinstance(x, str) for x in command):
                errors.append("Original commands must be nonempty argv arrays")
            timeout = check.get("timeout")
            if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not 0 < timeout <= 3600:
                errors.append("Original checks need a finite timeout in (0,3600]")
    coverage = {"status": "not-checked", "reason": "Supply a CTest --show-only=json-v1 catalog reference"}
    if catalog_reference:
        catalog_path = project.reference(catalog_reference)
        catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
        available = {test["name"]: test for test in catalog["tests"]}
        missing, disabled = [], []
        for name in tests if isinstance(tests, list) else []:
            if not isinstance(name, str):
                continue
            if name not in available:
                missing.append(name)
            elif any(p["name"] == "DISABLED" and p["value"] for p in available[name].get("properties", [])):
                disabled.append(name)
        if missing or disabled:
            errors.append("Required CTests are missing or disabled")
        coverage = {"status": "failed" if missing or disabled else "registered-in-supplied-catalog",
                    "missing": missing, "disabled": disabled, "catalog": file_record(catalog_path),
                    "limits": "Catalog freshness, content root, fixture expansion and execution are not proven"}
    return {"reference": reference, "recipe": file_record(path), "ready_for_review": not errors,
            "boundary": recipe.get("boundary"), "excluded": recipe.get("excluded", []),
            "errors": errors, "evidence": evidence, "test_registration": coverage,
            "executed": False, "behavior_verified": False,
            "next": "Run tools/verify-fidelity.py with this recipe and explicit build/data/iso/report paths"}
