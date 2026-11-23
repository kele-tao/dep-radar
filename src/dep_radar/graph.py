"""Graph algorithms over the resolved dependency tree.

Everything here is linear in edges (O(V+E)) so a 1000-package tree stays well
under the 2 s budget on a laptop.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from .model import Project


@dataclass
class GraphStats:
    """Aggregate shape of the tree."""

    total: int = 0
    direct: int = 0
    transitive: int = 0
    max_depth: int = 0
    depth_histogram: dict[int, int] = field(default_factory=dict)
    duplicates: dict[str, list[str]] = field(default_factory=dict)
    duplicate_versions: int = 0
    orphaned: list[str] = field(default_factory=list)
    dev_only: int = 0
    optional_only: int = 0
    by_ecosystem: dict[str, int] = field(default_factory=dict)

    @property
    def mean_depth(self) -> float:
        if not self.depth_histogram:
            return 0.0
        weighted = sum(depth * count for depth, count in self.depth_histogram.items())
        return round(weighted / max(1, sum(self.depth_histogram.values())), 2)


def adjacency(project: Project) -> dict[str, list[str]]:
    """Parent key -> ordered unique child keys. '' is the project root."""
    table: dict[str, list[str]] = {}
    for edge in project.edges:
        children = table.setdefault(edge.parent, [])
        if edge.child not in children:
            children.append(edge.child)
    return table


def depths(project: Project) -> dict[str, int]:
    """Shortest distance from the project root for every reachable package."""
    table = adjacency(project)
    result: dict[str, int] = {}
    queue: deque[tuple[str, int]] = deque([("", 0)])
    while queue:
        node, depth = queue.popleft()
        for child in table.get(node, []):
            if child in result:
                continue
            result[child] = depth
            queue.append((child, depth + 1))
    return result


def all_paths(
    project: Project, target: str, limit: int = 3, max_depth: int = 12
) -> list[list[str]]:
    """Shortest simple paths from the root to *target*, breadth first."""
    table = adjacency(project)
    found: list[list[str]] = []
    queue: deque[list[str]] = deque([[""]])
    while queue and len(found) < limit:
        path = queue.popleft()
        node = path[-1]
        if len(path) > max_depth:
            continue
        for child in table.get(node, []):
            if child in path:
                continue
            extended = path + [child]
            if child == target:
                found.append(extended)
                if len(found) >= limit:
                    break
            else:
                queue.append(extended)
    return found


def reachable_from(project: Project, start: str) -> set[str]:
    """Every package reachable from *start* (excluding start itself)."""
    table = adjacency(project)
    seen: set[str] = set()
    queue: deque[str] = deque([start])
    while queue:
        node = queue.popleft()
        for child in table.get(node, []):
            if child in seen:
                continue
            seen.add(child)
            queue.append(child)
    return seen


def roots(project: Project) -> set[str]:
    """Packages no other package depends on (the top of the tree)."""
    has_parent = {edge.child for edge in project.edges if edge.parent}
    return {key for key in project.packages if key not in has_parent}


def compute_stats(project: Project) -> GraphStats:
    """Compute depth, duplication and reachability statistics in one pass."""
    depth_map = depths(project)
    stats = GraphStats()
    stats.total = len(project.packages)
    stats.direct = len({edge.child for edge in project.edges if edge.parent == ""})
    stats.transitive = max(0, stats.total - stats.direct)
    for depth in depth_map.values():
        stats.depth_histogram[depth] = stats.depth_histogram.get(depth, 0) + 1
    stats.max_depth = max(stats.depth_histogram) if stats.depth_histogram else 0

    versions: dict[str, list[str]] = {}
    for package in project.packages.values():
        versions.setdefault(package.name, []).append(package.version or "unversioned")
    for name, items in versions.items():
        unique = sorted(set(items))
        if len(unique) > 1:
            stats.duplicates[name] = unique
            stats.duplicate_versions += len(unique) - 1

    stats.orphaned = sorted(key for key in project.packages if key not in depth_map)
    stats.dev_only = len([p for p in project.packages.values() if p.dev and not p.optional])
    stats.optional_only = len([p for p in project.packages.values() if p.optional])
    for package in project.packages.values():
        needle = package.ecosystem.value
        stats.by_ecosystem[needle] = stats.by_ecosystem.get(needle, 0) + 1
    return stats


def explain(project: Project, query: str) -> dict:
    """Answer 'why is this in my tree' for a package name or key."""
    lowered = query.strip().lower()
    matches = [
        package
        for package in project.packages.values()
        if package.name.lower() == lowered or package.key.lower() == lowered
    ]
    if not matches:
        matches = [
            package for package in project.packages.values() if lowered in package.name.lower()
        ]
    if not matches:
        return {"query": query, "found": False, "matches": []}
    depth_map = depths(project)
    direct_declared = {dep.name.split("[")[0].lower() for dep in project._root_declared}
    results = []
    for package in sorted(matches, key=lambda p: (p.name, p.version or "")):
        paths = all_paths(project, package.key, limit=3)
        rendered = []
        for path in paths:
            rendered.append(
                ["<root>"] + [project.packages[key].display for key in path[1:] if key in project.packages]
            )
        is_direct = package.name.split("[")[0].lower() in direct_declared
        results.append(
            {
                "key": package.key,
                "name": package.name,
                "version": package.version,
                "ecosystem": package.ecosystem.value,
                "direct": is_direct,
                "depth": depth_map.get(package.key),
                "paths": rendered,
                "via": (
                rendered[0][1]
                if not is_direct and rendered and len(rendered[0]) > 1
                else None
            ),
                "parents": sorted(
                    {
                        project.packages[e.parent].display
                        for e in project.parents(package.key)
                        if e.parent in project.packages
                    }
                ),
                "license": package.license,
                "source_kind": package.source_kind,
            }
        )
    return {"query": query, "found": True, "matches": results}
