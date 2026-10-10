import { useState, type ReactNode } from "react";

export interface Column<T> {
  header: string;
  cell: (row: T) => ReactNode;
  width?: string;
}

/**
 * List view in the style of a Qt QTreeView: grid lines, alternating rows,
 * click selects, double click opens. With `parentOf`, rows are shown as a
 * collapsible tree (first column indented).
 */
export function ListView<T extends { id: number }>({
  rows,
  columns,
  selected,
  onSelect,
  onOpen,
  empty,
  parentOf,
}: {
  rows: T[];
  columns: Column<T>[];
  selected: number | null;
  onSelect: (id: number) => void;
  onOpen?: (id: number) => void;
  empty: string;
  parentOf?: (row: T) => number | null;
}) {
  const [collapsed, setCollapsed] = useState<Set<number>>(new Set());

  let ordered: { row: T; depth: number; hasChildren: boolean }[];
  if (parentOf) {
    const ids = new Set(rows.map((r) => r.id));
    const children = new Map<number | null, T[]>();
    for (const r of rows) {
      const p = parentOf(r);
      const key = p !== null && ids.has(p) ? p : null;
      children.set(key, [...(children.get(key) ?? []), r]);
    }
    ordered = [];
    const walk = (parent: number | null, depth: number) => {
      for (const r of children.get(parent) ?? []) {
        const kids = children.get(r.id) ?? [];
        ordered.push({ row: r, depth, hasChildren: kids.length > 0 });
        if (!collapsed.has(r.id)) walk(r.id, depth + 1);
      }
    };
    walk(null, 0);
  } else {
    ordered = rows.map((row) => ({ row, depth: 0, hasChildren: false }));
  }

  function toggle(id: number) {
    setCollapsed((c) => {
      const n = new Set(c);
      if (n.has(id)) n.delete(id);
      else n.add(id);
      return n;
    });
  }

  return (
    <div
      className="listview h-full"
      tabIndex={0}
      onKeyDown={(e) => {
        const i = ordered.findIndex((o) => o.row.id === selected);
        if (e.key === "ArrowDown" && i < ordered.length - 1) onSelect(ordered[i + 1].row.id);
        if (e.key === "ArrowUp" && i > 0) onSelect(ordered[i - 1].row.id);
        if (e.key === "Enter" && selected !== null) onOpen?.(selected);
      }}
    >
      <table>
        <colgroup>
          {columns.map((c) => (
            <col key={c.header} style={{ width: c.width }} />
          ))}
        </colgroup>
        <thead>
          <tr>
            {columns.map((c) => (
              <th key={c.header}>{c.header}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {ordered.map(({ row, depth, hasChildren }) => (
            <tr
              key={row.id}
              aria-selected={selected === row.id}
              onMouseDown={() => onSelect(row.id)}
              onDoubleClick={() => onOpen?.(row.id)}
            >
              {columns.map((c, ci) => (
                <td key={c.header}>
                  {ci === 0 && parentOf ? (
                    <span style={{ paddingLeft: depth * 16 }}>
                      <span
                        className="twisty"
                        onMouseDown={(e) => {
                          e.stopPropagation();
                          if (hasChildren) toggle(row.id);
                        }}
                      >
                        {hasChildren ? (collapsed.has(row.id) ? "▶" : "▼") : ""}
                      </span>
                      {c.cell(row)}
                    </span>
                  ) : (
                    c.cell(row)
                  )}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
      {ordered.length === 0 && <div className="muted p-4 text-center">{empty}</div>}
    </div>
  );
}
