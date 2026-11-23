// Synthetic demo component tree.
import React from 'react';
import { createRoot } from 'react-dom/client';
import chalk from 'chalk';

export function Dashboard({ metrics }) {
  console.log(chalk.green('render'), metrics.length);
  return <table>{metrics.map((row) => <tr key={row.id}>{row.label}</tr>)}</table>;
}

export function mount(node) {
  createRoot(node).render(<Dashboard metrics={[]} />);
}
