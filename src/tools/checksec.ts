import { exec } from './exec.js';

export interface Protections {
  nx: boolean;
  canary: boolean;
  pie: boolean;
  relro: 'no' | 'partial' | 'full';
  fortify: boolean;
}

export function parseChecksecOutput(raw: string, binaryPath: string): Protections {
  const json = JSON.parse(raw) as Record<string, unknown>;

  let entry = json[binaryPath] as Record<string, unknown> | undefined;
  if (!entry) {
    const firstKey = Object.keys(json)[0];
    if (!firstKey) throw new Error('checksec: empty JSON output');
    entry = json[firstKey] as Record<string, unknown>;
  }

  const nx = entry['nx'] === 'yes';
  const canary = entry['stack_canary'] === 'yes';
  const pie = entry['pie'] === 'yes';

  const relroRaw = String(entry['relro'] ?? '').toLowerCase();
  const relro: 'no' | 'partial' | 'full' =
    relroRaw === 'full' ? 'full' : relroRaw === 'partial' ? 'partial' : 'no';

  const fortify =
    entry['fortify_source'] === 'yes' ||
    (typeof entry['fortified'] === 'number' && (entry['fortified'] as number) > 0) ||
    entry['fortified'] === 'yes';

  return { nx, canary, pie, relro, fortify };
}

export async function runChecksec(binaryPath: string): Promise<Protections> {
  const result = await exec('checksec', ['--format=json', `--file=${binaryPath}`]);
  return parseChecksecOutput(result.stdout, binaryPath);
}
