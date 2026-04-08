import { exec } from './exec.js';

export interface OneGadgetResult {
  address: number;
  constraints: string[];
}

export function parseOneGadgetOutput(raw: string): OneGadgetResult[] {
  const results: OneGadgetResult[] = [];
  const lines = raw.split('\n');

  let currentAddress: number | null = null;
  let currentConstraints: string[] = [];

  for (const line of lines) {
    const addrMatch = line.match(/^(0x[0-9a-fA-F]+)/);
    if (addrMatch) {
      if (currentAddress !== null) {
        results.push({ address: currentAddress, constraints: currentConstraints });
      }
      currentAddress = parseInt(addrMatch[1], 16);
      currentConstraints = [];
      continue;
    }

    if (currentAddress !== null) {
      const trimmed = line.trim();
      // Constraint lines are non-empty lines that follow an address line
      if (trimmed && !trimmed.startsWith('#')) {
        currentConstraints.push(trimmed);
      }
    }
  }

  if (currentAddress !== null) {
    results.push({ address: currentAddress, constraints: currentConstraints });
  }

  return results;
}

export async function findOneGadgets(libcPath: string): Promise<OneGadgetResult[]> {
  const result = await exec('one_gadget', [libcPath], { timeout: 30_000 });
  return parseOneGadgetOutput(result.stdout);
}
