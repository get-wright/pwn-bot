import { exec } from './exec.js';

export interface Gadget {
  address: number;
  instructions: string;
}

export function parseRopGadgetOutput(raw: string): Gadget[] {
  const gadgets: Gadget[] = [];

  for (const line of raw.split('\n')) {
    // Format: "0x0000000000401234 : pop rdi ; ret"
    const match = line.match(/^(0x[0-9a-fA-F]+)\s*:\s*(.+)$/);
    if (match) {
      gadgets.push({
        address: parseInt(match[1], 16),
        instructions: match[2].trim(),
      });
    }
  }

  return gadgets;
}

export async function findGadgets(binaryPath: string, filter?: string): Promise<Gadget[]> {
  const args = ['--binary', binaryPath, '--rop'];
  if (filter) {
    args.push('--re', filter);
  }

  const result = await exec('ROPgadget', args, { timeout: 60_000 });
  return parseRopGadgetOutput(result.stdout);
}

export function findGadget(gadgets: Gadget[], pattern: string): Gadget | undefined {
  return gadgets.find((g) => g.instructions.includes(pattern));
}
