import { Client as AttestationClient } from "@lafiya/attestation-registry";
import { Client as AttesterClient } from "@lafiya/attester-registry";
import { Client as StatusListClient } from "@lafiya/status-list";
import { Buffer } from "buffer";
import type { AttesterState, ChainReader, OnChainAttestation } from "./chain.js";
import type { NetworkTrust } from "./trust.js";

/** A versioned status-list segment as stored on-chain. */
export interface StatusListSegment {
  /** Segment index within the status list. */
  index: number;
  /** Monotonic version of this segment's contents. */
  version: number;
  /** Raw bitstring bytes for the segment. */
  bits: Uint8Array;
}

/** A signed commitment over the status-list root. */
export interface StatusListRoot {
  /** Monotonic version of the signed root. */
  version: number;
  /** Root commitment (hex-encoded) over all segment commitments. */
  root: string;
  /** Ledger timestamp at which the root was signed. */
  timestamp: bigint;
  /** Signature over the root commitment. */
  signature: string;
}

/** Reads contract state over Soroban RPC through the generated bindings. */
export class BindingsChainReader implements ChainReader {
  readonly source = "rpc" as const;

  constructor(private readonly options: { allowHttp?: boolean } = {}) {}

  private clientOptions(trust: NetworkTrust, contractId: string) {
    return {
      contractId,
      networkPassphrase: trust.networkPassphrase,
      rpcUrl: trust.rpcUrl,
      allowHttp: this.options.allowHttp,
    };
  }

  async getAttestation(trust: NetworkTrust, recordHash: string) {
    const client = new AttestationClient(this.clientOptions(trust, trust.attestationRegistry));
    const tx = await client.get_attestation({ record_hash: Buffer.from(recordHash, "hex") });
    return tx.result ? toAttestation(tx.result) : null;
  }

  async getAttestationHistory(trust: NetworkTrust, recordHash: string) {
    const client = new AttestationClient(this.clientOptions(trust, trust.attestationRegistry));
    const tx = await client.get_attestation_history({
      record_hash: Buffer.from(recordHash, "hex"),
    });
    return tx.result.map(toAttestation);
  }

  async getAttesterStatus(trust: NetworkTrust, attester: string): Promise<AttesterState | null> {
    const client = new AttesterClient(this.clientOptions(trust, trust.attesterRegistry));
    const status = (await client.get_attester_status({ attester })).result;
    if (!status) return null;
    return {
      suspended: status.suspended,
      ...(status.info.region ? { region: String(status.info.region) } : {}),
    };
  }

  async getStatusListRoot(trust: NetworkTrust): Promise<StatusListRoot | null> {
    const client = new StatusListClient(this.clientOptions(trust, trust.statusList));
    const root = (await client.get_root()).result;
    if (!root) return null;
    return {
      version: Number(root.version),
      root: Buffer.from(root.root).toString("hex"),
      timestamp: BigInt(root.timestamp),
      signature: Buffer.from(root.signature).toString("hex"),
    };
  }

  async getStatusListSegment(trust: NetworkTrust, index: number): Promise<StatusListSegment | null> {
    const client = new StatusListClient(this.clientOptions(trust, trust.statusList));
    const segment = (await client.get_segment({ index })).result;
    if (!segment) return null;
    return {
      index: Number(segment.index),
      version: Number(segment.version),
      bits: Uint8Array.from(segment.bits),
    };
  }
}

function toAttestation(a: { attester: string; timestamp: bigint | number }): OnChainAttestation {
  return { attester: a.attester, timestamp: BigInt(a.timestamp) };
}
