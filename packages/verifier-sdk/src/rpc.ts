import { Client as AttestationClient } from "@lafiya/attestation-registry";
import { Client as AttesterClient } from "@lafiya/attester-registry";
import { Buffer } from "buffer";
import type { AttesterState, ChainReader, OnChainAttestation } from "./chain.js";
import {
  callWithPolicy,
  DEFAULT_RETRY,
  DEFAULT_TIMEOUT_MS,
  type CallOptions,
  type RetryPolicy,
} from "./transport.js";
import type { NetworkTrust } from "./trust.js";

export interface BindingsChainReaderOptions {
  allowHttp?: boolean;
  /** Default per-attempt deadline; a call's own `timeoutMs` wins. */
  timeoutMs?: number;
  /** Retry budget for reads (all reads here are idempotent). */
  retry?: RetryPolicy;
}

/**
 * Reads contract state over Soroban RPC through the generated bindings.
 * Every read honours `signal`/`timeoutMs`, is retried within the retry
 * budget, and fails with a typed {@link TransportError}.
 */
export class BindingsChainReader implements ChainReader {
  readonly source = "rpc" as const;

  constructor(private readonly options: BindingsChainReaderOptions = {}) {}

  private clientOptions(trust: NetworkTrust, contractId: string) {
    return {
      contractId,
      networkPassphrase: trust.networkPassphrase,
      rpcUrl: trust.rpcUrl,
      allowHttp: this.options.allowHttp,
    };
  }

  private read<T>(fn: () => Promise<T>, opts: CallOptions = {}): Promise<T> {
    return callWithPolicy(fn, {
      signal: opts.signal,
      timeoutMs: opts.timeoutMs ?? this.options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
      retry: this.options.retry ?? DEFAULT_RETRY,
      idempotent: true,
    });
  }

  async getAttestation(trust: NetworkTrust, recordHash: string, opts?: CallOptions) {
    const client = new AttestationClient(this.clientOptions(trust, trust.attestationRegistry));
    const tx = await this.read(
      () => client.get_attestation({ record_hash: Buffer.from(recordHash, "hex") }),
      opts,
    );
    return tx.result ? toAttestation(tx.result) : null;
  }

  async getAttestationHistory(trust: NetworkTrust, recordHash: string, opts?: CallOptions) {
    const client = new AttestationClient(this.clientOptions(trust, trust.attestationRegistry));
    const tx = await this.read(
      () => client.get_attestation_history({ record_hash: Buffer.from(recordHash, "hex") }),
      opts,
    );
    return tx.result.map(toAttestation);
  }

  async getAttesterStatus(
    trust: NetworkTrust,
    attester: string,
    opts?: CallOptions,
  ): Promise<AttesterState | null> {
    const client = new AttesterClient(this.clientOptions(trust, trust.attesterRegistry));
    const status = (await this.read(() => client.get_attester_status({ attester }), opts)).result;
    if (!status) return null;
    return {
      suspended: status.suspended,
      ...(status.info.region ? { region: String(status.info.region) } : {}),
    };
  }
}

function toAttestation(a: { attester: string; timestamp: bigint | number }): OnChainAttestation {
  return { attester: a.attester, timestamp: BigInt(a.timestamp) };
}
