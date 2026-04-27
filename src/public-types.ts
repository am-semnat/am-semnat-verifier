export type DerBytes = Uint8Array;

export interface PassiveVerificationInput {
  rawSod: DerBytes;
  dataGroups: Record<number, DerBytes>;
  trustAnchors: DerBytes[];
}

export interface DataGroupVerificationResult {
  dgNumber: number;
  valid: boolean;
  error?: string;
}

export interface PassiveVerificationResult {
  valid: boolean;
  errors: string[];
  signerCommonName: string | null;
  signedAt: Date | null;
  dataGroupResults: DataGroupVerificationResult[];
}

export interface PadesVerificationInput {
  pdf: DerBytes;
  trustAnchors: DerBytes[];
}

export interface PadesVerificationResult {
  valid: boolean;
  errors: string[];
  signerCommonName: string | null;
  signedAt: Date | null;
  signatureIndex: number;
  fieldName: string | null;
  byteRange: [number, number, number, number];
  coversWholeDocument: boolean;
}
