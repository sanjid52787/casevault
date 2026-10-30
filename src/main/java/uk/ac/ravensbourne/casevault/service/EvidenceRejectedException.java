package uk.ac.ravensbourne.casevault.service;

/** Safe, opaque rejection used for evidence validation and integrity failures (CWE-209). */
public final class EvidenceRejectedException extends RuntimeException {
    public EvidenceRejectedException() {
        super("Evidence rejected");
    }
}
