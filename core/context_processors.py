"""
Context processors for CaseVault core application.
"""

def csp_nonce(request):
    """
    Exposes the per-request CSP nonce to templates for safe script/style inclusion.
    """
    return {
        'csp_nonce': getattr(request, 'csp_nonce', '')
    }

