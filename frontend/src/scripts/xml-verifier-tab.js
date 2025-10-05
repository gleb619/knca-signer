export default () => ({
    activeSubTab: 'verify',

    // Form data for XML verification
    xmlContent: `\
<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<root>
	<item>Sample content to verify</item>
	<signature>Sample signature here</signature>
	<ds:Signature
		xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
		<ds:SignedInfo>
			<ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
			<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
			<ds:Reference URI="">
				<ds:Transforms>
					<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
					<ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"/>
				</ds:Transforms>
				<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
				<ds:DigestValue>b2458b13-78ab-4d9d-89aa-c20f0e1a79a2</ds:DigestValue>
			</ds:Reference>
		</ds:SignedInfo>
		<ds:SignatureValue>46f7e78c-bda5-44a9-a907-274aa1b0532e</ds:SignatureValue>
		<ds:KeyInfo>
			<ds:X509Data>
				<ds:X509Certificate>bfe57dc8-ed87-4f36-8496-ba566e02445e</ds:X509Certificate>
			</ds:X509Data>
		</ds:KeyInfo>
	</ds:Signature>
</root>`,
    validationResult: null,
    isValidating: false,

    initXmlVerifier() {
        //ignore
    },

    async validateXml() {
        // Clear previous messages
        this.errorMessage = '';
        this.successMessage = '';

        // Validation
        if (!this.xmlContent || !this.xmlContent.trim()) {
            this.errorMessage = 'XML content cannot be empty';
            return;
        }

        this.isValidating = true;

        try {
            const response = await fetch('/api/validate/xml', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    xml: this.xmlContent.trim()
                })
            });

            const result = await response.json();

            if (!response.ok) {
                throw new Error(result.error || 'Validation failed');
            }

            this.validationResult = result;

            if (result.valid) {
                this.successMessage = result.message || 'XML signature is valid';
            } else {
                this.errorMessage = result.message || 'XML signature is invalid';
            }

        } catch (error) {
            console.error('XML validation error:', error);
            this.errorMessage = error.message || 'XML validation failed. Please check your input and try again.';
        } finally {
            this.isValidating = false;
        }
    },

    resetValidation() {
        this.xmlContent = '';
        this.validationResult = null;
        this.errorMessage = '';
        this.successMessage = '';
    },

    copyValidationResult() {
        if (navigator.clipboard && window.isSecureContext) {
            const resultText = this.validationResult
                ? `Valid: ${this.validationResult.valid}\n${this.validationResult.message || ''}`
                : 'No validation result available';

            navigator.clipboard.writeText(resultText).then(() => {
                this.successMessage = 'Validation result copied to clipboard!';
                setTimeout(() => this.successMessage = '', 3000);
            }).catch(() => {
                this.fallbackCopyValidationResult(resultText);
            });
        } else {
            this.fallbackCopyValidationResult(resultText);
        }
    },

    fallbackCopyValidationResult(text) {
        const textArea = document.createElement('textarea');
        textArea.value = text;
        textArea.style.position = 'fixed';
        textArea.style.left = '-999999px';
        textArea.style.top = '-999999px';
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        try {
            document.execCommand('copy');
            this.successMessage = 'Validation result copied to clipboard!';
            setTimeout(() => this.successMessage = '', 3000);
        } catch (err) {
            this.errorMessage = 'Failed to copy validation result';
        }
        document.body.removeChild(textArea);
    }
});
