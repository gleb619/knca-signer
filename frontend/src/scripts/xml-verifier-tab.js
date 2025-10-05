export default () => ({
    activeSubTab: 'xml',

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

    // Form data for signature verification
    signatureData: '',
    signature: '',
    certAlias: 'user',

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

    async verifySignature() {
        // Clear previous messages
        this.errorMessage = '';
        this.successMessage = '';

        // Validation
        if (!this.signatureData || !this.signatureData.trim()) {
            this.errorMessage = 'Data cannot be empty';
            return;
        }

        if (!this.signature || !this.signature.trim()) {
            this.errorMessage = 'Signature cannot be empty';
            return;
        }

        this.isValidating = true;

        try {
            const response = await fetch('/api/verify', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    data: this.signatureData.trim(),
                    signature: this.signature.trim(),
                    certAlias: this.certAlias || 'user'
                })
            });

            const result = await response.json();

            if (!response.ok) {
                throw new Error(result.error || 'Verification failed');
            }

            this.validationResult = result;

            if (result.valid) {
                this.successMessage = result.message || 'Signature is valid';
            } else {
                this.errorMessage = result.message || 'Signature is invalid';
            }

        } catch (error) {
            console.error('Signature verification error:', error);
            this.errorMessage = error.message || 'Signature verification failed. Please check your input and try again.';
        } finally {
            this.isValidating = false;
        }
    },

    resetValidation() {
        this.xmlContent = '';
        this.signatureData = '';
        this.signature = '';
        this.certAlias = 'user';
        this.validationResult = null;
        this.errorMessage = '';
        this.successMessage = '';

        // Clear file input
        const certificateFileInput = document.getElementById('certificateFile');
        if (certificateFileInput) {
            certificateFileInput.value = '';
        }
    },

    loadCertificateFile(event) {
        const file = event.target.files[0];
        if (file) {
            this.successMessage = '';
            this.errorMessage = '';

            const reader = new FileReader();
            reader.onload = (e) => {
                try {
                    // Convert ArrayBuffer to base64
                    const arrayBuffer = e.target.result;
                    const bytes = new Uint8Array(arrayBuffer);
                    let binary = '';
                    for (let i = 0; i < bytes.byteLength; i++) {
                        binary += String.fromCharCode(bytes[i]);
                    }
                    const base64 = btoa(binary);
                    this.signature = base64;
                    this.successMessage = `Certificate file loaded successfully (${file.name})`;
                    setTimeout(() => this.successMessage = '', 3000);
                } catch (error) {
                    console.error('Error processing file:', error);
                    this.errorMessage = 'Failed to process the certificate file';
                }
            };
            reader.onerror = () => {
                this.errorMessage = 'Failed to read the certificate file';
            };
            reader.readAsArrayBuffer(file);
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
