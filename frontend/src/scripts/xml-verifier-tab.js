export default () => ({
    activeSubTab: 'xml',

    // Form data for XML verification
    xmlContent: ``,
    xmlContentSample: `\
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
    xmlContentBase64: '',//TODO: add base64 example
    validationResult: null,
    isValidating: false,

    // Validation configuration
    validationConfig: {
        checkKalkanProvider: false,
        checkData: true,
        checkTime: true,
        checkIinInCert: false,
        checkIinInSign: false,
        checkBinInCert: false,
        checkBinInSign: false,
        checkCertificateChain: false,
        checkPublicKey: false,
        expectedIin: '',
        expectedBin: ''
    },

    // Public key file handling
    publicKeyFile: null,
    publicKeyFileName: '',

    // CA PEM file handling
    caPemFile: null,
    caPemFileName: '',

    initXmlVerifier() {
        //ignore
    },

    async handlePublicKeyFileChange(event) {
        const file = event.target.files[0];
        if (file) {
            this.publicKeyFileName = file.name;
            this.publicKeyFile = file;

            // Read file content as base64
            const reader = new FileReader();
            reader.onload = (e) => {
                // Remove the data URL prefix (data:text/plain;base64,) and keep only base64 data
                const base64Content = e.target.result.split(',')[1];
                this.validationConfig.publicKey = base64Content;
            };
            reader.readAsDataURL(file);
        } else {
            this.publicKeyFileName = '';
            this.publicKeyFile = null;
            this.validationConfig.publicKey = '';
        }
    },

    async handleCaPemFileChange(event) {
        const file = event.target.files[0];
        if (file) {
            this.caPemFileName = file.name;
            this.caPemFile = file;

            // Read file content as base64
            const reader = new FileReader();
            reader.onload = (e) => {
                // Remove the data URL prefix (data:text/plain;base64,) and keep only base64 data
                const base64Content = e.target.result.split(',')[1];
                this.validationConfig.caPem = base64Content;
            };
            reader.readAsDataURL(file);
        } else {
            this.caPemFileName = '';
            this.caPemFile = null;
            this.validationConfig.caPem = '';
        }
    },

    async validateXml() {
        // Validation
        if (!this.xmlContent || !this.xmlContent.trim()) {
            this.addNotification('error', 'xmlValidationRequired');
            return;
        }

        // Check if public key file is required but not provided
        if (this.validationConfig.checkPublicKey && (!this.validationConfig.publicKey || !this.validationConfig.publicKey.trim())) {
            this.addNotification('error', 'publicKeyRequired');
            return;
        }

        this.isValidating = true;

        try {
            const requestData = {
                xml: this.xmlContent.trim(),
                ...this.validationConfig
            };

            // Remove empty expectedIin and expectedBin
            if (!requestData.expectedIin.trim()) {
                delete requestData.expectedIin;
            }
            if (!requestData.expectedBin.trim()) {
                delete requestData.expectedBin;
            }

            const response = await fetch('/api/verify', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(requestData)
            });

            const result = await response.json();

            if (!response.ok) {
                throw new Error(result.error || 'Validation failed');
            }

            this.validationResult = result;

            if (result.valid) {
                this.addNotification('success', result.message || 'xmlVerificationPassed');
            } else {
                this.addNotification('error', result.message || 'xmlVerificationFailed');
            }

        } catch (error) {
            console.error('XML validation error:', error);
            this.addNotification('error', error.message || 'xmlVerificationFailedGeneral');
        } finally {
            this.isValidating = false;
        }
    },

    resetValidation() {
        this.xmlContent = '';
        this.validationConfig.checkKalkanProvider = false;
        this.validationConfig.checkData = true;
        this.validationConfig.checkTime = true;
        this.validationConfig.checkIinInCert = false;
        this.validationConfig.checkIinInSign = false;
        this.validationConfig.checkBinInCert = false;
        this.validationConfig.checkBinInSign = false;
        this.validationConfig.checkCertificateChain = false;
        this.validationConfig.checkPublicKey = false;
        this.validationConfig.expectedIin = '';
        this.validationConfig.expectedBin = '';
        // Reset public key file
        this.publicKeyFile = null;
        this.publicKeyFileName = '';
        this.validationConfig.publicKey = '';
        // Reset CA PEM file
        this.caPemFile = null;
        this.caPemFileName = '';
        this.validationConfig.caPem = '';
        // Clear file inputs
        const publicKeyFileInput = document.getElementById('publicKeyFile');
        if (publicKeyFileInput) publicKeyFileInput.value = '';
        const caPemFileInput = document.getElementById('caPemFile');
        if (caPemFileInput) caPemFileInput.value = '';
        this.validationResult = null;
    },

    copyValidationResult() {
        if (!this.validationResult) return;

        // Create a formatted string with validation details
        let resultText = JSON.stringify(this.validationResult, null, 2);

        // Try modern clipboard API first
        if (navigator.clipboard) {
            navigator.clipboard.writeText(resultText).then(() => {
                this.addNotification('success', 'copySuccess');
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
            this.addNotification('success', 'copySuccess');
        } catch (err) {
            this.addNotification('error', 'copyFailed');
        }
        document.body.removeChild(textArea);
    },

    handleSignatureVerify(detail) {
        console.info("detail: ", detail);
        this.xmlContent = detail?.signature;
    }

});
